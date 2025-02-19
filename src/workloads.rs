//! Common workloads

use std::{cmp::Ordering, time::Instant};

use crate::ScailError;

use super::{get_user_home_dir, oomkiller_blacklist_by_name};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshError, SshShell, SshSpawnHandle};

/// Generate a command prefix to run perf stat collecting the given counters.
pub fn gen_perf_command_prefix(
    output_file: impl AsRef<str>,
    counters: &[impl AsRef<str>],
    extra_args: impl AsRef<str>,
) -> String {
    let mut prefix = String::from("sudo perf stat ");

    for c in counters {
        prefix.push_str(" -e ");
        prefix.push_str(c.as_ref());
    }

    prefix.push_str(" -o ");
    prefix.push_str(output_file.as_ref());

    prefix.push(' ');
    prefix.push_str(extra_args.as_ref());

    prefix.push_str(" -- ");

    prefix
}

/// Specifies how `TasksetCtx` should assign cores across NUMA nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TasksetCtxInterleaving {
    /// Assign all cores on a node before moving to the next node.
    Sequential,
    /// Assign cores in a round-robin manner across numa nodes.
    RoundRobin,
}

/// Creates a new `TasksetCtx` with the given parameters.
#[derive(Debug, Clone)]
pub struct TasksetCtxBuilder {
    /// Stores the topology of the machine: `topology[socket][core][thread]` is a cpu id for the
    /// hardware thread on the given socket and core.
    topology: Vec<Vec<Vec<usize>>>,

    /// Build a `TasksetCtx` that skips hyperthreads. Default: false.
    skip_hyperthreads: bool,

    /// Build a `TasksetCtx` that gives hyperthreads on the same core together. Default: false.
    group_hyperthreads: bool,


    /// Build a `TasksetCtx` that uses the given NUMA interleaving mode.
    /// See `TasksetCtxInterleaving`. Default: `Sequential`.
    numa_interleaving: TasksetCtxInterleaving,
}

impl Default for TasksetCtxBuilder {
    fn default() -> Self {
        TasksetCtxBuilder::new()
    }
}

impl TasksetCtxBuilder {
    /// Create a new empty builder with no topology.
    pub fn new() -> Self {
        Self {
            topology: Vec::new(),
            skip_hyperthreads: false,
            group_hyperthreads: false,
            numa_interleaving: TasksetCtxInterleaving::Sequential,
        }
    }

    fn from_lscpu_inner(lscpu_output: &str) -> Self {
        let mut builder = TasksetCtxBuilder::new();
        for line in lscpu_output.lines() {
            if line.contains('#') {
                continue;
            }
            let mut split = line.trim().split(',');
            let thread = split
                .next()
                .unwrap()
                .parse::<usize>()
                .expect("Expected integer");
            let core = split
                .next()
                .unwrap()
                .parse::<usize>()
                .expect("Expected integer");
            let socket = split
                .next()
                .unwrap()
                .parse::<usize>()
                .expect("Expected integer");

            builder = builder.add_thread(socket, core, thread);
        }

        builder
    }

    /// Use the output of `lscpu -p` to determine the topology of the system.
    pub fn from_lscpu(shell: &SshShell) -> Result<Self, SshError> {
        // Run lscpu and process the output.
        let lscpu_output = shell.run(cmd!("lscpu -p"))?.stdout;
        Ok(Self::from_lscpu_inner(&lscpu_output))
    }

    /// Build a simple `TasksetCtx` with `ncores` cores, assuming all are on the same socket and
    /// every other core is a hyperthread.
    ///
    /// This was the old behavior of `TasksetCtx`, so this constructor allows for compatibility.
    pub fn simple(ncores: usize) -> Self {
        assert!(ncores > 0);
        let mut builder = TasksetCtxBuilder::new();
        for i in 0..ncores {
            builder = builder.add_thread(0, i / 2, i);
        }
        builder
    }

    /// Add a hardware thread on the given socket and core to the topology. If the given
    /// socket, core, or thread do not exist, they are created, along with every socket, core, and
    /// thread of smaller id. Note that this may leave a "ragged" topology. For example:
    ///
    /// ```rust,ignore
    /// let builder = TasksetCtxBuilder::new().add_thread(2, 5, 2);
    /// ```
    ///
    /// This code produces the following topology:
    /// ```txt
    /// Socket 0:
    /// Socket 1:
    /// Socket 2:
    ///     Core 0:
    ///     Core 1:
    ///     Core 2:
    ///     Core 3:
    ///     Core 4:
    ///     Core 5:
    ///         Thread (cpu id) 2
    /// ```
    ///
    /// It is the caller's responsibility to deal with or avoid ragged topologies like this.
    ///
    fn add_thread(mut self, socket_id: usize, core_id: usize, thread_id: usize) -> Self {
        let sockets_to_create = if socket_id >= self.topology.len() {
            socket_id - self.topology.len() + 1
        } else {
            0
        };

        for _ in 0..sockets_to_create {
            self.topology.push(Vec::new());
        }

        let cores_to_create = if core_id >= self.topology[socket_id].len() {
            core_id - self.topology[socket_id].len() + 1
        } else {
            0
        };

        for _ in 0..cores_to_create {
            self.topology[socket_id].push(Vec::new());
        }

        self.topology[socket_id][core_id].push(thread_id);

        self
    }

    /// If `true`, remove hyperthreads from the topology. Else, leave them in the topology.
    pub fn skip_hyperthreads(self, skip: bool) -> Self {
        Self {
            skip_hyperthreads: skip,
            ..self
        }
    }

    /// If `true`, group hyperthreads together when returning CPU ids. Else, do not
    /// consider hyperthread placement
    pub fn group_hyperthreads(self, group: bool) -> Self {
        Self {
            group_hyperthreads: group,
            ..self
        }
    }

    /// Build a `TasksetCtx` that uses the given NUMA interleaving mode.
    /// See `TasksetCtxInterleaving`.
    pub fn numa_interleaving(self, mode: TasksetCtxInterleaving) -> Self {
        Self {
            numa_interleaving: mode,
            ..self
        }
    }

    /// Build the specified `TasksetCtx`. Panics if there is not at least one thread.
    pub fn build(self) -> TasksetCtx {
        let mut topology = Vec::new();

        let mut at_least_one = false;

        for socket in self.topology.into_iter() {
            let mut new_socket = Vec::new();

            for mut core in socket.into_iter() {
                let mut new_core = Vec::new();

                if self.skip_hyperthreads {
                    if let Some(thread) = core.pop() {
                        new_core.push((thread, TasksetCpuStatus::Unassigned));
                        at_least_one = true;
                    }
                } else {
                    for thread in core.into_iter() {
                        new_core.push((thread, TasksetCpuStatus::Unassigned));
                        at_least_one = true;
                    }
                }

                new_socket.push(new_core)
            }

            topology.push(new_socket);
        }

        if !at_least_one {
            panic!("`TasksetCtx` must have at least one hardware thead.");
        }

        TasksetCtx {
            topology,
            numa_interleaving: self.numa_interleaving,
            group_hyperthreads: self.group_hyperthreads,
            next: (0, 0, 0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TasksetCpuStatus {
    Unassigned,
    Assigned,
    Skipped,
}

/// Keeps track of which guest vCPUs have been assigned.
#[derive(Debug)]
pub struct TasksetCtx {
    /// The topology of the machine, as built by a `TasksetCtxBuilder`. We also keep track of which
    /// threads/cores have been assigned.
    topology: Vec<Vec<Vec<(usize, TasksetCpuStatus)>>>,

    /// Build a `TasksetCtx` that uses the given NUMA interleaving mode.
    /// See `TasksetCtxInterleaving`.
    numa_interleaving: TasksetCtxInterleaving,

    /// Build a `TasksetCtx` that gives hyperthreads on the same core together
    /// See `TasksetCtxInterleaving`
    group_hyperthreads: bool,

    /// The next thread to be assigned -- note these are indices into `topology`, not necessarily
    /// cpu ids!
    next: (usize, usize, usize),
}

impl TasksetCtx {
    /// Create a new context with the given total number of cores.
    pub fn new(ncores: usize) -> Self {
        TasksetCtxBuilder::simple(ncores).build()
    }

    /// Skip one CPU. This is useful to avoid hyperthreading effects.
    pub fn skip(&mut self) {
        let (socketidx, coreidx, threadidx) = self.next;
        self.topology[socketidx][coreidx][threadidx].1 = TasksetCpuStatus::Skipped;

        self.advance();
    }

    /// Get the next thread (cpuid) (wrapping around to 0 if all cores have been assigned).
    ///
    /// This was the old behavior of `next`.
    pub fn next_unchecked(&mut self) -> usize {
        match self.next() {
            Ok(cpuid) | Err(cpuid) => cpuid,
        }
    }

    /// Get the next thread (cpuid) that has not been assigned or explicitly skipped. If there is
    /// no such cpuid, returns `Err` with the return value of `next_unchecked`.
    pub fn next(&mut self) -> Result<usize, usize> {
        use TasksetCpuStatus::*;

        let (socketidx, coreidx, threadidx) = self.next;
        let (cpuid, status) = self.topology[socketidx][coreidx][threadidx];

        let retval = match status {
            Unassigned => {
                self.topology[socketidx][coreidx][threadidx].1 = Assigned;
                Ok(cpuid)
            }
            Assigned | Skipped => Err(cpuid),
        };

        self.advance();

        retval
    }

    /// Get the number of threads that are assignable.
    pub fn num_threads(&self) -> usize {
        let mut count = 0;

        for s in 0..self.topology.len() {
            count += self.num_threads_on_socket(s);
        }

        count
    }

    /// Get the number of assignable threads in a specified socket
    pub fn num_threads_on_socket(&self, socket: usize) -> usize {
        let mut count = 0;

        for c in 0..self.topology[socket].len() {
            count += self.topology[socket][c].len();
        }

        count
    }

    /// Select the next unassigned, unskipped cpuid if there is one. Otherwise, select the next
    /// skipped cpuid. Otherwise, select the next cpuid.
    fn advance(&mut self) {
        use Ordering::*;
        use TasksetCpuStatus::*;
        use TasksetCtxInterleaving::*;

        // We construct a list of all CPUs and sort it in order of preference. Then, we take the
        // first CPU in the list. Since we don't expec the list of CPUs to be huge, this should be
        // fine.
        let (current_socket, current_core, current_thread) = self.next;
        let (current_cpuid, _) = self.topology[current_socket][current_core][current_thread];

        let mut all_cpuids = self
            .topology
            .iter()
            .enumerate()
            .flat_map(move |(s, socket)| {
                socket.iter().enumerate().flat_map(move |(c, core)| {
                    core.iter()
                        .enumerate()
                        .map(move |(t, (cpuid, status))| (s, c, t, *cpuid, *status))
                })
            })
            .collect::<Vec<_>>();

        // Ordering::Less indicates A is preferred to B.
        let compare =
            |&(asock, acore, _athrd, acpuid, astatus): &(_, _, _, usize, _),
             &(bsock, bcore, _bthrd, bcpuid, bstatus): &(_, _, _, usize, _)| {
                // Consider availability of the core.
                match (astatus, bstatus) {
                    // If they are the same, inconclusive...
                    (Unassigned, Unassigned) | (Assigned, Assigned) | (Skipped, Skipped) => {}

                    // If one is unassigned and the other is not, the unassigned CPU gets preference.
                    (Unassigned, _) => return Less,
                    (_, Unassigned) => return Greater,

                    (Assigned, Skipped) => return Greater,
                    (Skipped, Assigned) => return Less,
                }

                // Consider interleaving strategy.
                match self.numa_interleaving {
                    // Prefer the socket self.next and those immediately after it.
                    Sequential => {
                        let adiff = (asock as isize) - (current_socket as isize);
                        let bdiff = (bsock as isize) - (current_socket as isize);
                        // A is before current socket; B is at or after current socket.
                        if adiff < 0 && bdiff >= 0 {
                            return Greater;
                        } else if bdiff < 0 && adiff >= 0 {
                            return Less;
                        }
                        // Both before or both after current socket, but not the same.
                        else if adiff != bdiff {
                            return adiff.cmp(&bdiff);
                        }
                    }

                    // Prefer sockets other than self.next, starting with the one after next.
                    RoundRobin => {
                        let adiff = (asock as isize) - (current_socket as isize);
                        let bdiff = (bsock as isize) - (current_socket as isize);
                        // A is before current socket; B is after current socket.
                        if adiff < 0 && bdiff > 0 {
                            return Greater;
                        } else if bdiff < 0 && adiff > 0 {
                            return Less;
                        }
                        // If one of them is the current socket and the other is not.
                        else if adiff == 0 && bdiff != 0 {
                            return Greater;
                        } else if bdiff == 0 && adiff != 0 {
                            return Less;
                        }
                        // Both before or both after current socket, but not the same.
                        else if adiff != bdiff {
                            return adiff.cmp(&bdiff);
                        }
                    }
                }

                // Consider whether to group hyperthreads together
                if self.group_hyperthreads && acore != bcore {
                    if acore == current_core {
                        return Less;
                    } else if bcore == current_core {
                        return Greater;
                    }
                }

                // Otherwise, simply pick the next cpuid and wrap around when needed.
                match (acpuid.cmp(&current_cpuid), bcpuid.cmp(&current_cpuid)) {
                    // Otherwise, make sure we don't pick the same cpuid twice.
                    (Equal, Equal) => Equal,
                    (Equal, _) => Greater,
                    (_, Equal) => Less,

                    // Prefer subsequent cpuids so we proceed in a round-robin manner.
                    (Less, Greater) => Greater,
                    (Greater, Less) => Less,

                    // Both before or both after => just pick the lower cpuid.
                    (Less, Less) | (Greater, Greater) => acpuid.cmp(&bcpuid),
                }
            };

        all_cpuids.sort_by(compare);

        let (nextsock, nextcore, nextthread, _, _) = all_cpuids.first().unwrap();
        self.next = (*nextsock, *nextcore, *nextthread);
    }
}

#[cfg(test)]
mod taskset_ctx_tests {
    use super::*;

    #[test]
    fn test_simple() {
        let mut tctx = TasksetCtxBuilder::simple(10).build();
        assert_eq!(tctx.next(), Ok(0));
        assert_eq!(tctx.next(), Ok(1));
        assert_eq!(tctx.next(), Ok(2));
        assert_eq!(tctx.next(), Ok(3));
        assert_eq!(tctx.next(), Ok(4));
        assert_eq!(tctx.next(), Ok(5));
        assert_eq!(tctx.next(), Ok(6));
        assert_eq!(tctx.next(), Ok(7));
        assert_eq!(tctx.next(), Ok(8));
        assert_eq!(tctx.next(), Ok(9));
        assert_eq!(tctx.next(), Err(0));
        assert_eq!(tctx.next(), Err(1));
        assert_eq!(tctx.next(), Err(2));
        assert_eq!(tctx.next(), Err(3));
        assert_eq!(tctx.next(), Err(4));
        assert_eq!(tctx.next(), Err(5));
        assert_eq!(tctx.next(), Err(6));
        assert_eq!(tctx.next(), Err(7));
        assert_eq!(tctx.next(), Err(8));
        assert_eq!(tctx.next(), Err(9));
    }

    #[test]
    fn test_simple_skip_hyperthreads() {
        let mut tctx = TasksetCtxBuilder::simple(10)
            .skip_hyperthreads(true)
            .build();
        assert_eq!(tctx.next(), Ok(1));
        assert_eq!(tctx.next(), Ok(3));
        assert_eq!(tctx.next(), Ok(5));
        assert_eq!(tctx.next(), Ok(7));
        assert_eq!(tctx.next(), Ok(9));
        assert_eq!(tctx.next(), Err(1));
        assert_eq!(tctx.next(), Err(3));
        assert_eq!(tctx.next(), Err(5));
        assert_eq!(tctx.next(), Err(7));
        assert_eq!(tctx.next(), Err(9));
    }

    #[test]
    fn test_sockets_sequential() {
        let mut tctx = TasksetCtxBuilder::new()
            .add_thread(0, 0, 0)
            .add_thread(0, 0, 1)
            .add_thread(0, 1, 2)
            .add_thread(0, 1, 3)
            .add_thread(1, 0, 4)
            .add_thread(1, 0, 5)
            .add_thread(1, 1, 6)
            .add_thread(1, 1, 7)
            .numa_interleaving(TasksetCtxInterleaving::Sequential)
            .build();
        assert_eq!(tctx.next(), Ok(0));
        assert_eq!(tctx.next(), Ok(1));
        assert_eq!(tctx.next(), Ok(2));
        assert_eq!(tctx.next(), Ok(3));
        assert_eq!(tctx.next(), Ok(4));
        assert_eq!(tctx.next(), Ok(5));
        assert_eq!(tctx.next(), Ok(6));
        assert_eq!(tctx.next(), Ok(7));
        // Continues to try to assign on same numa node...
        assert_eq!(tctx.next(), Err(4));
        assert_eq!(tctx.next(), Err(5));
        assert_eq!(tctx.next(), Err(6));
        assert_eq!(tctx.next(), Err(7));
        assert_eq!(tctx.next(), Err(4));
        assert_eq!(tctx.next(), Err(5));
        assert_eq!(tctx.next(), Err(6));
        assert_eq!(tctx.next(), Err(7));
    }

    #[test]
    fn test_sockets_roundrobin() {
        let mut tctx = TasksetCtxBuilder::new()
            .add_thread(0, 0, 0)
            .add_thread(0, 0, 1)
            .add_thread(0, 1, 2)
            .add_thread(0, 1, 3)
            .add_thread(1, 0, 4)
            .add_thread(1, 0, 5)
            .add_thread(1, 1, 6)
            .add_thread(1, 1, 7)
            .numa_interleaving(TasksetCtxInterleaving::RoundRobin)
            .build();
        assert_eq!(tctx.next(), Ok(0));
        assert_eq!(tctx.next(), Ok(4));
        assert_eq!(tctx.next(), Ok(1));
        assert_eq!(tctx.next(), Ok(5));
        assert_eq!(tctx.next(), Ok(2));
        assert_eq!(tctx.next(), Ok(6));
        assert_eq!(tctx.next(), Ok(3));
        assert_eq!(tctx.next(), Ok(7));
        // Continues to try to assign on alternating numa nodes...
        assert_eq!(tctx.next(), Err(0));
        assert_eq!(tctx.next(), Err(4));
        assert_eq!(tctx.next(), Err(0));
        assert_eq!(tctx.next(), Err(4));
        assert_eq!(tctx.next(), Err(0));
        assert_eq!(tctx.next(), Err(4));
        assert_eq!(tctx.next(), Err(0));
        assert_eq!(tctx.next(), Err(4));
    }

    #[test]
    fn test_sockets_roundrobin_skip_hyperthreads() {
        let mut tctx = TasksetCtxBuilder::new()
            .add_thread(0, 0, 0)
            .add_thread(0, 0, 1)
            .add_thread(0, 1, 2)
            .add_thread(0, 1, 3)
            .add_thread(1, 0, 4)
            .add_thread(1, 0, 5)
            .add_thread(1, 1, 6)
            .add_thread(1, 1, 7)
            .numa_interleaving(TasksetCtxInterleaving::RoundRobin)
            .skip_hyperthreads(true)
            .build();
        assert_eq!(tctx.next(), Ok(1));
        assert_eq!(tctx.next(), Ok(5));
        assert_eq!(tctx.next(), Ok(3));
        assert_eq!(tctx.next(), Ok(7));
        // Continues to try to assign on alternating numa nodes...
        assert_eq!(tctx.next(), Err(1));
        assert_eq!(tctx.next(), Err(5));
        assert_eq!(tctx.next(), Err(1));
        assert_eq!(tctx.next(), Err(5));
        assert_eq!(tctx.next(), Err(1));
        assert_eq!(tctx.next(), Err(5));
        assert_eq!(tctx.next(), Err(1));
        assert_eq!(tctx.next(), Err(5));
    }

    #[test]
    fn test_lscpu() {
        const LSCPU_TEXT: &str = "# The following is the parsable format, which can be fed to other
                                  # programs. Each different item in every column has an unique ID
                                  # starting from zero.
                                  # CPU,Core,Socket,Node,,L1d,L1i,L2,L3
                                  0,0,0,0,,0,0,0,0
                                  1,1,0,0,,1,1,1,0
                                  2,2,0,0,,2,2,2,0
                                  3,3,0,0,,3,3,3,0
                                  4,4,0,0,,4,4,4,0
                                  5,5,0,0,,5,5,5,0
                                  6,6,0,0,,6,6,6,0
                                  7,7,0,0,,7,7,7,0
                                  8,8,1,1,,8,8,8,1
                                  9,9,1,1,,9,9,9,1
                                  10,10,1,1,,10,10,10,1
                                  11,11,1,1,,11,11,11,1
                                  12,12,1,1,,12,12,12,1
                                  13,13,1,1,,13,13,13,1
                                  14,14,1,1,,14,14,14,1
                                  15,15,1,1,,15,15,15,1
                                  16,0,0,0,,0,0,0,0
                                  17,1,0,0,,1,1,1,0
                                  18,2,0,0,,2,2,2,0
                                  19,3,0,0,,3,3,3,0
                                  20,4,0,0,,4,4,4,0
                                  21,5,0,0,,5,5,5,0
                                  22,6,0,0,,6,6,6,0
                                  23,7,0,0,,7,7,7,0
                                  24,8,1,1,,8,8,8,1
                                  25,9,1,1,,9,9,9,1
                                  26,10,1,1,,10,10,10,1
                                  27,11,1,1,,11,11,11,1
                                  28,12,1,1,,12,12,12,1
                                  29,13,1,1,,13,13,13,1
                                  30,14,1,1,,14,14,14,1
                                  31,15,1,1,,15,15,15,1";
        let mut tctx = TasksetCtxBuilder::from_lscpu_inner(LSCPU_TEXT)
            .skip_hyperthreads(true)
            .numa_interleaving(TasksetCtxInterleaving::Sequential)
            .build();

        assert_eq!(tctx.next(), Ok(16));
        assert_eq!(tctx.next(), Ok(17));
        assert_eq!(tctx.next(), Ok(18));
        assert_eq!(tctx.next(), Ok(19));
        assert_eq!(tctx.next(), Ok(20));
        assert_eq!(tctx.next(), Ok(21));
        assert_eq!(tctx.next(), Ok(22));
        assert_eq!(tctx.next(), Ok(23));

        assert_eq!(tctx.next(), Ok(24));
        assert_eq!(tctx.next(), Ok(25));
        assert_eq!(tctx.next(), Ok(26));
        assert_eq!(tctx.next(), Ok(27));
        assert_eq!(tctx.next(), Ok(28));
        assert_eq!(tctx.next(), Ok(29));
        assert_eq!(tctx.next(), Ok(30));
        assert_eq!(tctx.next(), Ok(31));

        // Continues to try to assign on same numa node...
        assert_eq!(tctx.next(), Err(24));
        assert_eq!(tctx.next(), Err(25));
        assert_eq!(tctx.next(), Err(26));
        assert_eq!(tctx.next(), Err(27));
        assert_eq!(tctx.next(), Err(28));
        assert_eq!(tctx.next(), Err(29));
        assert_eq!(tctx.next(), Err(30));
        assert_eq!(tctx.next(), Err(31));
        assert_eq!(tctx.next(), Err(24));
        assert_eq!(tctx.next(), Err(25));
        assert_eq!(tctx.next(), Err(26));
        assert_eq!(tctx.next(), Err(27));
        assert_eq!(tctx.next(), Err(28));
        assert_eq!(tctx.next(), Err(29));
        assert_eq!(tctx.next(), Err(30));
        assert_eq!(tctx.next(), Err(31));
    }
}

/// Indicates a Intel PIN pintool to run, along with the needed parameters.
#[derive(Debug)]
pub enum Pintool<'s> {
    /// Collect a memory trace.
    MemTrace {
        /// The path to the root of the `pin/` directory. This should be accessible in the VM.
        pin_path: &'s str,
        /// The file path and name to output the trace to.
        output_path: &'s str,
    },
}

/// The configuration of a memcached workload.
#[derive(Debug)]
pub struct PostgresWorkloadConfig<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    /// The directory in which the postgres binary is in
    pub postgres_path: &'s str,
    /// The path of the database directory
    pub db_dir: &'s str,

    /// If using tmpfs for Postgres's data directory, how much to use in GB
    pub tmpfs_size: Option<usize>,

    /// The user running postgres
    pub user: &'s str,

    /// The core number that the memcached server is pinned to, if any.
    pub server_pin_core: Option<usize>,

    /// Indicates that we should run the given pintool on the workload.
    pub pintool: Option<Pintool<'s>>,

    /// A prefix for the shell command that starts the process
    pub cmd_prefix: Option<&'s str>,

    /// Extra options to run postgres with
    pub postgres_options: Option<&'s str>,

    /// Indicates that we should run the workload under `perf` to capture MMU overhead stats.
    /// The string is the path to the output.
    pub mmu_perf: Option<(&'s str, &'s [String])>,

    /// A callback executed after the memcached server starts but before the workload starts.
    pub server_start_cb: F,
}

/// Start a `Postgres` server in daemon mode
pub fn start_postgres<F>(
    shell: &SshShell,
    cfg: &PostgresWorkloadConfig<'_, F>
) -> Result<Option<spurs::SshSpawnHandle>, ScailError>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    let taskset = if let Some(server_pin_core) = cfg.server_pin_core {
        format!("taskset -c {} ", server_pin_core)
    } else {
        "".into()
    };

    let pintool = match cfg.pintool {
        Some(Pintool::MemTrace {
            pin_path,
            output_path,
        }) => format!(
            "{}/pin -t {}/source/tools/MemTrace/obj-intel64/membuffer.so -o {} -emit -- ",
            pin_path, pin_path, output_path
        ),

        None => "".into(),
    };

    // Create the DB directory if it doesn't exist and clear it
    shell.run(cmd!("mkdir -p {}", cfg.db_dir))?;
    shell.run(cmd!("sudo rm -rf {}/*", cfg.db_dir))?;

    if let Some(tmpfs_size) = cfg.tmpfs_size {
        shell.run(cmd!(
            "sudo mount -t tmpfs -o size={}g tmpfs {}",
            tmpfs_size,
            cfg.db_dir
        ))?;
        shell.run(cmd!(
            "sudo chown {} {}",
            cfg.user,
            cfg.db_dir
        ))?;
    }

    // Now we have to setup the DB dir for postgres
    shell.run(cmd!("{}/initdb -D {}", cfg.postgres_path, cfg.db_dir))?;

    shell.spawn(cmd!(
        "{}{}{} {}/postgres {} -D {} ",
        pintool,
        taskset,
        cfg.cmd_prefix.unwrap_or(""),
        cfg.postgres_path,
        cfg.postgres_options.unwrap_or(""),
        cfg.db_dir,
    ))?;

    // Wait for postgres to start by using `pg_isready` until we are able to connect.
    while let Err(..) = shell.run(cmd!(
        "{}/pg_isready",
        cfg.postgres_path
    )) {}

    // Setup the DB for YCSB
    shell.run(cmd!("{}/createdb", cfg.postgres_path))?;
    shell.run(cmd!("{}/psql -w -c \"CREATE TABLE usertable \
        (YCSB_KEY VARCHAR(255) PRIMARY KEY not NULL, \
        YCSB_VALUE JSONB not NULL);\"", 
        cfg.postgres_path))?;

    // Run the callback
    (cfg.server_start_cb)(shell)?;

    // Start `perf` if needed.
    Ok(if let Some((output_path, counters)) = &cfg.mmu_perf {
        let handle = shell.spawn(cmd!(
            "{}",
            gen_perf_command_prefix(output_path, counters, "-p `pgrep postgres`")
        ))?;

        // Wait for perf to start collection.
        shell.run(cmd!("while [ ! -e {} ] ; do sleep 1 ; done", output_path).use_bash())?;

        Some(handle)
    } else {
        None
    })
}

/// The configuration of a memcached workload.
#[derive(Debug)]
pub struct MemcachedWorkloadConfig<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    /// The directory in which the memcached binary is contained.
    pub memcached: &'s str,

    /// The user to run the `memcached` server as.
    pub user: &'s str,
    /// The size of `memcached` server in MB.
    pub server_size_mb: usize,
    /// Specifies whether the memcached server is allowed to OOM.
    pub allow_oom: bool,
    /// Specifies if memcached should use hugepages
    pub hugepages: bool,

    /// The core number that the memcached server is pinned to, if any.
    pub server_pin_core: Option<usize>,

    /// The size of the workload in GB.
    pub wk_size_gb: usize,
    /// The file to which the workload will write its output. If `None`, then `/dev/null` is used.
    pub output_file: Option<&'s str>,

    /// Indicates that we should run the given pintool on the workload.
    pub pintool: Option<Pintool<'s>>,

    /// A prefix for the shell command that starts the process
    pub cmd_prefix: Option<&'s str>,

    /// Indicates that we should run the workload under `perf` to capture MMU overhead stats.
    /// The string is the path to the output.
    pub mmu_perf: Option<(&'s str, &'s [String])>,

    /// A callback executed after the memcached server starts but before the workload starts.
    pub server_start_cb: F,
}

/// Start a `memcached` server in daemon mode as the given user with the given amount of memory.
/// Usually this is called indirectly through one of the other workload routines.
///
/// `allow_oom` specifies whether memcached is allowed to OOM. This gives much simpler performance
/// behaviors. memcached uses a large amount of the memory you give it for bookkeeping, rather
/// than user data, so OOM will almost certainly happen. memcached will also evict the LRU data in
/// this case.
pub fn start_memcached<F>(
    shell: &SshShell,
    cfg: &MemcachedWorkloadConfig<'_, F>,
) -> Result<Option<spurs::SshSpawnHandle>, ScailError>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    // We need to update the system vma limit because malloc may cause it to be hit for
    // large-memory systems.
    shell.run(cmd!("sudo sysctl -w vm.max_map_count={}", 1_000_000_000))?;

    let taskset = if let Some(server_pin_core) = cfg.server_pin_core {
        format!("taskset -c {} ", server_pin_core)
    } else {
        "".into()
    };

    let pintool = match cfg.pintool {
        Some(Pintool::MemTrace {
            pin_path,
            output_path,
        }) => format!(
            "{}/pin -t {}/source/tools/MemTrace/obj-intel64/membuffer.so -o {} -emit -- ",
            pin_path, pin_path, output_path
        ),

        None => "".into(),
    };

    shell.spawn(cmd!(
        "{}{}{} {}/memcached {} {} -m {} -u {} -f 1.11 -v",
        pintool,
        taskset,
        cfg.cmd_prefix.unwrap_or(""),
        cfg.memcached,
        if cfg.allow_oom { "-M" } else { "" },
        if cfg.hugepages { "-L" } else { "" },
        cfg.server_size_mb,
        cfg.user
    ))?;

    // Wait for memcached to start by using `memcached-tool` until we are able to connect.
    while shell
        .run(cmd!(
            "{}/scripts/memcached-tool localhost:11211",
            cfg.memcached
        ))
        .is_err()
    {}

    // Don't let memcached get OOM killed.
    oomkiller_blacklist_by_name(shell, "memcached")?;

    // Run the callback.
    (cfg.server_start_cb)(shell)?;

    // Start `perf` if needed.
    Ok(if let Some((output_path, counters)) = &cfg.mmu_perf {
        let handle = shell.spawn(cmd!(
            "{}",
            gen_perf_command_prefix(output_path, counters, "-p `pgrep memcached`")
        ))?;

        // Wait for perf to start collection.
        shell.run(cmd!("while [ ! -e {} ] ; do sleep 1 ; done", output_path).use_bash())?;

        Some(handle)
    } else {
        None
    })
}

/// The configuration of a MongoDB workload.
#[derive(Debug)]
pub struct MongoDBWorkloadConfig<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    /// The path where mongodb is located
    pub mongo_dir: &'s str,
    /// The path of the database directory
    pub db_dir: &'s str,
    /// The size of the tmpfs in GB mounted at db_dir. If None, don't mount anything to
    /// db_dir
    pub tmpfs_size: Option<usize>,

    /// The cache size of `MongoDB` server in MB. The default will be used if None.
    pub cache_size_mb: Option<usize>,

    /// The core number that the `MongoDB` server is pinned to, if any.
    pub server_pin_core: Option<usize>,

    /// A prefix for the shell command that starts the process
    pub cmd_prefix: Option<&'s str>,

    /// A callback executed after the mongodb server starts but before the workload starts.
    pub server_start_cb: F,
}

/// Start a `MongoDB` server in daemon mode with a given amount of memory for its
/// cache.
pub fn start_mongodb<F>(
    shell: &SshShell,
    cfg: &MongoDBWorkloadConfig<'_, F>,
) -> Result<(), ScailError>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    let mongod_dir = format!("{}/mongo/build/opt/mongo", cfg.mongo_dir);

    let taskset = if let Some(server_pin_core) = cfg.server_pin_core {
        format!("taskset -c {} ", server_pin_core)
    } else {
        "".into()
    };

    let wired_tiger_cache_size = if let Some(cache_size_mb) = cfg.cache_size_mb {
        format!("--wiredTigerCacheSizeGB {}", cache_size_mb as f64 / 1024.0)
    } else {
        "".into()
    };

    // Create the DB directory if it doesn't exist and clear it.
    shell.run(cmd!("mkdir -p {}", cfg.db_dir))?;
    shell.run(cmd!("sudo rm -rf {}/*", cfg.db_dir))?;

    // See if we should mount a tmpfs to the DB directory
    if let Some(tmpfs_size) = cfg.tmpfs_size {
        shell.run(cmd!(
            "sudo mount -t tmpfs -o size={}g tmpfs {}",
            tmpfs_size,
            cfg.db_dir
        ))?;
    }

    // FIXME: The --fork flag might be a problem if something grabs the PID of
    // the first process, but not the forked process
    shell.run(
        cmd!(
            "sudo {} {} ./mongod --fork --logpath {}/log --dbpath {} {}",
            taskset,
            cfg.cmd_prefix.unwrap_or(""),
            cfg.db_dir,
            cfg.db_dir,
            wired_tiger_cache_size,
        )
        .cwd(mongod_dir),
    )?;

    // Wait for the server to start
    while shell.run(cmd!("nc -z localhost 27017")).is_err() {}

    // Run the callback.
    (cfg.server_start_cb)(shell)?;

    Ok(())
}

/// Every setting of the redis workload.
#[derive(Debug)]
pub struct RedisWorkloadConfig<'s> {
    /// The path where redis is located
    pub redis_dir: &'s str,

    /// The path to the nullfs submodule on the remote.
    pub nullfs: Option<&'s str>,
    /// The path of the `redis.conf` file on the remote.
    pub redis_conf: &'s str,

    /// The size of `redis` server in MB.
    pub server_size_mb: usize,
    /// The size of the workload in GB.
    pub wk_size_gb: usize,
    /// The file to which the workload will write its output. If `None`, then `/dev/null` is used.
    pub output_file: Option<&'s str>,

    /// The core number that the redis server is pinned to, if any.
    pub server_pin_core: Option<usize>,

    /// A prefix for the shell command that starts the process
    pub cmd_prefix: Option<&'s str>,

    /// Indicates that we should run the given pintool on the workload.
    pub pintool: Option<Pintool<'s>>,
}

/// Spawn a `redis` server in a new shell with the given amount of memory and set some important
/// config settings. Usually this is called indirectly through one of the other workload routines.
///
/// In order for redis snapshots to work properly, we need to tell the kernel to overcommit memory.
/// This requires `sudo` access.
///
/// We also
///     - delete any existing RDB files.
///     - set up a nullfs to use for the snapshot directory
///
/// Returns the spawned shell.
pub fn start_redis(
    shell: &SshShell,
    cfg: &RedisWorkloadConfig<'_>,
) -> Result<SshSpawnHandle, ScailError> {
    // Set overcommit
    shell.run(cmd!("echo 1 | sudo tee /proc/sys/vm/overcommit_memory"))?;

    // Delete any previous database
    shell.run(cmd!("sudo rm -rf /mnt/nullfs"))?;
    shell.run(cmd!("sudo mkdir -p /mnt/nullfs"))?;
    shell.run(cmd!("sudo chmod 777 /mnt/nullfs"))?;

    // Delete the previous log.
    // Not doing this can cause issues if redis was previously started as root
    shell.run(cmd!("sudo rm -f /tmp/redis.log"))?;
    shell.run(cmd!("sudo rm -f /tmp/redis.sock"))?;

    // Start nullfs
    if let Some(nullfs_path) = &cfg.nullfs {
        shell.run(cmd!("nohup {}/nullfs /mnt/nullfs", nullfs_path))?;

        // On some kernels, we need to do this again. On some, we don't.
        shell.run(cmd!("sudo chmod 777 /mnt/nullfs").allow_error())?;
    }

    // Start the redis server
    let taskset = if let Some(server_pin_core) = cfg.server_pin_core {
        format!("taskset -c {} ", server_pin_core)
    } else {
        "".into()
    };

    let pintool = match cfg.pintool {
        Some(Pintool::MemTrace {
            pin_path,
            output_path,
        }) => format!(
            "{}/pin -t {}/source/tools/MemTrace/obj-intel64/membuffer.so -o {} -emit -- ",
            pin_path, pin_path, output_path
        ),

        None => "".into(),
    };

    let handle = shell.spawn(cmd!(
        "{}{} {} {}/redis-server {}",
        pintool,
        taskset,
        cfg.cmd_prefix.unwrap_or(""),
        cfg.redis_dir,
        cfg.redis_conf
    ))?;

    // Wait for server to start
    loop {
        let res = shell.run(cmd!("redis-cli -s /tmp/redis.sock INFO"));
        if res.is_ok() {
            break;
        }
    }

    // Settings
    // - maxmemory amount + evict random keys when full
    with_shell! { shell =>
        cmd!("redis-cli -s /tmp/redis.sock CONFIG SET maxmemory-policy allkeys-random"),
        cmd!("redis-cli -s /tmp/redis.sock CONFIG SET maxmemory {}mb", cfg.server_size_mb),
    }

    // Make sure redis doesn't get oom killed.
    oomkiller_blacklist_by_name(shell, "redis-server")?;

    Ok(handle)
}

/// Run the metis matrix multiply workload with the given matrix dimensions (square matrix). This
/// workload takes a really long time, so we start it in a spawned shell and return the join handle
/// rather than waiting for the workload to return.
///
/// NOTE: The amount of virtual memory used by the workload is `(dim * dim) * 4 * 2` bytes so if
/// you want a workload of size `t` GB, use `dim = sqrt(t << 27)`.
///
/// - `bmk_dir` is the path to the `Metis` directory in the workspace on the remote.
/// - `dim` is the dimension of the matrix (one side), which is assumed to be square.
pub fn run_metis_matrix_mult(
    shell: &SshShell,
    bmk_dir: &str,
    dim: usize,
    cmd_prefix: Option<&str>,
    tctx: &mut TasksetCtx,
) -> Result<SshSpawnHandle, SshError> {
    shell.spawn(
        cmd!(
            "taskset -c {} {} ./obj/matrix_mult2 -q -o -l {} ; echo matrix_mult2 done ;",
            tctx.next_unchecked(),
            cmd_prefix.unwrap_or(""),
            dim
        )
        .cwd(bmk_dir),
    )
}

/// What distribution the YCSB workload should use to choose items
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum YcsbDistribution {
    Zipfian,
    Uniform,
    Latest,
}

/// Which YCSB core workload to run.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum YcsbWorkload {
    A,
    B,
    C,
    D,
    E,
    F,
    Custom {
        /// The number of entries to start the workload with
        record_count: usize,
        /// The number of operations to perform in the workload
        op_count: usize,
        /// The distribution of requests across the keyspace to use
        distribution: YcsbDistribution,
        /// The proportion of reads for the workload to perform
        read_prop: f32,
        /// The proportion of updates for the workload to perform
        update_prop: f32,
        /// The proportion of inserts for the workload to perform
        insert_prop: f32,
    },
}

/// Which backend to use for YCSB.
#[derive(Debug)]
pub enum YcsbSystem<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    Postgres(PostgresWorkloadConfig<'s, F>),
    Memcached(MemcachedWorkloadConfig<'s, F>),
    Redis(RedisWorkloadConfig<'s>),
    MongoDB(MongoDBWorkloadConfig<'s, F>),
    KyotoCabinet,
}

/// Every setting of a YCSB workload.
pub struct YcsbConfig<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    pub workload: YcsbWorkload,

    /// A config file for the server.
    ///
    /// For memcached and redis, the following config fields are ignored:
    /// - wk_size_gb
    /// - output_file
    /// - freq
    /// - pf_time
    pub system: YcsbSystem<'s, F>,

    /// The core number that the workload client is pinned to.
    pub client_pin_core: Option<usize>,

    /// The path of the YCSB directory.
    pub ycsb_path: &'s str,

    /// Path for the results file of the YCSB output
    pub ycsb_result_file: Option<&'s str>,
}

/// State associated with actually running a ycsb workload.
pub struct YcsbSession<'a, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    /// The configuration.
    cfg: YcsbConfig<'a, F>,

    /// Computed flags for YCSB.
    flags: Vec<String>,

    /// Any handles that need to be retained to keep stuff running.
    handles: Vec<SshSpawnHandle>,
}

impl<F> YcsbSession<'_, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), ScailError>,
{
    pub fn new(cfg: YcsbConfig<'_, F>) -> YcsbSession<'_, F> {
        YcsbSession {
            cfg,
            flags: vec![],
            handles: vec![],
        }
    }

    /// Start background processes/storage systems/servers, and load the dataset into it, but do
    /// not run the actual workload yet.
    pub fn start_and_load(&mut self, shell: &SshShell) -> Result<(), ScailError> {
        let user_home = get_user_home_dir(shell)?;
        let ycsb_wkld_file = format!("{}/ycsb_wkld", user_home);
        let workload_file = match self.cfg.workload {
            YcsbWorkload::A => "workloads/workloada",
            YcsbWorkload::B => "workloads/workloadb",
            YcsbWorkload::C => "workloads/workloadc",
            YcsbWorkload::D => "workloads/workloadd",
            YcsbWorkload::E => "workloads/workloade",
            YcsbWorkload::F => "workloads/workloadf",
            YcsbWorkload::Custom { .. } => &ycsb_wkld_file,
        };

        let taskset = if let Some(client_pin_core) = self.cfg.client_pin_core {
            format!("taskset -c {}", client_pin_core)
        } else {
            "".into()
        };

        // If this is a custom workload, we have to build the workload file
        if let YcsbWorkload::Custom {
            record_count,
            op_count,
            distribution,
            read_prop,
            update_prop,
            insert_prop,
        } = self.cfg.workload
        {
            let dist = match distribution {
                YcsbDistribution::Zipfian => "zipfian",
                YcsbDistribution::Uniform => "uniform",
                YcsbDistribution::Latest => "latest",
            };

            shell.run(cmd!(
                "echo \"recordcount={}\" > {}",
                record_count,
                ycsb_wkld_file
            ))?;
            shell.run(cmd!(
                "echo \"operationcount={}\" >> {}",
                op_count,
                ycsb_wkld_file
            ))?;
            shell.run(cmd!(
                "echo \"workload=site.ycsb.workloads.CoreWorkload\" >> {}",
                ycsb_wkld_file
            ))?;
            shell.run(cmd!("echo \"readallfields=true\" >> {}", ycsb_wkld_file))?;
            shell.run(cmd!(
                "echo \"readproportion={:.3}\" >> {}",
                read_prop,
                ycsb_wkld_file
            ))?;
            shell.run(cmd!(
                "echo \"updateproportion={:.3}\" >> {}",
                update_prop,
                ycsb_wkld_file
            ))?;
            shell.run(cmd!("echo \"scanproportion=0\" >> {}", ycsb_wkld_file))?;
            shell.run(cmd!(
                "echo \"insertproportion={:.3}\" >> {}",
                insert_prop,
                ycsb_wkld_file
            ))?;
            shell.run(cmd!(
                "echo \"requestdistribution={}\" >> {}",
                dist,
                ycsb_wkld_file
            ))?;
        }

        #[allow(dead_code)]
        /// The number of KB a record takes.
        const RECORD_SIZE_KB: usize = 16;

        match &self.cfg.system {
            YcsbSystem::Postgres(cfg_postgres) => {
                start_postgres(&shell, cfg_postgres)?;

                self.flags.push(format!("-p postgrenosql.url=jdbc:postgresql://localhost:5432/{}", cfg_postgres.user));
                self.flags.push(format!("-p postgrenosql.user={}", cfg_postgres.user));
                shell.run(
                    cmd!(
                        "{} python2 ./bin/ycsb load postgrenosql -s -P {} {}",
                        taskset,
                        ycsb_wkld_file,
                        self.flags.join(" ")
                    )
                    .cwd(&self.cfg.ycsb_path),
                )?;
            }
            YcsbSystem::Memcached(cfg_memcached) => {
                start_memcached(shell, cfg_memcached)?;

                /*
                // This is the number of records that would consume the memory given to memcached
                // (approximately)...
                let nrecords = (cfg_memcached.server_size_mb << 10) / RECORD_SIZE_KB;

                // ... however, the JVM for YCSB also consumes about 5-8% more memory (empirically),
                // so we make the workload a bit smaller to avoid being killed by the OOM killer.
                let nrecords = nrecords * 9 / 10;

                // recordcount is used for the "load" phase, while operationcount is used for the "run
                // phase. YCSB ignores the parameters in the alternate phases.
                let ycsb_flags = format!(
                    "-p memcached.hosts=localhost:11211 -p recordcount={} -p operationcount={}",
                    nrecords, nrecords
                );
                */
                self.flags.push("-p memcached.hosts=localhost:11211".into());

                with_shell! { shell in &self.cfg.ycsb_path =>
                    cmd!("{} python2 ./bin/ycsb load memcached -s -P {} {}", taskset, workload_file, self.flags.join(" ")),
                    cmd!("{}/scripts/memcached-tool localhost:11211", cfg_memcached.memcached),
                }
            }

            YcsbSystem::Redis(cfg_redis) => {
                // Need to hold onto this handle to keep the process alive.
                let handle = start_redis(shell, cfg_redis)?;
                self.handles.push(handle);

                /*
                // This is the number of records that would consume the memory given to redis
                // (approximately)...
                let nrecords = (cfg_redis.server_size_mb << 10) / RECORD_SIZE_KB;

                // ... however, the JVM for YCSB also consumes about 5-8% more memory (empirically),
                // so we make the workload a bit smaller to avoid being killed by the OOM killer.
                let nrecords = nrecords * 9 / 10;

                // recordcount is used for the "load" phase, while operationcount is used for the "run
                // phase. YCSB ignores the parameters in the alternate phases.
                let ycsb_flags = format!(
                    "-p redis.uds=/tmp/redis.sock -p recordcount={} -p operationcount={}",
                    nrecords, nrecords
                );
                */
                self.flags.push("-p redis.uds=/tmp/redis.sock".into());

                with_shell! { shell in &self.cfg.ycsb_path =>
                    cmd!("{} python2 ./bin/ycsb load redis -s -P {} {}", taskset, workload_file, self.flags.join(" ")),
                    cmd!("redis-cli -s /tmp/redis.sock INFO"),
                }
            }

            YcsbSystem::MongoDB(cfg_mongodb) => {
                start_mongodb(shell, cfg_mongodb)?;

                // Load the database before starting the workload
                shell.run(
                    cmd!(
                        "{} python2 ./bin/ycsb load mongodb -s -P {}",
                        taskset,
                        ycsb_wkld_file
                    )
                    .cwd(&self.cfg.ycsb_path),
                )?;
            }

            YcsbSystem::KyotoCabinet => todo!("KC with memtracing support"),
        }

        Ok(())
    }

    /// Run a YCSB workload, returning the handle. `start_and_load` must be called first.
    pub fn run_handle(&mut self, shell: &SshShell) -> Result<SshSpawnHandle, ScailError> {
        let user_home = get_user_home_dir(shell)?;
        let ycsb_wkld_file = format!("{}/ycsb_wkld", user_home);
        let workload_file = match self.cfg.workload {
            YcsbWorkload::A => "workloads/workloada",
            YcsbWorkload::B => "workloads/workloadb",
            YcsbWorkload::C => "workloads/workloadc",
            YcsbWorkload::D => "workloads/workloadd",
            YcsbWorkload::E => "workloads/workloade",
            YcsbWorkload::F => "workloads/workloadf",
            YcsbWorkload::Custom { .. } => &ycsb_wkld_file,
        };
        let ycsb_result_file = self.cfg.ycsb_result_file.unwrap_or("");

        let taskset = if let Some(client_pin_core) = self.cfg.client_pin_core {
            format!("taskset -c {}", client_pin_core)
        } else {
            "".into()
        };

        let handle = match &self.cfg.system {
            YcsbSystem::Postgres(_cfg_postgres) => {
                shell.spawn(
                    cmd!(
                        "{} python2 ./bin/ycsb run postgrenosql -s -P {} {} | tee {}",
                        taskset,
                        workload_file,
                        self.flags.join(" "),
                        ycsb_result_file
                    )
                    .cwd(&self.cfg.ycsb_path),
                )?
            }
            YcsbSystem::Memcached(_cfg_memcached) => {
                shell.spawn(
                    cmd!(
                        "{} python2 ./bin/ycsb run memcached -s -P {} {} | tee {}",
                        taskset,
                        workload_file,
                        self.flags.join(" "),
                        ycsb_result_file
                    )
                    .cwd(self.cfg.ycsb_path),
                )?
            }

            YcsbSystem::Redis(_cfg_redis) => {
                shell.spawn(
                    cmd!(
                        "{} python2 ./bin/ycsb run redis -s -P {} {} | tee {}",
                        taskset,
                        workload_file,
                        self.flags.join(" "),
                        ycsb_result_file
                    )
                    .cwd(self.cfg.ycsb_path),
                )?
            }

            YcsbSystem::MongoDB(_cfg_mongodb) => {
                shell.spawn(
                    cmd!(
                        "{} python2 ./bin/ycsb run mongodb -s -P {} | tee {}",
                        taskset,
                        ycsb_wkld_file,
                        ycsb_result_file
                    )
                    .cwd(self.cfg.ycsb_path),
                )?
            }

            YcsbSystem::KyotoCabinet => todo!("KC with memtracing support"),
        };

        Ok(handle)
    }

    /// Run a YCSB workload, waiting to completion. `start_and_load` must be called first.
    pub fn run(&mut self, shell: &SshShell) -> Result<(), ScailError> {
        self.run_handle(shell)?.join().1?;

        Ok(())
    }
}

/// Run the Graph500 workload (BFS and SSSP), waiting to completion.
pub fn run_graph500(
    shell: &SshShell,
    graph500_path: &str,
    scale: usize,
    output_file: &str,
    cmd_prefix: &str,
    pintool: Option<Pintool<'_>>,
    mmu_overhead: Option<(&str, &[String])>,
) -> Result<(), ScailError> {
    let pintool = match pintool {
        Some(Pintool::MemTrace {
            pin_path,
            output_path,
        }) => format!(
            "{}/pin -t {}/source/tools/MemTrace/obj-intel64/membuffer.so -o {} -emit -ff -- ",
            pin_path, pin_path, output_path
        ),

        None => "".into(),
    };

    let mmu_perf = mmu_overhead
        .map(|(mmu_output, counters)| gen_perf_command_prefix(mmu_output, counters, "-D 5000"))
        .unwrap_or_default();

    // Graph500 consists of 3 phases. The first phase generates the graph. It is not considered
    // part of the benchmark, but it takes a looong time. For memory tracing, we want to fast
    // forward past this part so as not to waste time and bloat the trace. To do this, the -ff flag
    // for the tracing PIN tool waits for `/tmp/pin-memtrace-go` to be created. Additionally, my
    // hacked-up version of graph500 will first create `/tmp/graph500-ready` then wait for
    // `/tmp/insinstrumentation-ready` ready to be created before proceeding.

    // Delete if they happen to already be there.
    shell.run(cmd!(
        "rm -f /tmp/instrumentation-ready /tmp/graph500-ready /tmp/pin-memtrace-go"
    ))?;

    // DAMON doesn't need to wait. Just let it go.
    shell.run(cmd!("touch /tmp/instrumentation-ready"))?;

    // Run the workload, possibly under instrumentation, but don't block.
    let handle = shell.spawn(cmd!(
        "{}{}{}{}/omp-csr/omp-csr -s {} | tee {}",
        mmu_perf,
        pintool,
        cmd_prefix,
        graph500_path,
        scale,
        output_file,
    ))?;

    // Wait for the workload to finish.
    let _out = handle.join();

    Ok(())
}

/// Represents a single SPEC 2017 workload.
pub enum Spec2017Workload {
    Mcf,
    Xz { size: usize },
    Xalancbmk,
    CactuBSSN,
}

pub fn run_spec17(
    shell: &SshShell,
    spec_dir: &str,
    workload: Spec2017Workload,
    input: Option<&str>,
    cmd_prefix: Option<&str>,
    runtime_file: &str,
    // The spec workloads default to 4 threads, so we require 4 cores.
    pin_cores: Vec<usize>,
) -> Result<(), ScailError> {
    let (cmd, bmk) = match workload {
        Spec2017Workload::Mcf => (format!("./mcf_s {}", input.unwrap_or("inp.in")), "mcf_s"),
        Spec2017Workload::Xz { size } => {
            let cmd = if let Some(input) = input {
                format!("./xz_s {}", input)
            } else if size == 0 {
                "./xz_s cpu2006docs.tar.xz 6643 \
                 055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c\
                 774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa\
                 5ad2c04fbc447549c2810fae 1036078272 1111795472 4"
                    .to_string()
            } else {
                format!(
                    "./xz_s cpu2006docs.tar.xz {} \
                        055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c\
                        774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa\
                        5ad2c04fbc447549c2810fae -1 -1 4",
                    size
                )
            };

            (cmd, "xz_s")
        }
        Spec2017Workload::Xalancbmk => {
            let cmd = format!(
                "./xalancbmk_s -v {} xalanc.xsl > /dev/null",
                input.unwrap_or("input.xml")
            );
            (cmd, "xalancbmk_s")
        }
        Spec2017Workload::CactuBSSN => {
            let cmd = format!(
                "./cactuBSSN_s spec_ref.par"
            );
            (cmd, "cactuBSSN_s")
        }
    };

    let bmk_dir = format!(
        "{}/benchspec/CPU/*{}/run/run_base_refspeed_markm-thp-m64.0000",
        spec_dir, bmk
    );

    let pin_cores = pin_cores
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let start = Instant::now();

    shell.run(
        cmd!(
            "sudo taskset -c {} {} {}",
            pin_cores,
            cmd_prefix.unwrap_or(""),
            cmd,
        )
        .cwd(bmk_dir),
    )?;

    // Output the workload runtime in ms as measure of workload performance.
    let duration = Instant::now() - start;
    shell.run(cmd!("echo '{}' > {}", duration.as_millis(), runtime_file))?;

    Ok(())
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum CannealWorkload {
    Small,
    Medium,
    Large,
    Native,
    Custom,
}

pub fn run_canneal(
    shell: &SshShell,
    parsec_path: &str,
    workload: CannealWorkload,
    cmd_prefix: Option<&str>,
    input_file: Option<&str>,
    runtime_file: &str,
    pin_core: usize,
) -> Result<(), ScailError> {
    let canneal_path = format!(
        "{}/pkgs/kernels/canneal/inst/amd64-linux.gcc/bin/",
        parsec_path
    );
    let net_path = format!("{}/pkgs/kernels/canneal/inputs/", parsec_path);

    // Extract the input file
    let input_file = if let CannealWorkload::Custom = workload {
        input_file.unwrap().to_string()
    } else {
        let input_file = match workload {
            CannealWorkload::Small => "input_simsmall.tar",
            CannealWorkload::Medium => "input_simmedium.tar",
            CannealWorkload::Large => "input_simlarge.tar",
            CannealWorkload::Native => "input_native.tar",
            _ => "error",
        };
        shell.run(cmd!("tar -xvf {}", input_file).cwd(&net_path))?;
        shell.run(cmd!("mv *.nets {canneal_path}/input.nets").cwd(&net_path))?;
        format!("{}/input.nets", &canneal_path)
    };

    let cmd = format!("./canneal 1 15000 2000 {} 6000", input_file);

    let start = Instant::now();

    shell.run(
        cmd!(
            "sudo taskset -c {} {} {}",
            pin_core,
            cmd_prefix.unwrap_or(""),
            cmd
        )
        .cwd(canneal_path),
    )?;

    // Output the workload runtime in ms as measure of workload performance.
    let duration = Instant::now() - start;
    shell.run(cmd!("echo '{}' > {}", duration.as_millis(), runtime_file))?;

    Ok(())
}
