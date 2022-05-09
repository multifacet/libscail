//! Common workloads

use std::time::Instant;

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

    prefix.push_str(" ");
    prefix.push_str(extra_args.as_ref());

    prefix.push_str(" -- ");

    prefix
}

/// Keeps track of which guest vCPUs have been assigned.
#[derive(Debug)]
pub struct TasksetCtx {
    /// The total number of vCPUs.
    ncores: usize,

    /// The number of assignments so far.
    next: usize,
}

impl TasksetCtx {
    /// Create a new context with the given total number of cores.
    pub fn new(ncores: usize) -> Self {
        assert!(ncores > 0);
        TasksetCtx { ncores, next: 0 }
    }

    /// Skip one CPU. This is useful to avoid hyperthreading effects.
    pub fn skip(&mut self) {
        self.next += 1;
    }

    /// Get the next core (wrapping around to 0 if all cores have been assigned).
    pub fn next(&mut self) -> usize {
        let c = self.next % self.ncores;
        self.next += 1;
        c
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
pub struct MemcachedWorkloadConfig<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
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
    /// The core number that the workload client is pinned to.
    pub client_pin_core: usize,

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
) -> Result<Option<spurs::SshSpawnHandle>, failure::Error>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
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
    while let Err(..) = shell.run(cmd!("{}/scripts/memcached-tool localhost:11211", cfg.memcached)) {}

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
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
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
    /// The core number that the workload client is pinned to.
    pub client_pin_core: usize,

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
) -> Result<(), failure::Error>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
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
    while let Err(..) = shell.run(cmd!("nc -z localhost 27017")) {}

    // Run the callback.
    (cfg.server_start_cb)(shell)?;

    Ok(())
}

/// Every setting of the redis workload.
#[derive(Debug)]
pub struct RedisWorkloadConfig<'s> {
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
    /// The core number that the workload client is pinned to.
    pub client_pin_core: usize,

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
) -> Result<SshSpawnHandle, failure::Error> {
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
        "{}{} {} /usr/bin/redis-server {}",
        pintool,
        taskset,
        cfg.cmd_prefix.clone().unwrap_or("".into()),
        cfg.redis_conf
    ))?;

    // Wait for server to start
    loop {
        let res = shell.run(cmd!("redis-cli -s /tmp/redis.sock INFO"));
        if res.is_ok() {
            break;
        }
    }

    const REDIS_SNAPSHOT_FREQ_SECS: usize = 300;

    // Settings
    // - maxmemory amount + evict random keys when full
    // - save snapshots every 300 seconds if >= 1 key changed to the file /tmp/dump.rdb
    with_shell! { shell =>
        cmd!("redis-cli -s /tmp/redis.sock CONFIG SET maxmemory-policy allkeys-random"),
        cmd!("redis-cli -s /tmp/redis.sock CONFIG SET maxmemory {}mb", cfg.server_size_mb),

        cmd!("redis-cli -s /tmp/redis.sock CONFIG SET save \"{} 1\"", REDIS_SNAPSHOT_FREQ_SECS),
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
            tctx.next(),
            cmd_prefix.unwrap_or(""),
            dim
        )
        .cwd(bmk_dir),
    )
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
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    Memcached(MemcachedWorkloadConfig<'s, F>),
    Redis(RedisWorkloadConfig<'s>),
    MongoDB(MongoDBWorkloadConfig<'s, F>),
    KyotoCabinet,
}

/// Every setting of a YCSB workload.
pub struct YcsbConfig<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    pub workload: YcsbWorkload,

    /// A config file for the server.
    ///
    /// For memcached and redis, the following config fields are ignored:
    /// - client_pin_core
    /// - wk_size_gb
    /// - output_file
    /// - freq
    /// - pf_time
    pub system: YcsbSystem<'s, F>,

    /// The path of the YCSB directory.
    pub ycsb_path: &'s str,

    /// Path for the results file of the YCSB output
    pub ycsb_result_file: Option<&'s str>,
}

/// State associated with actually running a ycsb workload.
pub struct YcsbSession<'a, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
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
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    pub fn new<'a>(cfg: YcsbConfig<'a, F>) -> YcsbSession<'a, F> {
        YcsbSession {
            cfg,
            flags: vec![],
            handles: vec![],
        }
    }

    /// Start background processes/storage systems/servers, and load the dataset into it, but do
    /// not run the actual workload yet.
    pub fn start_and_load(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
        let user_home = get_user_home_dir(&shell)?;
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

        // If this is a custom workload, we have to build the workload file
        if let YcsbWorkload::Custom {
            record_count,
            op_count,
            read_prop,
            update_prop,
            insert_prop,
        } = self.cfg.workload
        {
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
                "echo \"requestdistribution=zipfian\" >> {}",
                ycsb_wkld_file
            ))?;
        }

        #[allow(dead_code)]
        /// The number of KB a record takes.
        const RECORD_SIZE_KB: usize = 16;

        match &self.cfg.system {
            YcsbSystem::Memcached(cfg_memcached) => {
                start_memcached(shell, &cfg_memcached)?;

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
                    cmd!("./bin/ycsb load memcached -s -P {} {}", workload_file, self.flags.join(" ")),
                    cmd!("{}/scripts/memcached-tool localhost:11211", cfg_memcached.memcached),
                }
            }

            YcsbSystem::Redis(cfg_redis) => {
                // Need to hold onto this handle to keep the process alive.
                let handle = start_redis(shell, &cfg_redis)?;
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
                    cmd!("./bin/ycsb load redis -s -P {} {}", workload_file, self.flags.join(" ")),
                    cmd!("redis-cli -s /tmp/redis.sock INFO"),
                }
            }

            YcsbSystem::MongoDB(cfg_mongodb) => {
                start_mongodb(&shell, cfg_mongodb)?;

                // Load the database before starting the workload
                shell.run(
                    cmd!("./bin/ycsb load mongodb -s -P {}", ycsb_wkld_file)
                        .cwd(&self.cfg.ycsb_path),
                )?;
            }

            YcsbSystem::KyotoCabinet => todo!("KC with memtracing support"),
        }

        Ok(())
    }

    /// Run a YCSB workload, waiting to completion. `start_and_load` must be called first.
    pub fn run(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
        let user_home = get_user_home_dir(&shell)?;
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

        match &self.cfg.system {
            YcsbSystem::Memcached(_cfg_memcached) => {
                shell.run(
                    cmd!(
                        "./bin/ycsb run memcached -s -P {} {} | tee {}",
                        workload_file,
                        self.flags.join(" "),
                        ycsb_result_file
                    )
                    .cwd(&self.cfg.ycsb_path),
                )?;
            }

            YcsbSystem::Redis(_cfg_redis) => {
                shell.run(
                    cmd!(
                        "./bin/ycsb run redis -s -P {} {} | tee {}",
                        workload_file,
                        self.flags.join(" "),
                        ycsb_result_file
                    )
                    .cwd(&self.cfg.ycsb_path),
                )?;
            }

            YcsbSystem::MongoDB(_cfg_mongodb) => {
                shell.run(
                    cmd!(
                        "./bin/ycsb run mongodb -s -P {} | tee {}",
                        ycsb_wkld_file,
                        ycsb_result_file
                    )
                    .cwd(&self.cfg.ycsb_path),
                )?;
            }

            YcsbSystem::KyotoCabinet => todo!("KC with memtracing support"),
        }

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
) -> Result<(), failure::Error> {
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
        .unwrap_or_else(String::new);

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
    Xz {size: usize},
    Xalancbmk,
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
) -> Result<(), failure::Error> {
    let (cmd, bmk) = match workload {
        Spec2017Workload::Mcf => {
            (format!("./mcf_s {}", input.unwrap_or("inp.in")), "mcf_s")
        },
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
        },
        Spec2017Workload::Xalancbmk => {
            let cmd = format!("./xalancbmk_s -v {} xalanc.xsl > /dev/null", input.unwrap_or("input.xml"));
            (cmd, "xalancbmk_s")
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
) -> Result<(), failure::Error> {
    let canneal_path = format!("{}/pkgs/kernels/canneal/inst/amd64-linux.gcc/bin/", parsec_path);
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
        shell.run(cmd!("mv *.nets input.nets").cwd(&net_path))?;
        format!("{}/input.nets", &net_path)
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
