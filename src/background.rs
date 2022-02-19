//! Module for running commands on the remote in the background, possibly periodically, and joining
//! with them at the end of the workload.

use spurs::{Execute, SshShell, SshSpawnHandle};

use crate::cmd;

/// A context for running and joining one or more `BackgroundRun`s.
pub struct BackgroundContext<'s> {
    /// A shell to use for starting tasks.
    shell: &'s SshShell,

    /// Currently running tasks.
    running: Vec<BackgroundTask<'s>>,

    /// Handles for each running task, in order. These are used for `join`ing later.
    handles: Vec<SshSpawnHandle>,
}

/// A background task. Build with `BackgroundTaskBuilder`.
pub struct BackgroundTask<'s> {
    /// The name of the task. Don't use characters that you wouldn't use in a file name.
    pub name: &'s str,

    /// The period with which to run the task, in seconds.
    pub period: usize,

    /// The command to run. Should not end with a semicolon (;).
    pub cmd: String,

    /// A file path to check to ensure that the task has started. If the file exists, then the task
    /// has started.
    pub ensure_started: String,
}

impl<'s> BackgroundContext<'s> {
    /// Create a new empty background job context. The given shell is used to start the tasks via
    /// the `spawn` method.
    pub fn new(shell: &'s SshShell) -> BackgroundContext<'s> {
        BackgroundContext {
            running: vec![],
            handles: vec![],
            shell,
        }
    }

    /// Run the given `BackgroundRun` in the background on the remote.
    pub fn spawn(&mut self, task: BackgroundTask<'s>) -> Result<(), failure::Error> {
        self.running.push(task);
        let handles = self.running.last().as_ref().unwrap().start(self.shell)?;
        self.handles.push(handles);

        Ok(())
    }

    pub fn notify_and_join_all(mut self) -> Result<(), failure::Error> {
        for j in self.running.iter() {
            j.notify(self.shell)?;
        }

        for h in self.handles.drain(..) {
            h.join().1?;
        }

        Ok(())
    }
}

impl BackgroundTask<'_> {
    fn start(&self, shell: &SshShell) -> Result<SshSpawnHandle, failure::Error> {
        let stop_file_path = format!("/tmp/exp-{}-stop", self.name.replace(" ", "-"));

        // Note: command needs to _not_ end with a `;`

        let cmd = cmd!(
            "while [ ! -e {stop_file_path} ] ; do \
                 {cmd} ; \
                 sleep {period} ; \
             done ; \
             {cmd} ; \
             echo done measuring",
            stop_file_path = stop_file_path,
            cmd = self.cmd,
            period = self.period
        )
        .use_bash();

        // Remove the stop path.
        shell.run(cmd!("rm -f {}", stop_file_path))?;

        // Start the task.
        let handle = shell.spawn(cmd)?;

        // Ensure that it has started.
        shell.run(cmd!("while [ ! -e {} ] ; do sleep 1 ; done", self.ensure_started).use_bash())?;

        Ok(handle)
    }

    fn notify(&self, shell: &SshShell) -> Result<(), failure::Error> {
        let stop_file_path = format!("/tmp/exp-{}-stop", self.name.replace(" ", "-"));
        shell.run(cmd!("touch {}", stop_file_path))?;
        Ok(())
    }
}
