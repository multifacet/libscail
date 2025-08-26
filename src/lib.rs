//! A library of routines commonly used in experiments.
//!
//! In honor of my friend Josh:
//!
//!  _━*━___━━___━__*___━_*___┓━╭━━━━━━━━━╮
//! __*_━━___━━___━━*____━━___┗┓|::::::^---^
//! ___━━___━*━___━━____━━*___━┗|::::|｡◕‿‿◕｡|
//! ___*━__━━_*___━━___*━━___*━━╰O­-O---O--O ╯

// Must be imported first because the other submodules use the macros defined therein.
#[macro_use]
mod macros;

#[macro_use]
pub mod output;

pub mod background;
pub mod cpu;
pub mod downloads;
pub mod workloads;

use crate::downloads::download_and_extract;

use std::backtrace::Backtrace;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};

/// An error type for errors that can be returned by various `libscail` functionality.
#[derive(Debug)]
pub enum ScailErrorType {
    /// A local command failed to run because the process began running but terminated with an
    /// error.
    CommandError {
        status: std::process::ExitStatus,

        /// An error message giving the context in `libscail`.
        msg: String,
    },

    /// Data was in an unrecognized, corrupt, or unrecognizable format.
    InvalidValueError {
        /// An error message giving the context in `libscail`.
        msg: String,
    },

    /// An attempt to run a remote command failed, and `spurs` returned an error.
    SpursError(spurs::SshError),

    /// An I/O error occurred while attempting to do something.
    IoError(std::io::Error),
}

#[derive(Debug)]
pub struct ScailError {
    pub err_type: ScailErrorType,
    backtrace: Backtrace,
}

impl ScailError {
    pub fn new(err_type: ScailErrorType) -> ScailError {
        ScailError {
            err_type,
            backtrace: Backtrace::capture(),
        }
    }

    pub fn backtrace(&self) -> String {
        self.backtrace.to_string()
    }
}

impl From<std::io::Error> for ScailError {
    fn from(err: std::io::Error) -> Self {
        ScailError::new(ScailErrorType::IoError(err))
    }
}

impl From<spurs::SshError> for ScailError {
    fn from(err: spurs::SshError) -> Self {
        ScailError::new(ScailErrorType::SpursError(err))
    }
}

impl From<std::str::Utf8Error> for ScailError {
    fn from(err: std::str::Utf8Error) -> Self {
        ScailError::new(ScailErrorType::InvalidValueError {
            msg: format!("unable to convert to UTF-8: {err}"),
        })
    }
}

impl From<serde_json::Error> for ScailError {
    fn from(err: serde_json::Error) -> Self {
        ScailError::new(ScailErrorType::InvalidValueError {
            msg: format!("error while serializing or deserializing: {err}"),
        })
    }
}

impl From<std::num::ParseIntError> for ScailError {
    fn from(err: std::num::ParseIntError) -> Self {
        ScailError::new(ScailErrorType::InvalidValueError {
            msg: format!("error parsing integer: {err}"),
        })
    }
}

impl std::fmt::Display for ScailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.err_type {
            ScailErrorType::CommandError { msg, .. } | ScailErrorType::InvalidValueError { msg } => {
                write!(f, "{msg}")
            }
            ScailErrorType::SpursError(err) => write!(f, "{err}"),
            ScailErrorType::IoError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ScailError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.err_type {
            ScailErrorType::CommandError { .. } | ScailErrorType::InvalidValueError { .. } => None,
            ScailErrorType::SpursError(err) => Some(err),
            ScailErrorType::IoError(err) => Some(err),
        }
    }
}

/// Validators for different CLI options.
pub mod validator {
    /// Validates that the argument is of type `T` that can be parsed from a string.
    pub fn is<T>(s: String) -> Result<(), String>
    where
        T: std::str::FromStr,
        <T as std::str::FromStr>::Err: std::fmt::Debug,
    {
        s.as_str()
            .parse::<T>()
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }
}

/// A git repository.
#[derive(Clone, Debug)]
pub enum GitRepo<'a, 's> {
    /// Use HTTPS to clone a public repo (no access control).
    HttpsPublic {
        /// Repo https URL (e.g. `github.com/multifacet/0sim-workspace`). Note the lack of `https://`!
        repo: &'a str,
    },

    /// Use HTTPS to clone a private repo. A password or personal access token must be provided at
    /// the time of the clone.
    HttpsPrivate {
        /// Repo https URL (e.g. `github.com/multifacet/0sim-workspace`). Note the lack of `https://`!
        repo: &'a str,

        /// The username to use when cloning the repository (e.g. `robo-mark-i-m` is the github
        /// username we use).
        username: &'s str,

        /// The personal access token or password to access the private repo
        secret: &'s str,
    },

    /// Use SSH. Not PAT is needed, and this works for public and private repos.
    Ssh {
        /// Repo git URL (e.g. `git@github.com:multifacet/0sim-workspace`)
        repo: &'s str,
    },
}

impl GitRepo<'_, '_> {
    /// Given a repository and access method, form the URL string to be passed to git.
    ///
    /// If this repository is public or SSH is used, then `secret` is ignored.
    pub fn git_repo_access_url(&self) -> String {
        match self {
            GitRepo::Ssh { repo } => repo.to_string(),
            GitRepo::HttpsPublic { repo } => format!("https://{}", repo),
            GitRepo::HttpsPrivate { repo, username, secret } => {
                format!("https://{}:{}@{}", username, secret, repo)
            }
        }
    }

    /// Given a repository, return the name of the default directory name for that
    /// repo if it is cloned.
    pub fn git_repo_default_name(&self) -> String {
        let repo = match self {
            GitRepo::Ssh { repo } => repo,
            GitRepo::HttpsPublic { repo } => repo,
            GitRepo::HttpsPrivate { repo, username: _, secret: _ } => repo,
        };

        // We want the string after the last "/" in the url
        let split = repo.split('/').collect::<Vec<&str>>();
        let name = split[split.len() - 1];
        let len = name.len();

        // Remove ".git" at the end of the name if it is there
        if len > 4 && name[len - 4..].eq(".git") {
            name[0..len - 4].to_string()
        } else {
            name.to_string()
        }
    }
}

/// Information needed to log into a remote machine.
#[derive(Clone, Debug)]
pub struct Login<'u, 'h, A: std::net::ToSocketAddrs + std::fmt::Display + Clone> {
    /// A network address for the host.
    pub host: A,
    /// A human-readable address for the host. Often, this is the same as `host`.
    pub hostname: &'h str,
    /// The username to log in as.
    pub username: &'u str,
}

/// Given an array of timings, generate a human-readable string.
pub fn timings_str(timings: &[(&str, std::time::Duration)]) -> String {
    let mut s = String::new();
    for (label, d) in timings.iter() {
        s.push_str(&format!("{}: {:?}\n", label, d));
    }
    s
}

/// Copy the given directory or files from this machine to the given remote at the given location.
/// This uses rsync via SSH to copy with compression, which often leads to significant speedups.
/// However, it will fail if the remote is not in known_hosts.
pub fn rsync_to_remote<A, P>(login: &Login<A>, from: P, to: P) -> Result<(), ScailError>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
    P: AsRef<Path>,
{
    println!(
        "Using rsync to copy files. If this fails, make sure your host is in \
         known_hosts and retry."
    );

    let mut cmd = Command::new("rsync");
    cmd.arg("-vvzP")
        .args(["-e", "ssh -o StrictHostKeyChecking=yes"])
        .arg(from.as_ref().as_os_str())
        .arg(format!(
            "{}@{}:{}",
            login.username,
            login.host.to_socket_addrs()?.next().unwrap().ip(),
            to.as_ref().display()
        ));

    println!("{:?}", cmd);

    let status = cmd.status()?;

    // If failure, exit with an Err(..).
    if !status.success() {
        return Err(ScailError::new(ScailErrorType::CommandError {
            status,
            msg: format!("rsync failed. Exit code: {:?}", status.code()),
        }));
    }

    Ok(())
}

/// Clone the repo and checkout the given submodules.
///
/// `secret` is a GitHub personal access token or password that is needed if a private repo is
/// being accessed via HTTPS.
///
/// If the repository is already cloned, it is updated (along with submodules).
///
/// Returns the git hash of the cloned repo.
///
pub fn clone_git_repo(
    ushell: &SshShell,
    repo: GitRepo,
    dir_name: Option<&str>,
    branch: Option<&str>,
    submodules: &[&str],
) -> Result<String, ScailError> {
    let default_name = repo.git_repo_default_name();
    let dir_name = dir_name.unwrap_or(&default_name);
    let branch_name = branch.unwrap_or("master");

    // Check if the repo is already cloned.
    if let Ok(_hash) = get_git_hash(ushell, dir_name) {
        // If so, just update it.
        with_shell! { ushell in &dir!(dir_name) =>
            cmd!("git fetch"),
            cmd!("git checkout {}", branch_name),
            cmd!("git pull"),
            cmd!("git submodule update"),
        }
    } else {
        // Clone the repo.
        ushell.run(cmd!(
            "git clone -b {} {} {}",
            branch_name,
            repo.git_repo_access_url(),
            dir_name,
        ))?;
    }

    // Checkout submodules.
    for submodule in submodules {
        ushell
            .run(cmd!("git submodule update --init --recursive -- {}", submodule).cwd(dir_name))?;
    }

    // Get the sha hash.
    get_git_hash(ushell, dir_name)
}

/// Get the git hash of the remote research workspace.
pub fn get_git_hash(ushell: &SshShell, name: &str) -> Result<String, ScailError> {
    let hash = ushell.run(cmd!("git rev-parse HEAD").cwd(name))?;
    let hash = hash.stdout.trim();

    Ok(hash.into())
}

/// Get the git hash of the local research workspace, specifically the workspace from which the
/// runner is run. Returns `"dirty"` if the workspace has uncommitted changes.
pub fn local_research_workspace_git_hash() -> Result<String, ScailError> {
    let is_dirty = std::process::Command::new("git")
        .args(["diff", "--quiet"])
        .status()?
        .code()
        .expect("terminated by signal")
        == 1;

    if is_dirty {
        return Ok("dirty".into());
    }

    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()?;
    let output = std::str::from_utf8(&output.stdout)?;
    let output = output.trim();
    Ok(output.into())
}

/// Get the path of the user's home directory.
pub fn get_user_home_dir(ushell: &SshShell) -> Result<String, ScailError> {
    let user_home = ushell
        .run(cmd!("echo $HOME").use_bash())?
        .stdout
        .trim()
        .to_owned();
    if user_home.is_empty() {
        Err(ScailError::new(ScailErrorType::InvalidValueError {
            msg: "$HOME is empty".into(),
        }))
    } else {
        Ok(user_home)
    }
}

/// There are some settings that are per-machine, rather than per-experiment (e.g. which devices to
/// turn on as swap devices). We keep these settings in a per-machine file called
/// `research-settings.json`, which is generated at the time of the setup.
///
/// This function sets the given setting or overwrites its current value.
pub fn set_remote_research_setting<V: Serialize>(
    ushell: &SshShell,
    setting: &str,
    value: V,
) -> Result<(), ScailError> {
    // Make sure the file exists
    ushell.run(cmd!("touch research-settings.json"))?;

    // We don't care too much about efficiency, so whenever we update, we will just read,
    // deserialize, update, and reserialize.
    let mut settings = get_remote_research_settings(ushell)?;

    let serialized = serde_json::to_string(&value).expect("unable to serialize");
    settings.insert(setting.into(), serialized);

    let new_contents = serde_json::to_string(&settings).expect("unable to serialize");

    ushell.run(cmd!(
        "echo {} > research-settings.json",
        spurs_util::escape_for_bash(&new_contents)
    ))?;

    Ok(())
}

/// Return all research settings. The user can then use `get_remote_research_setting` to parse out
/// a single value.
pub fn get_remote_research_settings(
    ushell: &SshShell,
) -> Result<std::collections::BTreeMap<String, String>, ScailError> {
    // Make sure the file exists
    ushell.run(cmd!("touch research-settings.json"))?;

    let file_contents = ushell.run(cmd!("cat research-settings.json"))?;
    let file_contents = file_contents.stdout.trim();

    if file_contents.is_empty() {
        Ok(std::collections::BTreeMap::new())
    } else {
        Ok(serde_json::from_str(file_contents).expect("unable to deserialize"))
    }
}

/// Returns the value of the given setting if it is set.
pub fn get_remote_research_setting<'s, 'd, V: Deserialize<'d>>(
    settings: &'s std::collections::BTreeMap<String, String>,
    setting: &str,
) -> Result<Option<V>, ScailError>
where
    's: 'd,
{
    if let Some(setting) = settings.get(setting) {
        Ok(Some(serde_json::from_str(setting)?))
    } else {
        Ok(None)
    }
}

/// Generate a local version name from the git branch and hash.
///
/// If the branch name is longer than 15 characters, it is truncated. If the git hash is longer
/// than 15 characters, it is truncated.
pub fn gen_local_version(branch: &str, hash: &str) -> String {
    let branch_split = std::cmp::min(branch.len(), 15);
    let hash_split = std::cmp::min(hash.len(), 15);
    format!(
        "{}-{}",
        branch.split_at(branch_split).0.replace("_", "-"),
        hash.split_at(hash_split).0
    )
}

/// Generate a new vagrant domain name and update the Vagrantfile.
pub fn gen_new_vagrantdomain(
    shell: &SshShell,
    vagrant_box: &str,
    vagrant_path: &str,
) -> Result<(), ScailError> {
    let uniq = shell.run(cmd!("date | sha256sum | head -c 10"))?;
    let uniq = uniq.stdout.trim();

    with_shell! { shell in vagrant_path =>
        cmd!(
            r#"sed -i 's/^vagrant_vm_name = :test_vm$/vagrant_vm_name = :test_vm_{}/' Vagrantfile"#,
            uniq
        ),
        cmd!(
            r#"sed -i 's|^vagrant_box = .*$|vagrant_box = "{}"|' Vagrantfile"#,
            vagrant_box
        ),
    }

    Ok(())
}

/// Returns the number of processor cores on the machine.
pub fn get_num_cores(shell: &SshShell) -> Result<usize, ScailError> {
    let nprocess = shell.run(cmd!("getconf _NPROCESSORS_ONLN"))?.stdout;
    let nprocess = nprocess.trim();
    let nprocess = nprocess.parse::<usize>()?;

    Ok(nprocess)
}

/// Get the max CPU frequency of the remote in MHz.
///
/// NOTE: this is not necessarily the current CPU freq. You need to set the scaling governor.
pub fn get_cpu_freq(shell: &SshShell) -> Result<usize, ScailError> {
    let freq =
        shell.run(cmd!("lscpu | grep 'CPU max MHz' | grep -oE '[0-9]+' | head -n1").use_bash())?;
    let alt =
        shell.run(cmd!("lscpu | grep 'CPU MHz' | grep -oE '[0-9]+' | head -n1").use_bash())?;
    if freq.stdout.trim().is_empty() {
        Ok(alt.stdout.trim().parse::<usize>().unwrap())
    } else {
        Ok(freq.stdout.trim().parse::<usize>().unwrap())
    }
}

/// Turn off ASLR.
pub fn disable_aslr(shell: &SshShell) -> Result<(), ScailError> {
    shell.run(cmd!(
        "echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
    ))?;
    Ok(())
}

/// Turn on ASLR.
pub fn enable_aslr(shell: &SshShell) -> Result<(), ScailError> {
    shell.run(cmd!(
        "echo 2 | sudo tee /proc/sys/kernel/randomize_va_space"
    ))?;
    Ok(())
}

/// Allow any user to run `perf`.
pub fn perf_for_all(shell: &SshShell) -> Result<(), ScailError> {
    shell.run(cmd!(
        "echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
    ))?;
    Ok(())
}

/// Turn on THP on the remote using the given settings. Requires `sudo`.
pub fn turn_on_thp(
    shell: &SshShell,
    transparent_hugepage_enabled: &str,
    transparent_hugepage_defrag: &str,
    transparent_hugepage_khugepaged_defrag: usize,
    transparent_hugepage_khugepaged_alloc_sleep_ms: usize,
    transparent_hugepage_khugepaged_scan_sleep_ms: usize,
) -> Result<(), ScailError> {
    shell.run(
        cmd!(
            "echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/enabled",
            transparent_hugepage_enabled
        )
        .use_bash(),
    )?;
    shell.run(
        cmd!(
            "echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/defrag",
            transparent_hugepage_defrag
        )
        .use_bash(),
    )?;
    shell.run(
        cmd!(
            "echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/khugepaged/defrag",
            transparent_hugepage_khugepaged_defrag
        )
        .use_bash(),
    )?;
    shell.run(
        cmd!("echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/khugepaged/alloc_sleep_millisecs",
             transparent_hugepage_khugepaged_alloc_sleep_ms).use_bash(),
    )?;
    shell.run(
        cmd!("echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs",
             transparent_hugepage_khugepaged_scan_sleep_ms).use_bash(),
    )?;

    Ok(())
}

pub fn set_auto_numa(shell: &SshShell, on: bool) -> Result<(), ScailError> {
    shell.run(cmd!(
        "echo {} | sudo tee /proc/sys/kernel/numa_balancing",
        if on { 1 } else { 0 }
    ))?;

    Ok(())
}

/// What type of package to produce from the kernel build?
pub enum KernelPkgType {
    /// `bindeb-pkg`
    Deb,
    /// `binrpm-pkg`
    Rpm,
}

/// Where to build the kernel from?
pub enum KernelSrc {
    /// The given git repo and commitish (a branch, tag, commit hash, etc, as accepted by git).
    ///
    /// The repo should already be cloned at the give path. This function will checkout the given
    /// branch, though, so the repo should be clean.
    Git {
        repo_path: String,
        commitish: String,
    },

    /// The given tarball, which will be untarred and built as is. We assume that the name of the
    /// unpacked source directory is the same as the tarball name without the `.tar.gz`, `.tar.xz`,
    /// or `.tgz` extension.
    Tar { tarball_path: String },
}

/// Where to get the base config (on top of which we will apply additional changes)?
pub enum KernelBaseConfigSource {
    /// Use `make defconfig`
    Defconfig,

    /// Use the running kernel.
    Current,

    /// Use the config from the given path.
    Path(String),
}

/// How to configure the kernel build? The config is created by taking some "base config", such as
/// the one for the running kernel, and applying some changes to it to enable or disable additional
/// options.
pub struct KernelConfig<'a> {
    pub base_config: KernelBaseConfigSource,

    /// A list of config option names that should be set or unset before building. It is the
    /// caller's responsibility to make sure that all dependencies are on too. If a config is
    /// `true` it is set to "y"; otherwise, it is unset.
    pub extra_options: &'a [(&'a str, bool)],
}

/// Contains paths to output from building a kernel.
pub struct KernelBuildArtifacts {
    /// The path to the source directory that was built.
    pub source_path: String,

    /// The path to the build directory.
    pub kbuild_path: String,

    /// The path to the built kernel DEB or RPM.
    pub pkg_path: String,

    /// The path to the built kernel headers DEB or RPM.
    pub headers_pkg_path: String,
}

pub fn get_absolute_path(shell: &SshShell, path: &str) -> Result<String, ScailError> {
    Ok(shell.run(cmd!("pwd").cwd(path))?.stdout.trim().into())
}

/// Build a Linux kernel package (RPM or DEB). This command does not install the new kernel.
///
/// `kernel_local_version` is the kernel `LOCALVERSION` string to pass to `make` for the RPM, if
/// any.
///
/// `cpupower` indicates whether to build and install `cpupower` (true) or not (false).
pub fn build_kernel(
    ushell: &SshShell,
    source: KernelSrc,
    config: KernelConfig<'_>,
    kernel_local_version: Option<&str>,
    pkg_type: KernelPkgType,
    compiler: Option<&str>,
    cpupower: bool,
) -> Result<KernelBuildArtifacts, ScailError> {
    // Check out or unpack the source code, returning its absolute path.
    let source_path = match source {
        KernelSrc::Git {
            repo_path,
            commitish,
        } => {
            ushell.run(cmd!("git fetch origin").cwd(&repo_path))?;
            ushell.run(cmd!("git checkout {commitish}").cwd(&repo_path))?;

            // If the git HEAD is detached, we should not attempt to `git pull` the latest changes,
            // as that doesn't make any sense.
            let is_detached = ushell
                .run(cmd!("git symbolic-ref -q HEAD").cwd(&repo_path))
                .is_err();

            if !is_detached {
                ushell.run(cmd!("git reset --hard origin/{commitish}").cwd(&repo_path))?;
            }

            get_absolute_path(ushell, &repo_path)?
        }

        KernelSrc::Tar { tarball_path } => {
            ushell.run(cmd!("tar xvf {tarball_path}"))?;

            get_absolute_path(
                ushell,
                tarball_path
                    .trim_end_matches(".tar.gz")
                    .trim_end_matches(".tar.xz")
                    .trim_end_matches(".tgz"),
            )?
        }
    };

    // Compiler path, if any.
    let compiler = if let Some(compiler) = compiler {
        format!("CC={compiler}")
    } else {
        "CC=/usr/bin/gcc".into()
    };

    // kbuild path.
    let kbuild_path = format!("{source_path}/kbuild");

    ushell.run(cmd!("mkdir -p {kbuild_path}"))?;

    // save old config if there is one.
    ushell.run(
        cmd!("cp .config config.bak")
            .cwd(&kbuild_path)
            .allow_error(),
    )?;

    // configure the new kernel we are about to build.
    ushell.run(cmd!("make O={kbuild_path} defconfig").cwd(&source_path))?;

    match config.base_config {
        // Nothing else to do
        KernelBaseConfigSource::Defconfig => {}

        KernelBaseConfigSource::Current => {
            let config = ushell
                .run(cmd!("ls -1 /boot/config-* | head -n1").use_bash())?
                .stdout;
            let config = config.trim();
            ushell.run(cmd!("cp {config} {kbuild_path}/.config"))?;
            ushell.run(cmd!("yes '' | make oldconfig").use_bash().cwd(&kbuild_path))?;
        }

        KernelBaseConfigSource::Path(template_path) => {
            ushell.run(cmd!("cp {template_path} {kbuild_path}/.config"))?;
            ushell.run(cmd!("yes '' | make oldconfig").use_bash().cwd(&kbuild_path))?;
        }
    }

    ushell.run(
        cmd!(
            r#"sed -i 's/CONFIG_SYSTEM_TRUSTED_KEYS=".*"/CONFIG_SYSTEM_TRUSTED_KEYS=""/' .config"#
        )
        .cwd(&kbuild_path),
    )?;
    ushell.run(cmd!(r#"sed -i 's/CONFIG_SYSTEM_REVOCATION_KEYS=".*"/CONFIG_SYSTEM_REVOCATION_KEYS=""/' .config"#).cwd(&kbuild_path))?;
    for (opt, set) in config.extra_options.iter() {
        if *set {
            ushell.run(cmd!(
                "sed -i 's/# {opt} is not set/{opt}=y/' {kbuild_path}/.config",
            ))?;
        } else {
            ushell.run(cmd!(
                "sed -i '/{opt}=/s/{opt}=.*$/# {opt} is not set/' {kbuild_path}/.config",
            ))?;
        }

        // Some options don't show up in the .config file if the conditions they depend on
        // (e.g. certain configs enabled/disabled) are not true, so call make oldconfig
        // after each config change to ensure the config lines exist for sed to replace.
        ushell.run(cmd!("yes '' | make oldconfig").cwd(&kbuild_path))?;
    }

    // Compile with as many processors as we have.
    //
    // NOTE: for some reason, this sometimes fails the first time, so just do it again.
    //
    // NOTE: we pipe `yes` into make because in some cases the build will request updating some
    // aspects of the config in ways that `make oldconfig` does not address, such as to generate a
    // signing key.
    let nprocess = get_num_cores(ushell)?;

    let make_target = match pkg_type {
        KernelPkgType::Deb => "bindeb-pkg",
        KernelPkgType::Rpm => "binrpm-pkg",
    };

    // Sometimes there is an error the first time. If so, retrying usually works.
    let res = ushell.run(
        cmd!(
            "yes '' | make -j {nprocess} {compiler} {make_target} {}",
            if let Some(kernel_local_version) = kernel_local_version {
                let kernel_local_version = kernel_local_version.replace("/", "-");
                format!("LOCALVERSION=-{kernel_local_version}")
            } else {
                "".into()
            }
        )
        .cwd(&kbuild_path),
    );
    if res.is_err() {
        ushell.run(
            cmd!(
                "make -j {nprocess} {compiler} {make_target} {}",
                if let Some(kernel_local_version) = kernel_local_version {
                    let kernel_local_version = kernel_local_version.replace("/", "-");
                    format!("LOCALVERSION=-{kernel_local_version}")
                } else {
                    "".into()
                }
            )
            .cwd(&kbuild_path),
        )?;
    }

    // Build and install `cpupower` and `libcpupower`, if needed.
    if cpupower {
        ushell.run(
            cmd!("make -j {nprocess} {compiler} && sudo make install")
                .cwd(&dir!(&source_path, "tools/power/cpupower/")),
        )?;
        // Make sure we reload the ld cache, so that new cpupower library is used.
        ushell.run(cmd!("sudo ldconfig"))?;
    }

    // Get the path to the built package so we can return it.
    let (pkg_path, headers_pkg_path) = match pkg_type {
        KernelPkgType::Deb => {
            let pkg_path = ushell
                .run(cmd!(
                    "ls -dArt {source_path}/* | \
                        grep '.*\\.deb' |\
                        grep -v headers | \
                        grep -v libc | \
                        grep -v dbg | \
                        tail -n 1"
                ))?
                .stdout
                .trim()
                .to_owned();
            let headers_pkg_path = ushell
                .run(cmd!(
                    "ls -dArt {source_path}/* | \
                        grep '.*\\.deb' | \
                        grep headers | \
                        tail -n 1"
                ))?
                .stdout
                .trim()
                .to_owned();
            (pkg_path, headers_pkg_path)
        }
        KernelPkgType::Rpm => {
            let user_home = &get_user_home_dir(ushell)?;
            let pkg_path = ushell
                .run(
                    cmd!(
                        "ls -Art {user_home}/rpmbuild/RPMS/x86_64/ |\
                            grep -v headers |\
                            tail -n 1",
                    )
                    .use_bash(),
                )?
                .stdout
                .trim()
                .to_owned();
            let headers_pkg_path = ushell
                .run(
                    cmd!(
                        "ls -Art {user_home}/rpmbuild/RPMS/x86_64/ |\
                            grep  headers |\
                            tail -n 1",
                    )
                    .use_bash(),
                )?
                .stdout
                .trim()
                .to_owned();
            (pkg_path, headers_pkg_path)
        }
    };

    Ok(KernelBuildArtifacts {
        source_path,
        kbuild_path,
        pkg_path,
        headers_pkg_path,
    })
}

/// Something that may be done to a service.
pub enum ServiceAction {
    /// Start the service if it is not active. Otherwise, do nothing.
    Start,
    /// Stop the service if it is active. Otherwise, do nothing.
    Stop,
    /// Restart the service, or start it if it is not active. Requires that the service exist.
    Restart,
    /// Disable and stop the service if it is active. Otherwise, do nothing.
    Disable,
    /// Enable the service, but do not start it. Requires that the service exist.
    Enable,
}

/// Start, stop, enable, disable, or restart a service.
pub fn service(shell: &SshShell, service: &str, action: ServiceAction) -> Result<(), ScailError> {
    let is_active = service_is_active(shell, service)?;

    match action {
        ServiceAction::Restart => {
            if is_active {
                shell.run(cmd!("sudo systemctl restart {}", service))?;
            } else {
                shell.run(cmd!("sudo systemctl start {}", service))?;
            }
        }
        ServiceAction::Start => {
            if !is_active {
                shell.run(cmd!("sudo systemctl start {}", service))?;
            }
        }
        ServiceAction::Stop => {
            if is_active {
                shell.run(cmd!("sudo systemctl stop {}", service))?;
            }
        }
        ServiceAction::Enable => {
            shell.run(cmd!("sudo systemctl enable {}", service))?;
        }
        ServiceAction::Disable => {
            if is_active {
                shell.run(cmd!("sudo systemctl disable --now {}", service))?;
            }
        }
    }

    Ok(())
}

/// Returns true if the given service is running.
pub fn service_is_active(shell: &SshShell, service: &str) -> Result<bool, ScailError> {
    Ok(shell.run(cmd!("systemctl is-active {}", service)).is_ok())
}

/// Set up passphraseless SSH to localhost.
pub fn setup_passphraseless_local_ssh(ushell: &SshShell) -> Result<(), ScailError> {
    // First check if it already works
    if ushell
        .run(cmd!("ssh -o StrictHostKeyChecking=no localhost -- whoami"))
        .is_err()
    {
        with_shell! { ushell =>
            cmd!("ssh-keygen -t rsa -N '' -f ~/.ssh/id_rsa").no_pty(),
            cmd!("cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys"),
            cmd!("ssh-keygen -R localhost -f ~/.ssh/known_hosts"),
            cmd!("ssh-keyscan -H localhost >> ~/.ssh/known_hosts"),
        }
    }

    // Test it.
    ushell.run(cmd!("ssh localhost -- whoami"))?;

    Ok(())
}

/// Returns the device id from `/dev/disk/by-id/` of the given device. `dev_name` should _exclude_
/// the `/dev/` (e.g. `sda`).
pub fn get_device_id(shell: &SshShell, dev_name: &str) -> Result<String, ScailError> {
    let out = shell.run(
        cmd!(
            "ls -lah /dev/disk/by-id/ | \
            sort -k 11 | \
            awk '{{print $11 \"\\t\" $9}}' | \
            grep {} | \
            head -n 1 | \
            awk '{{print $2}}'",
            dev_name
        )
        .use_bash(),
    )?;
    let name = out.stdout.trim().to_owned();

    if name.is_empty() {
        Err(ScailError::new(ScailErrorType::InvalidValueError {
            msg: format!("Unable to find device by ID: {}", dev_name),
        }))
    } else {
        Ok(name)
    }
}

/// Resize the root partition and file system to take up the whole remainder of the drive,
/// destroying an partitions that come after it.
pub fn resize_root_partition(shell: &SshShell) -> Result<(), ScailError> {
    // Find the root partition and device name.
    let output = shell
        .run(cmd!(
            r#"eval `lsblk -P -o NAME,PKNAME,MOUNTPOINT |\
              grep 'MOUNTPOINT="/"'` ; echo $NAME ; echo $PKNAME"#
        ))?
        .stdout;
    let mut output = output.split_whitespace();
    let root_part = output.next().unwrap().trim().to_owned();
    let root_device = output.next().unwrap().trim().to_owned();

    // Dump the original partition table.
    shell.run(cmd!(
        "sudo sfdisk -d /dev/{} | tee /tmp/sfdisk.old",
        root_device
    ))?;
    shell.run(cmd!("cp /tmp/sfdisk.old /tmp/sfdisk.new"))?;

    // Disable swap partitions.
    shell.run(cmd!(
        "for part in `lsblk -l | grep 'SWAP' | \
         grep {} | awk '{{print $1}}'` ; do \
         sudo swapoff /dev/$part ; done",
        root_device
    ))?;

    // Compute a new partition table. We want to canabalize all partitions after the root
    // partition.
    let table_raw = shell
        .run(cmd!(
            r#"cat /tmp/sfdisk.new |\
               grep '^/dev' |\
               sed 's|/dev/\([a-z0-9]*\).*start= *\([0-9]*\).*size= *\([0-9]*\).*|\1 \2 \3|g'"#,
        ))?
        .stdout;
    let mut old_partitions = std::collections::HashMap::new();
    for line in table_raw.lines() {
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap().trim();
        let start = parts.next().unwrap().trim().parse::<usize>().unwrap();
        let size = parts.next().unwrap().trim().parse::<usize>().unwrap();

        old_partitions.insert(name.to_string(), (start, size));
    }

    // Compute the list of partitions to delete and the new size of the root partition.
    let root_start = old_partitions.get(root_part.as_str()).unwrap().0;
    let to_delete: Vec<_> = old_partitions
        .iter()
        .filter_map(|(name, (start, _))| {
            if *start > root_start {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    let last_partition = old_partitions
        .iter()
        .max_by(|(_, (starta, sizea)), (_, (startb, sizeb))| {
            (starta + sizea).cmp(&(startb + sizeb))
        })
        .unwrap();

    let root_new_size = last_partition.1 .0 + last_partition.1 .1 - root_start;

    // Delete the partitions we want to get rid of (but not actually yet).
    for part in to_delete.into_iter() {
        shell.run(cmd!(r#"sed -i "/{}/d" /tmp/sfdisk.new"#, part))?;
    }

    // Update the root partition size (but not actually yet).
    shell.run(cmd!(
        r#"sed "s|\(.*{}.*size= *\)[0-9]*\(.*\)|\1{}\2|" /tmp/sfdisk.new > /tmp/sfdisk.new1 \
        && mv /tmp/sfdisk.new1 /tmp/sfdisk.new"#,
        root_part,
        root_new_size
    ))?;

    // Print old and new partition tables.
    shell.run(cmd!("cat /tmp/sfdisk.old /tmp/sfdisk.new"))?;

    // Actually change disk layout now.
    shell.run(cmd!("sudo sfdisk --force /dev/{} < /tmp/sfdisk.new", root_device).allow_error())?;
    shell.run(cmd!("sudo partprobe /dev/{}", root_device))?;
    shell.run(cmd!("sudo resize2fs /dev/{}", root_part))?;

    // Finally print results.
    shell.run(cmd!("lsblk ; df -h"))?;

    Ok(())
}

/// Dump a bunch of kernel info for debugging.
pub fn dump_sys_info(shell: &SshShell) -> Result<(), ScailError> {
    with_shell! { shell =>
        cmd!("uname -a"),
        cmd!("lsblk"),
        cmd!("free -h"),
    }

    Ok(())
}

/// Set the kernel `printk` level that gets logged to `dmesg`. `0` is only high-priority
/// messages. `7` is all messages.
pub fn set_kernel_printk_level(shell: &SshShell, level: usize) -> Result<(), ScailError> {
    assert!(level <= 7);
    shell.run(cmd!("echo {} | sudo tee /proc/sys/kernel/printk", level).use_bash())?;
    Ok(())
}

/// Tell the OOM killer not to kill the given process.
pub fn oomkiller_blacklist_by_name(shell: &SshShell, name: &str) -> Result<(), ScailError> {
    shell.run(cmd!(
        r"pgrep -f {} | while read PID; do \
            echo -1000 | sudo tee /proc/$PID/oom_score_adj;
        done",
        name
    ))?;

    Ok(())
}

/// Turn off soft lockup and NMI watchdogs if possible in the shell.
pub fn turn_off_watchdogs(shell: &SshShell) -> Result<(), ScailError> {
    shell.run(cmd!(
        "echo 0 | sudo tee /proc/sys/kernel/hung_task_timeout_secs"
    ))?;
    shell.run(cmd!("echo 0 | sudo tee /proc/sys/kernel/watchdog").allow_error())?;
    Ok(())
}

/// Gathers some common stats for any experiment. This is intended to be called after the
/// simulation.
///
/// Requires `sudo`.
pub fn gen_standard_host_output(
    out_dir: &str,
    out_file: &str,
    shell: &SshShell,
) -> Result<(), ScailError> {
    let out_file = dir!(out_dir, out_file);

    // Host config
    shell.run(cmd!("echo -e 'Host Config\n=====' > {}", out_file))?;
    shell.run(cmd!("cat /proc/cpuinfo >> {}", out_file))?;
    shell.run(cmd!("lsblk >> {}", out_file))?;

    // Memory usage, compressibility
    shell.run(cmd!(
        "echo -e '\nSimulation Stats (Host)\n=====' >> {}",
        out_file
    ))?;
    shell.run(cmd!("cat /proc/meminfo >> {}", out_file))?;
    shell.run(cmd!(
        "sudo bash -c 'tail /sys/kernel/debug/zswap/*' >> {}",
        out_file
    ))?;
    shell.run(cmd!(
        "(tail /proc/zerosim_guest_offset; echo) >> {}",
        out_file
    ))?;

    // Kernel log
    shell.run(cmd!("echo -e '\ndmesg (Host)\n=====' >> {}", out_file))?;
    shell.run(cmd!("dmesg >> {}", out_file))?;

    // Sync
    shell.run(cmd!("sync"))?;

    Ok(())
}

/// Build bcc tools from source and install them for CentOS
pub fn centos_install_bcc(shell: &SshShell) -> Result<(), spurs::SshError> {
    let enable = "source /opt/rh/llvm-toolset-7/enable";
    let bcc_exists = shell.run(cmd!("test -d bcc"));

    if let Err(bcc_test_err) = bcc_exists {
        // If test returned one, bcc does not exist, and should be built.
        // Any other error is unrecoverable
        if let spurs::SshError::NonZeroExit { cmd: _, exit } = bcc_test_err {
            if exit != 1 {
                return Ok(());
            }
        } else {
            return Err(bcc_test_err);
        }
    } else {
        // If test returned without an error, it exists, so there's nothing to do
        return Ok(());
    }

    // Enable LLVM by default
    shell.run(cmd!(
        "echo 'source /opt/rh/llvm-toolset-7/enable' | \
          sudo tee /etc/profile.d/llvm.sh"
    ))?;

    // Clone bcc
    shell.run(cmd!(
        "git clone -b v0.19.0 https://github.com/iovisor/bcc.git"
    ))?;
    shell.run(cmd!("mkdir bcc/build"))?;
    shell.run(cmd!("{}; cmake3 ..", enable).cwd("bcc/build"))?;
    shell.run(cmd!("{}; make", enable).cwd("bcc/build"))?;
    shell.run(cmd!("{}; sudo make install", enable).cwd("bcc/build"))?;

    Ok(())
}

/// Install jemalloc as the system directory.
pub fn install_jemalloc(shell: &SshShell) -> Result<(), ScailError> {
    // Download jemalloc.
    let user_home = &get_user_home_dir(shell)?;
    download_and_extract(shell, downloads::JEMALLOC, user_home, Some("jemalloc"))?;

    // Build and install.
    with_shell! { shell in &dir!(user_home, "jemalloc") =>
        cmd!("./autogen.sh"),
        cmd!("make -j"),
        cmd!("sudo make install"),
        cmd!("sudo touch /etc/ld.so.preload"),
    }

    // Set as the system allocator.
    shell.run(cmd!(
        "echo \" `jemalloc-config --libdir`/libjemalloc.so.`jemalloc-config --revision` \" \
         | sudo tee -a /etc/ld.so.preload",
    ))?;
    shell.run(cmd!("sudo ldconfig"))?;

    Ok(())
}

/// Install rust in the home directory of the given shell (can be guest or host).
pub fn install_rust(shell: &SshShell) -> Result<(), ScailError> {
    shell.run(
        cmd!(
            "curl https://sh.rustup.rs -sSf | \
             sh -s -- --default-toolchain nightly --no-modify-path -y"
        )
        .use_bash()
        .no_pty(),
    )?;

    Ok(())
}

/// Install SPEC 2017 on the remote host machine. The installed benchmarks are not available to
/// the guest.
///
/// Because SPEC is not free and requires a license, we can't just download it from the internet
/// somewhere. Instead, the user must provide us with a copy to install by pointing us to an ISO
/// on the driver machine somewhere.
pub fn install_spec_2017<A>(
    ushell: &SshShell,
    login: &Login<A>,
    iso_path: &str,
    config_path: &str,
    install_path: &str,
) -> Result<(), ScailError>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    let iso_fname = PathBuf::from(iso_path);
    let iso_fname = if let Some(iso_fname) = iso_fname.file_name().and_then(|f| f.to_str()) {
        iso_fname
    } else {
        return Err(ScailError::new(ScailErrorType::InvalidValueError {
            msg: format!("SPEC ISO is not a file name: {}", iso_path),
        }));
    };

    // Copy the ISO to the remote machine.
    let user_home = &get_user_home_dir(ushell)?;
    rsync_to_remote(login, iso_path, user_home)?;

    // Mount the ISO and execute the install script.
    const TMP_ISO_MOUNT: &str = "/tmp/spec_mnt";
    ushell.run(cmd!("sudo umount {}", TMP_ISO_MOUNT).allow_error())?;
    ushell.run(cmd!("mkdir -p {}", TMP_ISO_MOUNT))?;
    ushell.run(cmd!(
        "sudo mount -o loop {}/{} {}",
        user_home,
        iso_fname,
        TMP_ISO_MOUNT
    ))?;

    // Execute the installation script.
    let spec_dir = dir!(user_home, install_path);
    ushell.run(cmd!("./install.sh -f -d {}", spec_dir).cwd(TMP_ISO_MOUNT))?;

    // Copy the SPEC config to the installation and build the benchmarks.
    //
    // NOTE: this only installs SPEC INT SPEED 2017.
    ushell.run(cmd!("cp {} config/", config_path).cwd(&spec_dir))?;
    ushell.run(
        cmd!(
            "source shrc && runcpu --config={} --fake intspeed",
            config_path
        )
        .cwd(&spec_dir),
    )?;
    ushell.run(
        cmd!(
            "source shrc && runcpu --config={} --fake fpspeed",
            config_path
        )
        .cwd(&spec_dir),
    )?;
    ushell.run(
        cmd!(
            "source shrc && runcpu --config={} --action=build intspeed",
            config_path
        )
        .cwd(&spec_dir),
    )?;
    ushell.run(
        cmd!(
            "source shrc && runcpu --config={} --action=build fpspeed",
            config_path
        )
        .cwd(&spec_dir),
    )?;

    const SPEC_WORKLOADS: &[&str] = &[
        "perlbench_s",
        // FIXME: For gcc alone, the binary name is `sgcc` instead of `gcc_s`?! So we just exclude
        // it. A more thorough script would look at the runcpu log and figure out the appropriate
        // name.
        // "gcc_s",
        "xalancbmk_s",
        "x264_s",
        "deepsjeng_s",
        "leela_s",
        "exchange2_s",
        "xz_s",
        "mcf_s",
        "specrand_is",
        "cactuBSSN_s",
        "lbm_s",
        "omnetpp_s",
    ];

    for bmk in SPEC_WORKLOADS.iter() {
        ushell.run(
            cmd!(
                "cp benchspec/CPU/*{bmk}/build/build_base_markm-thp-m64.0000/{bmk} \
                benchspec/CPU/*{bmk}/run/run_base_refspeed_markm-thp-m64.0000/",
                bmk = bmk,
            )
            .cwd(&spec_dir),
        )?;
    }

    Ok(())
}
