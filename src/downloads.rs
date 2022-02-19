//! Utilities for downloading stuff.
use spurs::{cmd, Execute, SshShell};

/// Represents a possible artifact that can be downloaded.
#[derive(Debug, Clone)]
pub struct Download<'s> {
    /// The URL of the artifact, from which it can be downloaded.
    pub url: &'s str,
    /// The name of the downloaded artifact.
    pub name: &'s str,
}

/// Use `shell` to download the artifact to the directory `to` only if the tarball doesn't already
/// exist. Then, rename the tarball to `name` if any name is given. Returns the `Download` with
/// artifact info, including the original name of the download.
pub fn download(shell: &SshShell, info: &Download, to: &str) -> Result<(), failure::Error> {
    // Some websites reject non-browsers, so pretend to be Google Chrome.
    const USER_AGENT: &str = r#"--user-agent="Mozilla/5.0 \
                             (X11; Ubuntu; Linux x86_64; rv:92.0) \
                             Gecko/20100101 Firefox/92.0""#;

    // Check if the file exists and then maybe download.
    shell.run(
        cmd!(
            "[ -e {} ] || wget {} -O {} {}",
            info.name,
            USER_AGENT,
            info.name,
            info.url
        )
        .cwd(to),
    )?;

    Ok(())
}

/// Use `shell` to download the artifact to the directory `to` only if the tarball doesn't already
/// exist. Then, extract the artifact to a directory.
pub fn download_and_extract(
    shell: &SshShell,
    info: Download,
    to: &str,
) -> Result<(), failure::Error> {
    // Download, keep the original name.
    download(shell, &info, to)?;

    shell.run(cmd!("tar -xvf {}", info.name).cwd(to))?;

    Ok(())
}
