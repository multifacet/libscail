//! Utilities for downloading stuff.
use spurs::{cmd, Execute, SshShell};

use crate::ScailError;

/// Represents a possible artifact that can be downloaded.
#[derive(Debug, Clone)]
pub struct Download<'s> {
    /// The URL of the artifact, from which it can be downloaded.
    pub url: &'s str,
    /// The name of the downloaded artifact.
    pub name: &'s str,
}

pub const VAGRANT: Download = Download {
    url: "https://releases.hashicorp.com/vagrant/2.2.14/vagrant_2.2.14_x86_64.rpm",
    name: "vagrant_2.2.14_x86_64.rpm",
};
pub const QEMU: Download = Download {
    url: "https://download.qemu.org/qemu-4.0.0.tar.xz",
    name: "qemu-4.0.0.tar.xz",
};
pub const MAVEN: Download = Download {
    url: "https://downloads.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz",
    name: "apache-maven-3.6.3-bin.tar.gz",
};
pub const PIN: Download = Download {
    url: "https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz",
    name: "pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz",
};
pub const KYOTO_CABINET_CORE: Download = Download {
    url: "https://dbmx.net/kyotocabinet/pkg/kyotocabinet-1.2.77.tar.gz",
    name: "kyotocabinet-1.2.77.tar.gz",
};
pub const KYOTO_CABINET_JAVA: Download = Download {
    url: "https://dbmx.net/kyotocabinet/javapkg/kyotocabinet-java-1.24.tar.gz",
    name: "kyotocabinet-java-1.24.tar.gz",
};
pub const PARSEC: Download = Download {
    url: "https://parsec.cs.princeton.edu/download/3.0/parsec-3.0.tar.gz",
    name: "parsec-3.0.tar.gz",
};
pub const JEMALLOC: Download = Download {
    url: "https://github.com/jemalloc/jemalloc/archive/refs/tags/5.2.1.tar.gz",
    name: "5.2.1.tar.gz",
};

/// Use `shell` to download the artifact to the directory `to` only if the tarball doesn't already
/// exist. Then, rename the tarball to `name` if any name is given. Returns the `Download` with
/// artifact info, including the original name of the download.
pub fn download(
    shell: &SshShell,
    info: &Download,
    to: &str,
    name: Option<&str>,
) -> Result<(), ScailError> {
    // Some websites reject non-browsers, so pretend to be Google Chrome.
    const USER_AGENT: &str = r#"--user-agent="Mozilla/5.0 \
                             (X11; Ubuntu; Linux x86_64; rv:92.0) \
                             Gecko/20100101 Firefox/92.0""#;
    let name = name.unwrap_or(info.name);

    // Check if the file exists and then maybe download.
    shell.run(
        cmd!(
            "[ -e {} ] || wget {} -O {} {}",
            name,
            USER_AGENT,
            name,
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
    name: Option<&str>,
) -> Result<(), ScailError> {
    // Download, keep the original name.
    download(shell, &info, to, None)?;

    if let Some(name) = name {
        shell.run(cmd!("mkdir -p {}", name).cwd(to))?;
        shell.run(cmd!("tar -C {} --strip-components=1 -xvf {}", name, info.name).cwd(to))?;
    } else {
        shell.run(cmd!("tar -xvf {}", info.name).cwd(to))?;
    }

    Ok(())
}
