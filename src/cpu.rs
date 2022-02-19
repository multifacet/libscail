//! Utilities for working with different processors.

use spurs::{cmd, Execute, SshShell};

/// Intel (server and desktop) processors use `0x6` as the family number for `cpuid`.
pub const INTEL_FAMILY_NUMBER: usize = 0x6;

/// Processors.
///
/// Feel free to add more.
#[non_exhaustive]
pub enum Processor {
    Intel(IntelX86Model),
}

/// Intel processor model numbers (corresponding with `cpuid`).
///
/// This is not comprehensive. Feel free to add more.
///
/// See https://en.wikichip.org/wiki/intel/cpuid
#[non_exhaustive]
pub enum IntelX86Model {
    // Server microarchitectures
    SandyBridgeServer,
    IvyBridgeServer,
    HaswellServer,
    BroadwellServer,
    /// Also, Cascade Lake, Cooper Lake
    SkyLakeServer,
    IceLakeServer,

    // Consumer microarchitectures
    SandyBridgeConsumer,
    IvyBridgeConsumer,
    HaswellConsumer,
    BroadwellConsumer,
    SkyLakeConsumer,
    KabyLakeConsumer,
}

pub fn cpu_family_number(ushell: &SshShell) -> Result<usize, failure::Error> {
    Ok(ushell
        .run(cmd!(r#"lscpu | grep 'CPU family' | awk '{{print $3}}'"#))?
        .stdout
        .trim()
        .parse::<usize>()?)
}

pub fn cpu_model_number(ushell: &SshShell) -> Result<usize, failure::Error> {
    Ok(ushell
        .run(cmd!(r#"lscpu | grep 'Model:' | awk '{{print $2}}'"#))?
        .stdout
        .trim()
        .parse::<usize>()?)
}

pub fn cpu_family_model(ushell: &SshShell) -> Result<Processor, failure::Error> {
    use IntelX86Model::*;

    let family = cpu_family_number(ushell)?;
    let model = cpu_model_number(ushell)?;

    Ok(match (family, model) {
        (0x6, model) => Processor::Intel(match model {
            45 => SandyBridgeServer,
            62 => IvyBridgeServer,
            63 => HaswellServer,
            85 => SkyLakeServer,
            0x4F | 0x56 => BroadwellServer,
            0x6A | 0x6C => IceLakeServer,

            0x2A => SandyBridgeConsumer,
            0x3A => IvyBridgeConsumer,
            0x46 | 0x45 | 0x3C => HaswellConsumer,
            0x47 | 0x3D => BroadwellConsumer,
            0x4E | 0x5E => SkyLakeConsumer,
            0x9E | 0x8E => KabyLakeConsumer,

            _ => {
                failure::bail!("Unknown processor: family={} model={}", family, model);
            }
        }),

        (family, model) => {
            failure::bail!("Unknown processor: family={} model={}", family, model);
        }
    })
}

/// On Broadwell or older, the `*.walk_duration` perf counters are used to measure the amount of
/// cycles spent in page walks. On processors after Broadwell, the name of the counter is
/// `*.walk_active`.
///
/// This function checks which it is and returns either `Ok("walk_duration")` or
/// `Ok("walk_active")`.
pub fn page_walk_perf_counter_suffix(shell: &SshShell) -> Result<String, failure::Error> {
    let output = shell
        .run(cmd!(
            "(sudo perf list | grep -o walk_active > /tmp/x && cat /tmp/x | uniq) || echo walk_duration"
        ))?
        .stdout;

    Ok(output.trim().to_owned())
}
