//! Utilities for handling and tagging generated output. See the `Parametrize` trait.

use chrono::offset::Local;
use serde::{Deserialize, Serialize};

pub use runner_proc_macro::*;

/// A timestamp used to make filenames unique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp(pub String);

impl Timestamp {
    /// Returns a timestamp representing the current time.
    pub fn now() -> Self {
        Self(Local::now().format("%Y-%m-%d-%H-%M-%S-%f").to_string())
    }

    #[cfg(test)]
    pub fn test() -> Self {
        Self("2020-04-02-12-01-35-026490000".into())
    }
}

/// A `Parametrize` type manages all things regarding naming and tagging output with settings (i.e.
/// parameters) and properties of its data.
///
/// Each experiment should create a `Parametrize` type at the beginning with all of the settings
/// for the experiment. The derive macro can be used to do this conveniently. The `Parametrize`
/// type can then be used to generate filenames for output files and can generate a string
/// containing all of the settings, which can then be written to a `.param` file.
///
/// The generated filenames will be (probably) unique by including a timestamp (returned by the
/// `timestamp()` method. Fields can also optionally contain any settings marked as `important`,
/// which means that they will be included in the filename for greater visibility.
///
/// # Derive macro
///
/// `Parametrize` can be derived automatically for many types using a custom derive macro. Here is
/// an example usage:
///
/// ```rust,ignore
/// use crate::output::{Parametrize, Timestamp};
///
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize, Parametrize)]
/// struct Config {
///     // This is a setting with type `usize` and name `exp`.
///     exp: usize,
///
///     // The `name` attribute marks this setting as `important`.
///     #[name]
///     workload: YcsbWorkload,
///
///     // `name` can also take a condition: `cores` is only marked as important if it is `> 1`.
///     #[name(self.cores > 1)]
///     cores: usize,
///
///     // The `timestamp` attribute marks this field as the timestamp. It is returned from the
///     // generated `timestamp()` implementation.
///     #[timestamp]
///     timestamp: Timestamp,
/// }
///
/// ```
///
/// Then, to use the struct later, construct it like any other struct:
///
/// ```rust,ignore
/// // In `main` (or wherever):
/// let cfg = Config {
///     exp: 0xFF,
///     workload: YcsbWorkload::A,
///     cores: 32,
///     timestamp: Timestamp::now(),
/// };
///
/// // Run some experiments.
/// run(&cfg)?;
/// ```
///
/// By passing an immutable reference to the `Config` struct, we prevent accidental modification.
/// It also helps if the `run` function doesn't take any other input. This gives greater confidence
/// that the `Parametrize` is actually recording all of the needed parameters.
///
/// See any of the `exp*` modules in the runner for more examples.
pub trait Parametrize: Serialize + Deserialize<'static> {
    /// Generate the primary output and params filenames, in that order.
    fn gen_standard_names(&self) -> (String, String, String, String) {
        const OUTPUT_SUFFIX: &str = "out";
        const PARAMS_SUFFIX: &str = "params";
        const TIMES_SUFFIX: &str = "time";
        const SIM_SUFFIX: &str = "sim";

        (
            self.gen_file_name(OUTPUT_SUFFIX),
            self.gen_file_name(PARAMS_SUFFIX),
            self.gen_file_name(TIMES_SUFFIX),
            self.gen_file_name(SIM_SUFFIX),
        )
    }

    /// Generate a filename with the given extension. Only use this if you want to generate a file
    /// that is not a `.out` or a `.params` file. The parameter `ext` is the extension without the
    /// leading dot (e.g. `err`).
    fn gen_file_name(&self, ext: &str) -> String {
        const MAX_FILENAME_LEN: usize = 200;
        /// Helper to add the given setting to the given string. Used to build file names. The caller
        /// should ensure that the setting is registered.
        fn append_setting(string: &mut String, setting: &str, val: &str) {
            // sanitize
            let val = val
                .trim()
                .replace(" ", "_")
                .replace("\"", "_")
                .replace("\'", "_")
                .replace(",", "_")
                .replace("[", "_")
                .replace("]", "_")
                .replace("}", "_")
                .replace("{", "_")
                .replace(":", "_");

            string.push_str(setting);
            string.push_str(&val);
        }

        let mut base = String::new();

        // prepend all important settings
        for (i, (setting, value)) in self.important().iter().enumerate() {
            if i > 0 {
                base.push_str("-");
            }
            append_setting(&mut base, setting, value);
        }

        // Make sure the filename doesn't get too long
        base.truncate(MAX_FILENAME_LEN);

        // append the date
        base.push_str("-");
        base.push_str(&self.timestamp().0);

        base.push_str(".");
        base.push_str(ext);

        base
    }

    /// Returns a list of important settings and their values, which should be included in
    /// generated file names.
    fn important(&self) -> Vec<(String, String)>;

    /// Returns a timestamp (the same timestamp every time) that is associated with this set of
    /// parameters.
    fn timestamp(&self) -> &Timestamp;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate as runner;

    #[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
    struct Test {
        #[name]
        a: usize,

        #[name]
        b: String,

        #[name]
        c: (usize, String),

        #[name(self.d)]
        d: bool,

        e: (),

        f: Vec<usize>,

        #[timestamp]
        timestamp: Timestamp,
    }

    #[test]
    fn test_output_name() {
        let mut cfg = Test {
            a: 0xAA,
            b: "BB".into(),
            c: (0xCC, "CC".into()),
            d: false,
            e: (),
            f: vec![0xF0, 0xFF],

            timestamp: Timestamp::test(),
        };

        let test_name = cfg.gen_file_name("test");
        assert_eq!(
            test_name,
            "a170-b_BB_-c_204__CC__-2020-04-02-12-01-35-026490000.test"
        );

        cfg.d = true;

        let test_name = cfg.gen_file_name("test");
        assert_eq!(
            test_name,
            "a170-b_BB_-c_204__CC__-dtrue-2020-04-02-12-01-35-026490000.test"
        );
    }
}
