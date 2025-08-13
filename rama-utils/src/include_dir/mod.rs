//! An extension to the `include_str!()` and `include_bytes!()` macro for
//! embedding an entire directory tree into your binary.
//!
//! # Environment Variables
//!
//! You might
//! want to read the [*Environment Variables*][cargo-vars] section of *The
//! Cargo Book* for a list of variables provided by `cargo`.
//!
//! For example you might want to use the `$CARGO_MANIFEST_DIR` or `$OUT_DIR`
//! variables. In specific to include a folder relative to your crate you might
//! use `include_dir!("$CARGO_MANIFEST_DIR/assets")`.
//!
//! By default paths are assumed to be relative to the file where the macro
//! is executed from.
//! # Compile Time Considerations
//!
//! While the `include_dir!()` macro executes relatively quickly, it expands
//! to a fairly large amount of code (all your files are essentially embedded
//! as Rust byte strings) and this may have a flow-on effect on the build
//! process.
//!
//! In particular, including a large number or files or files which are
//! particularly big may cause the compiler to use large amounts of RAM or spend
//! a long time parsing your crate.
//!
//! As one data point, this crate's `target/` directory contained 620 files with
//! a total of 64 MB, with a full build taking about 1.5 seconds and 200MB of
//! RAM to generate a 7MB binary.
//!
//! Using `include_dir!("target/")` increased the compile time to 5 seconds
//! and used 730MB of RAM, generating a 72MB binary.
//!
//! [tracked-env]: https://github.com/rust-lang/rust/issues/74690
//! [track-path]: https://github.com/rust-lang/rust/issues/73921
//! [cargo-vars]: https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates

mod dir;
mod dir_entry;
mod file;
mod metadata;

pub use self::{dir::Dir, dir_entry::DirEntry, file::File, metadata::Metadata};

pub use ::rama_macros::include_dir;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relative_dir() {
        static ASSETS: Dir = include_dir!("../../../test-files");

        let entry = ASSETS.get_entry("index.html").unwrap();
        let file = entry.as_file().unwrap();

        assert!(file.contents_utf8().unwrap().contains("<b>HTML!</b>"));

        let _ = file.metadata().unwrap();
    }

    #[test]
    fn test_absolute_dir() {
        static ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/src");

        let entry = ASSETS.get_entry("include_dir/dir.rs").unwrap();
        let file = entry.as_file().unwrap();
        assert!(file.contents_utf8().unwrap().contains("fn get_entry"));

        let _ = file.metadata().unwrap();

        let entry = ASSETS.get_entry("macros").unwrap();
        let _ = entry.as_dir().unwrap();
    }

    #[test]
    fn test_absolute_with_relative_dir() {
        static ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/../test-files");

        let entry = ASSETS.get_entry("index.html").unwrap();
        let file = entry.as_file().unwrap();

        assert!(file.contents_utf8().unwrap().contains("<b>HTML!</b>"));

        let _ = file.metadata().unwrap();
    }
}
