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

#[doc(inline)]
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

        _ = file.metadata().unwrap();
    }

    #[test]
    fn test_absolute_dir() {
        static ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/src");

        let entry = ASSETS.get_entry("include_dir/dir.rs").unwrap();
        let file = entry.as_file().unwrap();
        assert!(file.contents_utf8().unwrap().contains("fn get_entry"));

        _ = file.metadata().unwrap();

        let entry = ASSETS.get_entry("macros").unwrap();
        _ = entry.as_dir().unwrap();
    }

    #[test]
    fn test_absolute_with_relative_dir() {
        static ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/../test-files");

        let entry = ASSETS.get_entry("index.html").unwrap();
        let file = entry.as_file().unwrap();

        assert!(file.contents_utf8().unwrap().contains("<b>HTML!</b>"));

        _ = file.metadata().unwrap();
    }

    #[test]
    fn test_extract_rejects_absolute_paths() {
        let malicious_file = File::new("/etc/passwd", b"malicious content");
        let malicious_entry = DirEntry::File(malicious_file);
        let entries = [malicious_entry];
        let malicious_dir = Dir::new("test", &entries);

        let temp_dir = std::env::temp_dir().join("test_extract_absolute");
        let result = malicious_dir.extract(&temp_dir);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_extract_rejects_parent_traversal() {
        let malicious_file = File::new("../../../etc/passwd", b"malicious content");
        let malicious_entry = DirEntry::File(malicious_file);
        let entries = [malicious_entry];
        let malicious_dir = Dir::new("test", &entries);

        let temp_dir = std::env::temp_dir().join("test_extract_traversal");
        let result = malicious_dir.extract(&temp_dir);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_extract_allows_safe_paths() {
        let safe_file = File::new("subdir/safe.txt", b"safe content");
        let safe_entry = DirEntry::File(safe_file);
        let entries = [safe_entry];
        let safe_dir = Dir::new("test", &entries);

        let temp_dir = std::env::temp_dir().join("test_extract_safe");
        let result = safe_dir.extract(&temp_dir);

        if temp_dir.exists() {
            let _ = std::fs::remove_dir_all(&temp_dir);
        }

        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_rejects_mixed_traversal() {
        let malicious_file = File::new("subdir/../../etc/passwd", b"malicious content");
        let malicious_entry = DirEntry::File(malicious_file);
        let entries = [malicious_entry];
        let malicious_dir = Dir::new("test", &entries);

        let temp_dir = std::env::temp_dir().join("test_extract_mixed");
        let result = malicious_dir.extract(&temp_dir);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn test_extract_rejects_symlink_escape() {
        let temp_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path().join("root");
        let outside = temp_dir.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(outside.join("escaped.txt"), root.join("link.txt")).unwrap();

        let malicious_file = File::new("link.txt", b"malicious content");
        let malicious_entry = DirEntry::File(malicious_file);
        let entries = [malicious_entry];
        let malicious_dir = Dir::new("test", &entries);

        let result = malicious_dir.extract(&root);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!outside.join("escaped.txt").exists());
    }
}
