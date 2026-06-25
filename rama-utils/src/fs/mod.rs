//! Filesystem helpers shared by Rama crates.

mod sanitize;
#[doc(inline)]
pub use sanitize::{
    UnsafePathError, is_reserved_device_name, sanitize_path, sanitize_relative_path,
};

use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Create a directory and all missing parents below `root`.
///
/// `path` is treated as relative to `root`; absolute paths, `..` traversal,
/// reserved device names, smuggled prefixes, and symbolic links that resolve
/// outside `root` are rejected. `root` itself must exist.
pub fn safe_create_dir_all_in(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<()> {
    let root = root.as_ref();
    let path = safe_path_in(root, path)?;
    ensure_within_root(root, &path)?;
    fs::create_dir_all(&path)?;
    ensure_within_root(root, &path)
}

/// Write `contents` to a file below `root`, creating missing parent
/// directories.
///
/// `path` is treated as relative to `root`; absolute paths, `..` traversal,
/// reserved device names, smuggled prefixes, and symbolic links that resolve
/// outside `root` are rejected. `root` itself must exist.
pub fn safe_write_in(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> io::Result<()> {
    let root = root.as_ref();
    let path = safe_path_in(root, path)?;

    if let Some(parent) = path.parent() {
        ensure_within_root(root, parent)?;
        fs::create_dir_all(parent)?;
        ensure_within_root(root, parent)?;
    }

    ensure_within_root(root, &path)?;
    fs::write(&path, contents)?;
    ensure_within_root(root, &path)
}

/// Resolve `path` below `root` after applying root-confined path validation.
///
/// `path` is treated as relative to `root`; absolute paths, `..` traversal,
/// reserved device names, smuggled prefixes, and symbolic links that resolve
/// outside `root` are rejected. `root` itself must exist.
pub fn safe_path_in(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    ensure_within_root(root, &path)?;
    Ok(path)
}

fn ensure_within_root(root: &Path, target: &Path) -> io::Result<()> {
    let canonical_root = fs::canonicalize(root)?;
    if let Some(existing) = nearest_existing_ancestor(target) {
        let canonical_target = canonicalize_existing_path(&existing)?;
        if !canonical_target.starts_with(&canonical_root) {
            return Err(UnsafePathError::EscapesRoot.into());
        }
    }
    Ok(())
}

fn canonicalize_existing_path(path: &Path) -> io::Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if fs::symlink_metadata(path).is_ok() {
                return Err(UnsafePathError::EscapesRoot.into());
            }
            Err(err)
        }
        Err(err) => Err(err),
    }
}

fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if fs::symlink_metadata(candidate).is_ok() {
            return Some(candidate.to_path_buf());
        }
        current = candidate.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_write_in_creates_parent_dirs() {
        let root = tempfile::tempdir().unwrap();
        safe_write_in(root.path(), "nested/file.txt", b"hello").unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("nested/file.txt")).unwrap(),
            "hello",
        );
    }

    #[test]
    fn safe_write_in_rejects_traversal() {
        let root = tempfile::tempdir().unwrap();
        let err = safe_write_in(root.path(), "../escape.txt", b"nope").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!root.path().parent().unwrap().join("escape.txt").exists());
    }

    #[test]
    fn safe_create_dir_all_in_rejects_absolute_paths() {
        let root = tempfile::tempdir().unwrap();
        let err = safe_create_dir_all_in(root.path(), "/tmp/escape").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn safe_path_in_resolves_plain_relative_path() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            safe_path_in(root.path(), "nested/file.txt").unwrap(),
            root.path().join("nested/file.txt"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn safe_write_in_rejects_symlink_escape() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let outside = parent.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(outside.join("created.txt"), root.join("link")).unwrap();

        let err = safe_write_in(&root, "link", b"nope").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("created.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn safe_create_dir_all_in_rejects_symlink_escape() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let outside = parent.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let err = safe_create_dir_all_in(&root, "link/nested").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("nested").exists());
    }
}
