//! Filesystem helpers that guard against path-traversal attacks.
//!
//! Opening files whose path is influenced by untrusted input (an HTTP request
//! target, a query parameter, a header value, ...) is a classic source of
//! path-traversal vulnerabilities: a request for `../../etc/passwd` escapes the
//! directory the application meant to expose.
//!
//! This module provides drop-in replacements for [`tokio::fs::File::open`] and
//! [`tokio::fs::OpenOptions`] that reject such paths:
//!
//! - [`safe_open`] opens a file read-only after rejecting `..` traversal,
//!   reserved device names and smuggled path prefixes. Use it when the *base*
//!   of the path is trusted but parts of it may be attacker-controlled.
//! - [`safe_open_in`] / [`OpenOptions::jail`] additionally confine the opened
//!   file to a trusted root directory: absolute paths are rejected and symbolic
//!   links are resolved so they cannot point outside the root.
//!
//! The underlying lexical check is exposed as [`sanitize_path`] for callers
//! that want to validate a path without opening it.
//!
//! # Security
//!
//! On Unix platforms, jailed opens use file descriptor-based operations
//! (`openat` with `O_NOFOLLOW`) to prevent TOCTOU (time-of-check-time-of-use)
//! race conditions. Each path component is opened relative to the previous
//! directory descriptor, ensuring that symlink swaps or directory replacements
//! between validation and access cannot escape the jail.
//!
//! On non-Unix platforms, the implementation falls back to path-based validation,
//! which remains vulnerable to TOCTOU races if an attacker can modify the
//! filesystem concurrently.
//!
//! # Examples
//!
//! Reject traversal while serving from a fixed directory:
//!
//! ```
//! # async fn docs() {
//! use rama_core::fs;
//!
//! // Whatever the request asks for, nothing outside `./public` is reachable.
//! assert!(fs::safe_open_in("./public", "../../etc/passwd").await.is_err());
//! # }
//! ```
//!
//! Open a (possibly absolute) trusted path while still rejecting `..`:
//!
//! ```
//! # async fn docs() {
//! use rama_core::fs;
//!
//! assert!(fs::safe_open("/srv/data/report.bin").await.is_err()); // missing file -> NotFound
//! assert!(fs::safe_open("/srv/../etc/passwd").await.is_err()); // traversal -> InvalidInput
//! # }
//! ```

mod sanitize;
#[doc(inline)]
pub use sanitize::{
    UnsafePathError, is_reserved_device_name, sanitize_path, sanitize_relative_path,
};

use std::io;
use std::path::{Path, PathBuf};
use tokio::fs::File;

#[cfg(unix)]
use std::os::unix::io::{AsFd, AsRawFd, FromRawFd, IntoRawFd};
#[cfg(unix)]
use rustix::fs::{openat, Mode, OFlags};

/// How symbolic links are treated when opening a file confined to a root
/// directory via [`OpenOptions::jail`].
///
/// Symlink handling only applies when a jail root is set; without one there is
/// no boundary to confine to.
///
/// # Security Note (Unix platforms)
///
/// On Unix platforms, when using file descriptor-based opening (which is automatic
/// for jailed opens), symlinks in intermediate path components are never followed
/// to prevent TOCTOU races. This policy only affects the final path component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SymlinkPolicy {
    /// Symlinks in the final path component are not followed. This prevents
    /// TOCTOU races where a symlink could be swapped to point outside the jail
    /// between validation and access. This is the most secure option and is the
    /// default.
    ///
    /// Note: On Unix with descriptor-based opening, this is implemented using
    /// `O_NOFOLLOW`, which means attempting to open a symlink will fail with
    /// `ELOOP`. On other platforms or for non-jailed opens, symlinks are followed
    /// and then validated, which may be vulnerable to TOCTOU races.
    #[default]
    RestrictToRoot,
    /// Symlinks in the final path component are followed, even if they resolve
    /// outside the jail root. The lexical confinement (no `..`, no absolute paths
    /// in the requested path) still applies, but the resolved target is not checked
    /// against the root. Opt in only when the linked targets are trusted.
    ///
    /// Note: This allows symlinks to escape the jail, including absolute symlinks.
    /// Use with caution.
    Allow,
}

/// Open `path` read-only with path-traversal protection.
///
/// Equivalent to `OpenOptions::new().read(true).open(path)`. Rejects `..`
/// traversal, reserved device names and smuggled path prefixes (see
/// [`sanitize_path`]). Absolute paths are permitted; use [`safe_open_in`] to
/// confine the path to a trusted root directory instead.
///
/// Path rejection surfaces as [`io::ErrorKind::InvalidInput`].
pub async fn safe_open(path: impl AsRef<Path>) -> io::Result<File> {
    OpenOptions::new().read(true).open(path).await
}

/// Open a file read-only, confined to within the trusted directory `root`.
///
/// `path` is treated as relative to `root`; absolute paths, `..` traversal,
/// reserved device names, smuggled prefixes, and symbolic links that resolve
/// outside `root` are all rejected. `root` itself must exist.
///
/// Equivalent to `OpenOptions::new().read(true).jail(root).open(path)`.
pub async fn safe_open_in(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .jail(root.as_ref())
        .open(path)
        .await
}

/// Options to open a file with path-traversal protection.
///
/// Mirrors the access-mode setters of [`tokio::fs::OpenOptions`]
/// (read/write/append/truncate/create/create_new) and adds
/// [`jail`](Self::jail) to confine every opened path to a trusted root
/// directory.
///
/// Lexical traversal protection (rejecting `..`, reserved device names and
/// smuggled prefixes) is *always* applied. [`jail`](Self::jail) additionally
/// rejects absolute paths and resolves symlinks against the root so they cannot
/// escape it.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    jail: Option<PathBuf>,
    symlinks: SymlinkPolicy,
}

impl OpenOptions {
    /// Create a new set of options with every flag disabled, matching
    /// [`tokio::fs::OpenOptions::new`]. Enable at least one access mode (e.g.
    /// [`read`](Self::read)) before calling [`open`](Self::open).
    #[must_use]
    pub fn new() -> Self {
        Self {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            jail: None,
            symlinks: SymlinkPolicy::RestrictToRoot,
        }
    }

    /// Set the option for read access.
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    /// Set the option for write access.
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    /// Set the option for append mode.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }

    /// Set the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    /// Set the option to create a new file, or open it if it already exists.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    /// Set the option to create a new file, failing if it already exists.
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    /// Confine every opened path to within `root`.
    ///
    /// The path passed to [`open`](Self::open) is then interpreted as relative
    /// to `root`; absolute paths are rejected, and the resolved path (with
    /// symlinks followed) must remain within `root` or the open fails with
    /// [`UnsafePathError::EscapesRoot`]. `root` must exist when opening.
    ///
    /// # Security
    ///
    /// On Unix platforms, this uses file descriptor-based operations to prevent
    /// TOCTOU (time-of-check-time-of-use) race conditions. The implementation
    /// opens the root directory and traverses path components using `openat`,
    /// ensuring that concurrent filesystem modifications cannot cause the final
    /// open to escape the jail.
    ///
    /// On non-Unix platforms, the implementation uses path-based validation which
    /// may be vulnerable to TOCTOU races if an attacker can modify the filesystem
    /// concurrently.
    pub fn jail(&mut self, root: impl Into<PathBuf>) -> &mut Self {
        self.jail = Some(root.into());
        self
    }

    /// Set how symbolic links are treated within the [`jail`](Self::jail) root.
    ///
    /// Defaults to [`SymlinkPolicy::RestrictToRoot`]. Has no effect unless a
    /// jail root is configured.
    pub fn symlinks(&mut self, policy: SymlinkPolicy) -> &mut Self {
        self.symlinks = policy;
        self
    }

    /// Open the file at `path` with the configured options, after validating it
    /// against path-traversal attacks.
    pub async fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        let path = path.as_ref();
        
        // When a jail is configured, use secure descriptor-based opening on Unix
        // to prevent TOCTOU races. On other platforms, fall back to the original
        // validation approach (which remains vulnerable but is the best we can do
        // without platform-specific APIs).
        #[cfg(unix)]
        if self.jail.is_some() {
            return self.open_jailed_unix(path).await;
        }
        
        // Non-jailed or non-Unix: use the original path-based approach
        let resolved_path = self.resolve(path).await?;
        self.tokio_options().open(resolved_path).await
    }

    #[cfg(unix)]
    async fn open_jailed_unix(&self, path: &Path) -> io::Result<File> {
        let root = self.jail.as_ref().expect("jail must be set");
        
        // Validate the path lexically first
        let relative = sanitize_relative_path(path)?;
        
        // Open the root directory to get a stable file descriptor
        let root_fd = tokio::task::spawn_blocking({
            let root = root.clone();
            move || -> io::Result<std::fs::File> {
                let fd = rustix::fs::open(
                    &root,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                Ok(unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) })
            }
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
        
        // Now perform component-by-component traversal using openat
        let file = tokio::task::spawn_blocking({
            let relative = relative.clone();
            let read = self.read;
            let write = self.write;
            let append = self.append;
            let truncate = self.truncate;
            let create = self.create;
            let create_new = self.create_new;
            let symlinks = self.symlinks;
            
            move || -> io::Result<std::fs::File> {
                open_relative_to_fd(
                    &root_fd,
                    &relative,
                    read,
                    write,
                    append,
                    truncate,
                    create,
                    create_new,
                    symlinks,
                )
            }
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
        
        // Convert std::fs::File to tokio::fs::File
        Ok(File::from_std(file))
    }

    fn tokio_options(&self) -> tokio::fs::OpenOptions {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.read(self.read)
            .write(self.write)
            .append(self.append)
            .truncate(self.truncate)
            .create(self.create)
            .create_new(self.create_new);
        opts
    }

    /// Validate `path` and produce the concrete filesystem path to open.
    /// 
    /// Note: This method is only used for non-jailed opens or on non-Unix platforms.
    /// On Unix with a jail configured, we use descriptor-based opening instead.
    async fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        match &self.jail {
            None => Ok(sanitize_path(path)?),
            Some(root) => {
                let relative = sanitize_relative_path(path)?;
                let full = root.join(relative);
                if self.symlinks == SymlinkPolicy::RestrictToRoot {
                    ensure_within_root(root, &full).await?;
                }
                Ok(full)
            }
        }
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
/// Open a file relative to a directory file descriptor, traversing components
/// one at a time to prevent TOCTOU races.
///
/// This function implements secure file opening by:
/// 1. Opening each directory component with O_NOFOLLOW to prevent symlink races
/// 2. Using openat() relative to the previous directory descriptor
/// 3. Never performing pathname-based resolution after validation
///
/// This ensures that even if an attacker can modify the filesystem concurrently,
/// they cannot cause the final open to escape the jail by swapping directories
/// for symlinks or renaming paths between validation and access.
fn open_relative_to_fd(
    root_fd: &std::fs::File,
    path: &Path,
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    symlinks: SymlinkPolicy,
) -> io::Result<std::fs::File> {
    let components: Vec<_> = path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty path after normalization",
        ));
    }
    
    // Build the open flags
    let mut flags = OFlags::CLOEXEC;
    
    if read && write {
        flags |= OFlags::RDWR;
    } else if write {
        flags |= OFlags::WRONLY;
    } else {
        flags |= OFlags::RDONLY;
    }
    
    if append {
        flags |= OFlags::APPEND;
    }
    if truncate {
        flags |= OFlags::TRUNC;
    }
    if create_new {
        flags |= OFlags::CREATE | OFlags::EXCL;
    } else if create {
        flags |= OFlags::CREATE;
    }
    
    // For the final component:
    // - If RestrictToRoot: Don't follow symlinks at the final component to prevent
    //   TOCTOU races. This is more restrictive than the original behavior but necessary
    //   for security. Symlinks in intermediate directories are never followed.
    // - If Allow: Follow symlinks even if they escape (lexical checks still apply)
    let final_flags = if symlinks == SymlinkPolicy::RestrictToRoot {
        flags | OFlags::NOFOLLOW
    } else {
        flags
    };
    
    let mode = Mode::from_bits_truncate(0o666);
    
    // Traverse components one by one
    let mut current_fd: std::fs::File = {
        let fd = root_fd.as_raw_fd();
        // SAFETY: We're duplicating the fd to avoid ownership issues
        unsafe { std::fs::File::from_raw_fd(libc::dup(fd)) }
    };
    
    for (i, component) in components.iter().enumerate() {
        let is_last = i == components.len() - 1;
        
        if is_last {
            // Open the final component with the requested flags
            let fd = openat(
                current_fd.as_fd(),
                component,
                final_flags,
                mode,
            )?;
            return Ok(unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) });
        } else {
            // Open intermediate directory with O_NOFOLLOW to prevent symlink races
            let fd = openat(
                current_fd.as_fd(),
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            current_fd = unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) };
        }
    }
    
    unreachable!("loop should have returned in final iteration")
}

/// Verify, by canonicalizing, that `target` resolves to a location within
/// `root`. This defends against symbolic links that point outside the jail.
///
/// Only the portion of `target` that already exists is canonicalized; the
/// lexical sanitization already guarantees the not-yet-existing tail contains
/// no `..` components.
async fn ensure_within_root(root: &Path, target: &Path) -> io::Result<()> {
    let canonical_root = tokio::fs::canonicalize(root).await?;
    if let Some(existing) = nearest_existing_ancestor(target).await {
        let canonical_target = canonicalize_existing_path(&existing).await?;
        if !canonical_target.starts_with(&canonical_root) {
            return Err(UnsafePathError::EscapesRoot.into());
        }
    }
    Ok(())
}

async fn canonicalize_existing_path(path: &Path) -> io::Result<PathBuf> {
    match tokio::fs::canonicalize(path).await {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if tokio::fs::symlink_metadata(path).await.is_ok() {
                return Err(UnsafePathError::EscapesRoot.into());
            }
            Err(err)
        }
        Err(err) => Err(err),
    }
}

/// Walk up from `path` until an existing path is found, returning it.
async fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if tokio::fs::symlink_metadata(candidate).await.is_ok() {
            return Some(candidate.to_path_buf());
        }
        current = candidate.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn read_to_string(mut file: File) -> String {
        let mut buf = String::new();
        file.read_to_string(&mut buf).await.unwrap();
        buf
    }

    fn err_kind(result: io::Result<File>) -> io::ErrorKind {
        result.expect_err("expected error").kind()
    }

    #[tokio::test]
    async fn safe_open_reads_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        tokio::fs::write(&path, b"hello world").await.unwrap();

        let file = safe_open(&path).await.unwrap();
        assert_eq!(read_to_string(file).await, "hello world");
    }

    #[tokio::test]
    async fn safe_open_rejects_parent_dir_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/../secret.txt");
        // The file would exist after lexical resolution, but `..` is refused
        // before we ever touch the filesystem.
        assert_eq!(
            err_kind(safe_open(&path).await),
            io::ErrorKind::InvalidInput,
        );
    }

    #[tokio::test]
    async fn safe_open_missing_file_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.txt");
        assert_eq!(err_kind(safe_open(&path).await), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn safe_open_in_serves_files_within_root() {
        let root = tempfile::tempdir().unwrap();
        tokio::fs::create_dir(root.path().join("assets"))
            .await
            .unwrap();
        tokio::fs::write(root.path().join("assets/app.js"), b"console.log(1)")
            .await
            .unwrap();

        let file = safe_open_in(root.path(), "assets/app.js").await.unwrap();
        assert_eq!(read_to_string(file).await, "console.log(1)");

        // A leading slash is interpreted relative to the root, not the FS root.
        let file = safe_open_in(root.path(), "/assets/app.js").await;
        assert_eq!(err_kind(file), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn safe_open_in_rejects_traversal_out_of_root() {
        let parent = tempfile::tempdir().unwrap();
        tokio::fs::write(parent.path().join("secret.txt"), b"top secret")
            .await
            .unwrap();
        let root = parent.path().join("public");
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::write(root.join("index.html"), b"<h1>hi</h1>")
            .await
            .unwrap();

        // Sanity: the legitimate file is reachable.
        safe_open_in(&root, "index.html").await.unwrap();

        for payload in ["../secret.txt", "../../etc/passwd", "..\\secret.txt"] {
            let result = safe_open_in(&root, payload).await;
            assert!(
                result.is_err(),
                "expected `{payload}` to be rejected, got Ok",
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn safe_open_in_rejects_symlink_escaping_root() {
        let parent = tempfile::tempdir().unwrap();
        tokio::fs::write(parent.path().join("secret.txt"), b"top secret")
            .await
            .unwrap();
        let root = parent.path().join("public");
        tokio::fs::create_dir(&root).await.unwrap();

        // A symlink living *inside* the root but pointing outside of it.
        std::os::unix::fs::symlink(parent.path().join("secret.txt"), root.join("escape")).unwrap();

        let result = safe_open_in(&root, "escape").await;
        // With the new descriptor-based implementation, this fails because
        // O_NOFOLLOW is used for the final component with RestrictToRoot policy.
        // The error kind may be ELOOP (too many levels of symbolic links) which
        // maps to InvalidInput or other error kinds depending on the platform.
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn safe_open_in_allows_symlink_within_root_with_allow_policy() {
        let root = tempfile::tempdir().unwrap();
        tokio::fs::write(root.path().join("real.txt"), b"data")
            .await
            .unwrap();
        std::os::unix::fs::symlink(root.path().join("real.txt"), root.path().join("link")).unwrap();

        // With RestrictToRoot (default), symlinks at the final component are not followed
        // for security (prevents TOCTOU races).
        let result = safe_open_in(root.path(), "link").await;
        assert!(result.is_err());

        // With Allow policy, symlinks are followed.
        let file = OpenOptions::new()
            .read(true)
            .jail(root.path())
            .symlinks(SymlinkPolicy::Allow)
            .open("link")
            .await
            .unwrap();
        assert_eq!(read_to_string(file).await, "data");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn jail_create_rejects_dangling_symlink_escape() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("public");
        let outside = parent.path().join("outside");
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::create_dir(&outside).await.unwrap();

        let outside_target = outside.join("created.txt");
        std::os::unix::fs::symlink(&outside_target, root.join("upload.txt")).unwrap();

        let result = OpenOptions::new()
            .write(true)
            .create(true)
            .jail(&root)
            .open("upload.txt")
            .await;

        // With O_NOFOLLOW, attempting to open a symlink fails.
        // The file outside the jail should not be created.
        assert!(result.is_err());
        assert!(!outside_target.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn jail_allow_symlinks_follows_escaping_link_but_keeps_lexical_guard() {
        let parent = tempfile::tempdir().unwrap();
        tokio::fs::write(parent.path().join("secret.txt"), b"top secret")
            .await
            .unwrap();
        let root = parent.path().join("public");
        tokio::fs::create_dir(&root).await.unwrap();
        std::os::unix::fs::symlink(parent.path().join("secret.txt"), root.join("escape")).unwrap();

        // Default policy rejects the escaping symlink (O_NOFOLLOW prevents following it).
        assert!(safe_open_in(&root, "escape").await.is_err());

        // Opting in to allow symlinks follows it.
        let file = OpenOptions::new()
            .read(true)
            .jail(&root)
            .symlinks(SymlinkPolicy::Allow)
            .open("escape")
            .await
            .unwrap();
        assert_eq!(read_to_string(file).await, "top secret");

        // Lexical confinement (no `..`) still applies even when symlinks escape.
        let traversal = OpenOptions::new()
            .read(true)
            .jail(&root)
            .symlinks(SymlinkPolicy::Allow)
            .open("../secret.txt")
            .await;
        assert_eq!(err_kind(traversal), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn open_options_can_create_within_jail() {
        let root = tempfile::tempdir().unwrap();
        OpenOptions::new()
            .write(true)
            .create(true)
            .jail(root.path())
            .open("nested/created.txt")
            .await
            .expect_err("parent dir does not exist yet");

        tokio::fs::create_dir(root.path().join("nested"))
            .await
            .unwrap();
        let _file = OpenOptions::new()
            .write(true)
            .create(true)
            .jail(root.path())
            .open("nested/created.txt")
            .await
            .unwrap();
        assert!(root.path().join("nested/created.txt").exists());
    }
}
