//! Filesystem helpers shared by Rama crates.
//!
//! Async helpers are the default. Use the `_sync` variants from blocking code.
//!
//! These helpers are implemented with `std`/`tokio` path APIs. They reject
//! lexical traversal and static symlink escapes, but they cannot make path-based
//! checks race-free if an attacker can concurrently mutate the checked directory.
//! Use them with roots that are not writable by untrusted actors.

mod sanitize;
#[doc(inline)]
pub use sanitize::{
    UnsafePathError, is_reserved_device_name, sanitize_path, sanitize_relative_path,
};

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use tokio::fs::File;

/// How symbolic links are treated when opening a file confined to a root
/// directory via [`OpenOptions::jail`] or [`OpenOptionsSync::jail`].
///
/// Symlink handling only applies when a jail root is set; without one there is
/// no boundary to confine to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SymlinkPolicy {
    /// Symlinks may be followed, but the fully resolved path must stay within
    /// the jail root. A symlink that resolves outside the root is rejected with
    /// [`UnsafePathError::EscapesRoot`]. This is the default.
    #[default]
    RestrictToRoot,
    /// Symlinks are followed even when they resolve outside the jail root. The
    /// lexical confinement (no `..`, no absolute paths) still applies, but the
    /// resolved target is not checked against the root. Opt in only when the
    /// linked targets are trusted.
    Allow,
}

/// Permissions to apply when [`OpenOptions`] or [`OpenOptionsSync`] creates a
/// new file.
///
/// These permissions only affect newly-created files. Existing files keep their
/// current permissions, matching the behavior of platform open options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CreatedFilePermissions {
    /// Use platform defaults.
    #[default]
    Default,
    /// Create private files intended for secrets or sensitive diagnostics.
    ///
    /// On Unix this creates files with mode `0o600` before the process umask is
    /// applied. On other platforms the file inherits the platform default ACLs.
    OwnerReadWrite,
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

/// Blocking variant of [`safe_open`].
pub fn safe_open_sync(path: impl AsRef<Path>) -> io::Result<fs::File> {
    OpenOptionsSync::new().read(true).open(path)
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

/// Blocking variant of [`safe_open_in`].
pub fn safe_open_in_sync(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<fs::File> {
    OpenOptionsSync::new()
        .read(true)
        .jail(root.as_ref())
        .open(path)
}

/// Resolve `path` below `root` after applying root-confined path validation.
///
/// `path` is treated as relative to `root`; absolute paths, `..` traversal,
/// reserved device names, smuggled prefixes, and symbolic links that resolve
/// outside `root` are rejected. `root` itself must exist.
///
/// The returned [`PathBuf`] is not a capability: if the directory tree is
/// modified after this function returns, callers must validate again or perform
/// the filesystem operation through a safe helper.
pub async fn safe_path_in(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    ensure_within_root(root, &path).await?;
    Ok(path)
}

/// Blocking variant of [`safe_path_in`].
pub fn safe_path_in_sync(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    ensure_within_root_sync(root, &path)?;
    Ok(path)
}

/// Create a directory and all missing parents below `root`.
///
/// `path` is treated as relative to `root`; absolute paths, `..` traversal,
/// reserved device names, smuggled prefixes, and symbolic links that resolve
/// outside `root` are rejected. `root` itself must exist.
pub async fn safe_create_dir_all_in(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<()> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    ensure_within_root(root, &path).await?;
    tokio::fs::create_dir_all(&path).await?;
    ensure_within_root(root, &path).await
}

/// Blocking variant of [`safe_create_dir_all_in`].
pub fn safe_create_dir_all_in_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<()> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    ensure_within_root_sync(root, &path)?;
    fs::create_dir_all(&path)?;
    ensure_within_root_sync(root, &path)
}

/// Write `contents` to a file below `root`, creating missing parent
/// directories.
///
/// `path` is treated as relative to `root`; absolute paths, `..` traversal,
/// reserved device names, smuggled prefixes, and symbolic links that resolve
/// outside `root` are rejected. `root` itself must exist.
pub async fn safe_write_in(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> io::Result<()> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let contents = contents.as_ref().to_owned();

    if let Some(parent) = path.parent() {
        ensure_within_root(root, parent).await?;
        tokio::fs::create_dir_all(parent).await?;
        ensure_within_root(root, parent).await?;
    }

    ensure_within_root(root, &path).await?;
    tokio::fs::write(&path, contents).await?;
    ensure_within_root(root, &path).await
}

/// Blocking variant of [`safe_write_in`].
pub fn safe_write_in_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> io::Result<()> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);

    if let Some(parent) = path.parent() {
        ensure_within_root_sync(root, parent)?;
        fs::create_dir_all(parent)?;
        ensure_within_root_sync(root, parent)?;
    }

    ensure_within_root_sync(root, &path)?;
    fs::write(&path, contents)?;
    ensure_within_root_sync(root, &path)
}

/// Options to open a file with async path-traversal protection.
///
/// Mirrors the access-mode setters of [`tokio::fs::OpenOptions`]
/// (read/write/append/truncate/create/create_new) and adds
/// [`jail`](Self::jail) to confine every opened path to a trusted root
/// directory.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    inner: OpenOptionsInner,
}

impl OpenOptions {
    /// Create a new set of options with every flag disabled, matching
    /// [`tokio::fs::OpenOptions::new`]. Enable at least one access mode (e.g.
    /// [`read`](Self::read)) before calling [`open`](Self::open).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OpenOptionsInner::new(),
        }
    }

    /// Set the option for read access.
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.inner.read = read;
        self
    }

    /// Set the option for write access.
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.inner.write = write;
        self
    }

    /// Set the option for append mode.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.inner.append = append;
        self
    }

    /// Set the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.inner.truncate = truncate;
        self
    }

    /// Set the option to create a new file, or open it if it already exists.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.inner.create = create;
        self
    }

    /// Set the option to create a new file, failing if it already exists.
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.inner.create_new = create_new;
        self
    }

    /// Confine every opened path to within `root`.
    ///
    /// The path passed to [`open`](Self::open) is then interpreted as relative
    /// to `root`; absolute paths are rejected, and the resolved path must remain
    /// within `root` or the open fails with [`UnsafePathError::EscapesRoot`].
    /// `root` must exist when opening.
    pub fn jail(&mut self, root: impl Into<PathBuf>) -> &mut Self {
        self.inner.jail = Some(root.into());
        self
    }

    /// Set how symbolic links are treated within the [`jail`](Self::jail) root.
    ///
    /// Defaults to [`SymlinkPolicy::RestrictToRoot`]. Has no effect unless a
    /// jail root is configured.
    pub fn symlinks(&mut self, policy: SymlinkPolicy) -> &mut Self {
        self.inner.symlinks = policy;
        self
    }

    /// Set permissions used when this open operation creates a new file.
    pub fn created_file_permissions(&mut self, permissions: CreatedFilePermissions) -> &mut Self {
        self.inner.created_file_permissions = permissions;
        self
    }

    /// Open the file at `path` with the configured options, after validating it
    /// against path-traversal attacks.
    pub async fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        let path = self.inner.resolve(path.as_ref()).await?;
        let file = self.inner.tokio_options().open(&path).await?;
        if let Some(root) = &self.inner.jail
            && self.inner.symlinks == SymlinkPolicy::RestrictToRoot
        {
            ensure_within_root(root, &path).await?;
        }
        Ok(file)
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Options to open a file with blocking path-traversal protection.
///
/// This is the sync counterpart to [`OpenOptions`].
#[derive(Debug, Clone)]
pub struct OpenOptionsSync {
    inner: OpenOptionsInner,
}

impl OpenOptionsSync {
    /// Create a new set of options with every flag disabled, matching
    /// [`std::fs::OpenOptions::new`]. Enable at least one access mode (e.g.
    /// [`read`](Self::read)) before calling [`open`](Self::open).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OpenOptionsInner::new(),
        }
    }

    /// Set the option for read access.
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.inner.read = read;
        self
    }

    /// Set the option for write access.
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.inner.write = write;
        self
    }

    /// Set the option for append mode.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.inner.append = append;
        self
    }

    /// Set the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.inner.truncate = truncate;
        self
    }

    /// Set the option to create a new file, or open it if it already exists.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.inner.create = create;
        self
    }

    /// Set the option to create a new file, failing if it already exists.
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.inner.create_new = create_new;
        self
    }

    /// Confine every opened path to within `root`.
    pub fn jail(&mut self, root: impl Into<PathBuf>) -> &mut Self {
        self.inner.jail = Some(root.into());
        self
    }

    /// Set how symbolic links are treated within the [`jail`](Self::jail) root.
    ///
    /// Defaults to [`SymlinkPolicy::RestrictToRoot`]. Has no effect unless a
    /// jail root is configured.
    pub fn symlinks(&mut self, policy: SymlinkPolicy) -> &mut Self {
        self.inner.symlinks = policy;
        self
    }

    /// Set permissions used when this open operation creates a new file.
    pub fn created_file_permissions(&mut self, permissions: CreatedFilePermissions) -> &mut Self {
        self.inner.created_file_permissions = permissions;
        self
    }

    /// Open the file at `path` with the configured options, after validating it
    /// against path-traversal attacks.
    pub fn open(&self, path: impl AsRef<Path>) -> io::Result<fs::File> {
        let path = self.inner.resolve_sync(path.as_ref())?;
        let file = self.inner.std_options().open(&path)?;
        if let Some(root) = &self.inner.jail
            && self.inner.symlinks == SymlinkPolicy::RestrictToRoot
        {
            ensure_within_root_sync(root, &path)?;
        }
        Ok(file)
    }
}

impl Default for OpenOptionsSync {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct OpenOptionsInner {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    jail: Option<PathBuf>,
    symlinks: SymlinkPolicy,
    created_file_permissions: CreatedFilePermissions,
}

impl OpenOptionsInner {
    fn new() -> Self {
        Self {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            jail: None,
            symlinks: SymlinkPolicy::RestrictToRoot,
            created_file_permissions: CreatedFilePermissions::Default,
        }
    }

    fn tokio_options(&self) -> tokio::fs::OpenOptions {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.read(self.read)
            .write(self.write)
            .append(self.append)
            .truncate(self.truncate)
            .create(self.create)
            .create_new(self.create_new);
        #[cfg(unix)]
        if self.created_file_permissions == CreatedFilePermissions::OwnerReadWrite {
            opts.mode(0o600);
        }
        opts
    }

    fn std_options(&self) -> fs::OpenOptions {
        let mut opts = fs::OpenOptions::new();
        opts.read(self.read)
            .write(self.write)
            .append(self.append)
            .truncate(self.truncate)
            .create(self.create)
            .create_new(self.create_new);
        #[cfg(unix)]
        if self.created_file_permissions == CreatedFilePermissions::OwnerReadWrite {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        opts
    }

    async fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        match &self.jail {
            None => Ok(sanitize_path(path)?),
            Some(root) => {
                let full = root.join(sanitize_relative_path(path)?);
                if self.symlinks == SymlinkPolicy::RestrictToRoot {
                    ensure_within_root(root, &full).await?;
                }
                Ok(full)
            }
        }
    }

    fn resolve_sync(&self, path: &Path) -> io::Result<PathBuf> {
        match &self.jail {
            None => Ok(sanitize_path(path)?),
            Some(root) => {
                let full = root.join(sanitize_relative_path(path)?);
                if self.symlinks == SymlinkPolicy::RestrictToRoot {
                    ensure_within_root_sync(root, &full)?;
                }
                Ok(full)
            }
        }
    }
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

fn ensure_within_root_sync(root: &Path, target: &Path) -> io::Result<()> {
    let canonical_root = fs::canonicalize(root)?;
    if let Some(existing) = nearest_existing_ancestor_sync(target) {
        let canonical_target = canonicalize_existing_path_sync(&existing)?;
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

fn canonicalize_existing_path_sync(path: &Path) -> io::Result<PathBuf> {
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

fn nearest_existing_ancestor_sync(path: &Path) -> Option<PathBuf> {
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

    #[test]
    fn safe_open_sync_reads_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        fs::write(&path, b"hello world").unwrap();

        let text = {
            let mut s = String::new();
            use std::io::Read as _;
            safe_open_sync(&path)
                .unwrap()
                .read_to_string(&mut s)
                .unwrap();
            s
        };
        assert_eq!(text, "hello world");
    }

    #[tokio::test]
    async fn safe_open_rejects_parent_dir_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/../secret.txt");
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

        std::os::unix::fs::symlink(parent.path().join("secret.txt"), root.join("escape")).unwrap();

        let result = safe_open_in(&root, "escape").await;
        assert_eq!(err_kind(result), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn safe_open_in_allows_symlink_within_root() {
        let root = tempfile::tempdir().unwrap();
        tokio::fs::write(root.path().join("real.txt"), b"data")
            .await
            .unwrap();
        std::os::unix::fs::symlink(root.path().join("real.txt"), root.path().join("link")).unwrap();

        let file = safe_open_in(root.path(), "link").await.unwrap();
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

        assert_eq!(err_kind(result), io::ErrorKind::InvalidInput);
        assert!(!outside_target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn jail_create_sync_rejects_dangling_symlink_escape() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("public");
        let outside = parent.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();

        let outside_target = outside.join("created.txt");
        std::os::unix::fs::symlink(&outside_target, root.join("upload.txt")).unwrap();

        let result = OpenOptionsSync::new()
            .write(true)
            .create(true)
            .jail(&root)
            .open("upload.txt");

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
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

        assert_eq!(
            err_kind(safe_open_in(&root, "escape").await),
            io::ErrorKind::InvalidInput,
        );

        let file = OpenOptions::new()
            .read(true)
            .jail(&root)
            .symlinks(SymlinkPolicy::Allow)
            .open("escape")
            .await
            .unwrap();
        assert_eq!(read_to_string(file).await, "top secret");

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

    #[cfg(unix)]
    #[tokio::test]
    async fn open_options_private_created_file_has_no_group_or_other_bits() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("secret.txt");
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
            .open(&path)
            .await
            .unwrap();

        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[cfg(unix)]
    #[test]
    fn open_options_sync_private_created_file_has_no_group_or_other_bits() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("secret.txt");
        let _file = OpenOptionsSync::new()
            .write(true)
            .create_new(true)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
            .open(&path)
            .unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[tokio::test]
    async fn safe_write_in_creates_parent_dirs() {
        let root = tempfile::tempdir().unwrap();
        safe_write_in(root.path(), "nested/file.txt", b"hello")
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read_to_string(root.path().join("nested/file.txt"))
                .await
                .unwrap(),
            "hello",
        );
    }

    #[test]
    fn safe_write_in_sync_creates_parent_dirs() {
        let root = tempfile::tempdir().unwrap();
        safe_write_in_sync(root.path(), "nested/file.txt", b"hello").unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("nested/file.txt")).unwrap(),
            "hello",
        );
    }

    #[test]
    fn safe_write_in_sync_rejects_traversal() {
        let root = tempfile::tempdir().unwrap();
        let err = safe_write_in_sync(root.path(), "../escape.txt", b"nope").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!root.path().parent().unwrap().join("escape.txt").exists());
    }

    #[tokio::test]
    async fn safe_create_dir_all_in_rejects_absolute_paths() {
        let root = tempfile::tempdir().unwrap();
        let err = safe_create_dir_all_in(root.path(), "/tmp/escape")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn safe_create_dir_all_in_sync_rejects_absolute_paths() {
        let root = tempfile::tempdir().unwrap();
        let err = safe_create_dir_all_in_sync(root.path(), "/tmp/escape").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn safe_path_in_sync_resolves_plain_relative_path() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            safe_path_in_sync(root.path(), "nested/file.txt").unwrap(),
            root.path().join("nested/file.txt"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn safe_write_in_sync_rejects_symlink_escape() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let outside = parent.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(outside.join("created.txt"), root.join("link")).unwrap();

        let err = safe_write_in_sync(&root, "link", b"nope").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("created.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn safe_create_dir_all_in_sync_rejects_symlink_escape() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let outside = parent.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let err = safe_create_dir_all_in_sync(&root, "link/nested").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("nested").exists());
    }
}
