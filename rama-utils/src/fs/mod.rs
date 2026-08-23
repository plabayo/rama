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

use crate::rng::{HasherRng, Rng};
use std::{
    ffi::{OsStr, OsString},
    fs, io,
    ops::Deref,
    path::{Path, PathBuf},
};
use tokio::sync::{mpsc, oneshot};

#[cfg(loom)]
use std::fs::File;
#[cfg(not(loom))]
use tokio::fs::File;

/// A path guard that schedules removal of its temporary file when dropped.
///
/// Removal is performed by the asynchronous worker returned by
/// [`TempPathCleanup::new`], keeping filesystem work out of `Drop`.
#[derive(Debug)]
pub struct TempPath {
    path: PathBuf,
    cleanup: TempPathCleanup,
}

/// Guard for a private temporary directory that removes it recursively on
/// drop.
///
/// [`new`][Self::new] and [`with_prefix`][Self::with_prefix] generate an
/// unpredictable name below the platform temporary directory. [`create`]
/// accepts an exact caller-selected path. Creation is exclusive and uses
/// owner-only permissions on Unix, so an existing file, directory, or symlink
/// is never reused.
///
/// [`create`]: Self::create
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

/// Handle for an asynchronous temporary-file cleanup worker.
#[derive(Debug, Clone)]
pub struct TempPathCleanup(mpsc::UnboundedSender<TempPathCleanupMessage>);

/// Worker half of [`TempPathCleanup`].
#[derive(Debug)]
pub struct TempPathCleanupTask {
    rx: mpsc::UnboundedReceiver<TempPathCleanupMessage>,
}

#[derive(Debug)]
enum TempPathCleanupMessage {
    Remove(PathBuf),
    Flush(oneshot::Sender<()>),
}

impl TempPathCleanup {
    /// Create a cleanup handle and its worker.
    ///
    /// The caller must spawn [`TempPathCleanupTask::run`] and retain this
    /// handle for at least as long as new path guards can be created.
    #[must_use]
    pub fn new() -> (Self, TempPathCleanupTask) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self(tx), TempPathCleanupTask { rx })
    }

    /// Wait until every removal queued before this call has been processed.
    pub async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.0.send(TempPathCleanupMessage::Flush(tx)).is_ok() {
            _ = rx.await;
        }
    }
}

impl TempPathCleanupTask {
    /// Process cleanup work until all cleanup handles and path guards drop.
    pub async fn run(mut self) {
        while let Some(message) = self.rx.recv().await {
            match message {
                TempPathCleanupMessage::Remove(path) => {
                    if let Err(err) = tokio::fs::remove_file(&path).await
                        && err.kind() != io::ErrorKind::NotFound
                    {
                        tracing::debug!(?path, "failed to remove temporary artifact: {err}");
                    }
                }
                TempPathCleanupMessage::Flush(done) => {
                    _ = done.send(());
                }
            }
        }
    }
}

impl TempPath {
    /// Guard an existing temporary file path with `cleanup`.
    #[must_use]
    pub fn new(path: PathBuf, cleanup: TempPathCleanup) -> Self {
        Self { path, cleanup }
    }
}

impl TempDir {
    /// Create an unpredictably named private temporary directory below the
    /// platform temporary directory.
    pub fn new() -> io::Result<Self> {
        Self::with_prefix("rama-")
    }

    /// Create an unpredictably named private temporary directory with
    /// `prefix` below the platform temporary directory.
    ///
    /// The prefix must be one ordinary path component. Creation is exclusive,
    /// so an existing file, directory, or symlink is never reused.
    pub fn with_prefix(prefix: impl AsRef<OsStr>) -> io::Result<Self> {
        let prefix = prefix.as_ref();
        let prefix_path = Path::new(prefix);
        if prefix.is_empty()
            || prefix_path.file_name() != Some(prefix)
            || prefix_path.components().count() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "temporary-directory prefix must be one ordinary path component",
            ));
        }

        let mut rng = HasherRng::new();
        Self::with_prefix_in(prefix, &std::env::temp_dir(), &mut rng)
    }

    fn with_prefix_in(prefix: &OsStr, parent: &Path, rng: &mut impl Rng) -> io::Result<Self> {
        const MAX_ATTEMPTS: usize = 16;

        for _ in 0..MAX_ATTEMPTS {
            let mut name = OsString::from(prefix);
            name.push(format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64()));
            match Self::create(parent.join(name)) {
                Ok(directory) => return Ok(directory),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary directory",
        ))
    }

    /// Exclusively create and guard a temporary directory at `path`.
    pub fn create(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(Self { path })
    }

    /// Return the guarded directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the directory now and report any cleanup failure.
    pub fn close(mut self) -> io::Result<()> {
        let path = std::mem::take(&mut self.path);
        remove_temp_dir(&path)
    }
}

/// Create an unpredictably named private temporary directory below the
/// platform temporary directory.
pub fn tempdir() -> io::Result<TempDir> {
    TempDir::new()
}

impl AsRef<Path> for TempPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Deref for TempPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let path = std::mem::take(&mut self.path);
        if self
            .cleanup
            .0
            .send(TempPathCleanupMessage::Remove(path.clone()))
            .is_err()
        {
            tracing::debug!(?path, "temporary-file cleanup worker is unavailable");
        }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let path = std::mem::take(&mut self.path);
        if let Err(err) = remove_temp_dir(&path) {
            tracing::debug!(?path, "failed to remove temporary directory: {err}");
        }
    }
}

fn remove_temp_dir(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

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

/// Open a file read-only, confined to `root`, given an **absolute** path.
///
/// [`safe_open_in`] treats its path as relative to `root` and rejects
/// absolute ones; this accepts an absolute path (as a `file:` uri yields)
/// and rejects it when it does not live under `root`.
pub async fn safe_open_under(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<File> {
    let (root, path) = (root.as_ref(), path.as_ref());
    let relative = path.strip_prefix(root).map_err(|_e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is outside the confined root",
        )
    })?;
    safe_open_in(root, relative).await
}

/// Blocking variant of [`safe_open_under`].
pub fn safe_open_under_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<fs::File> {
    let (root, path) = (root.as_ref(), path.as_ref());
    let relative = path.strip_prefix(root).map_err(|_e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is outside the confined root",
        )
    })?;
    safe_open_in_sync(root, relative)
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
    let canonical_root = canonicalize_root(root).await?;
    ensure_within_canonical_root(&canonical_root, &path).await?;
    Ok(path)
}

/// Blocking variant of [`safe_path_in`].
pub fn safe_path_in_sync(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = canonicalize_root_sync(root)?;
    ensure_within_canonical_root_sync(&canonical_root, &path)?;
    Ok(path)
}

/// Canonicalize an existing path confined to within the trusted directory `root`.
///
/// `path` is treated as relative to `root`; absolute paths, `..` traversal,
/// reserved device names, smuggled prefixes, and symbolic links that resolve
/// outside `root` are all rejected. `root` and `path` must exist.
pub async fn safe_canonicalize_in(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<PathBuf> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = canonicalize_root(root).await?;
    let canonical_path = canonicalize_existing_path(&path).await?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(UnsafePathError::EscapesRoot.into());
    }
    Ok(canonical_path)
}

/// Blocking variant of [`safe_canonicalize_in`].
pub fn safe_canonicalize_in_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<PathBuf> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = canonicalize_root_sync(root)?;
    let canonical_path = canonicalize_existing_path_sync(&path)?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(UnsafePathError::EscapesRoot.into());
    }
    Ok(canonical_path)
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
    let canonical_root = canonicalize_root(root).await?;
    ensure_within_canonical_root(&canonical_root, &path).await?;
    #[cfg(loom)]
    fs::create_dir_all(&path)?;
    #[cfg(not(loom))]
    tokio::fs::create_dir_all(&path).await?;
    ensure_within_canonical_root(&canonical_root, &path).await
}

/// Blocking variant of [`safe_create_dir_all_in`].
pub fn safe_create_dir_all_in_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<()> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = canonicalize_root_sync(root)?;
    ensure_within_canonical_root_sync(&canonical_root, &path)?;
    fs::create_dir_all(&path)?;
    ensure_within_canonical_root_sync(&canonical_root, &path)
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
    let canonical_root = canonicalize_root(root).await?;

    if let Some(parent) = path.parent() {
        ensure_within_canonical_root(&canonical_root, parent).await?;
        #[cfg(loom)]
        fs::create_dir_all(parent)?;
        #[cfg(not(loom))]
        tokio::fs::create_dir_all(parent).await?;
        ensure_within_canonical_root(&canonical_root, parent).await?;
    }

    ensure_within_canonical_root(&canonical_root, &path).await?;
    #[cfg(loom)]
    fs::write(&path, contents)?;
    #[cfg(not(loom))]
    tokio::fs::write(&path, contents).await?;
    ensure_within_canonical_root(&canonical_root, &path).await
}

/// Blocking variant of [`safe_write_in`].
pub fn safe_write_in_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> io::Result<()> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = canonicalize_root_sync(root)?;

    if let Some(parent) = path.parent() {
        ensure_within_canonical_root_sync(&canonical_root, parent)?;
        fs::create_dir_all(parent)?;
        ensure_within_canonical_root_sync(&canonical_root, parent)?;
    }

    ensure_within_canonical_root_sync(&canonical_root, &path)?;
    fs::write(&path, contents)?;
    ensure_within_canonical_root_sync(&canonical_root, &path)
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
        #[cfg(loom)]
        let file = self.inner.std_options().open(&path)?;
        #[cfg(not(loom))]
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

    #[cfg(not(loom))]
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
    let canonical_root = canonicalize_root(root).await?;
    ensure_within_canonical_root(&canonical_root, target).await
}

#[cfg(loom)]
async fn canonicalize_root(root: &Path) -> io::Result<PathBuf> {
    canonicalize_root_sync(root)
}

#[cfg(not(loom))]
async fn canonicalize_root(root: &Path) -> io::Result<PathBuf> {
    tokio::fs::canonicalize(root).await
}

#[cfg(loom)]
async fn ensure_within_canonical_root(canonical_root: &Path, target: &Path) -> io::Result<()> {
    ensure_within_canonical_root_sync(canonical_root, target)
}

#[cfg(not(loom))]
async fn ensure_within_canonical_root(canonical_root: &Path, target: &Path) -> io::Result<()> {
    if let Some(existing) = nearest_existing_ancestor(target).await {
        let canonical_target = canonicalize_existing_path(&existing).await?;
        if !canonical_target.starts_with(canonical_root) {
            return Err(UnsafePathError::EscapesRoot.into());
        }
    }
    Ok(())
}

fn ensure_within_root_sync(root: &Path, target: &Path) -> io::Result<()> {
    let canonical_root = canonicalize_root_sync(root)?;
    ensure_within_canonical_root_sync(&canonical_root, target)
}

fn canonicalize_root_sync(root: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(root)
}

fn ensure_within_canonical_root_sync(canonical_root: &Path, target: &Path) -> io::Result<()> {
    if let Some(existing) = nearest_existing_ancestor_sync(target) {
        let canonical_target = canonicalize_existing_path_sync(&existing)?;
        if !canonical_target.starts_with(canonical_root) {
            return Err(UnsafePathError::EscapesRoot.into());
        }
    }
    Ok(())
}

#[cfg(not(loom))]
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

#[cfg(loom)]
async fn canonicalize_existing_path(path: &Path) -> io::Result<PathBuf> {
    canonicalize_existing_path_sync(path)
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
#[cfg(not(loom))]
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

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn read_to_string(mut file: File) -> io::Result<String> {
        let mut buf = String::new();
        file.read_to_string(&mut buf).await?;
        Ok(buf)
    }

    fn err_kind<T>(result: io::Result<T>) -> Option<io::ErrorKind> {
        result.err().map(|err| err.kind())
    }

    #[test]
    fn generated_temp_dirs_are_unique_prefixed_and_reject_path_prefixes() {
        let first = tempdir().unwrap();
        let second = TempDir::with_prefix("rama-test.").unwrap();
        assert_ne!(first.path(), second.path());
        assert!(
            second
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("rama-test.")
        );

        for prefix in ["", ".", "..", "nested/path"] {
            assert_eq!(
                TempDir::with_prefix(prefix).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    struct SequenceRng {
        values: std::vec::IntoIter<u64>,
    }

    impl Rng for SequenceRng {
        fn next_u64(&mut self) -> u64 {
            self.values.next().unwrap_or_default()
        }
    }

    #[test]
    fn generated_temp_dir_retries_only_name_collisions() {
        let parent = tempdir().unwrap();
        let collision = parent.path().join("test-00000000000000010000000000000002");
        fs::create_dir(&collision).unwrap();
        let mut rng = SequenceRng {
            values: vec![1, 2, 3, 4].into_iter(),
        };

        let directory = TempDir::with_prefix_in("test-".as_ref(), parent.path(), &mut rng).unwrap();
        assert_eq!(
            directory.path().file_name().unwrap(),
            "test-00000000000000030000000000000004"
        );

        let not_a_directory = parent.path().join("regular-file");
        fs::write(&not_a_directory, b"not a directory").unwrap();
        let mut rng = SequenceRng {
            values: vec![5, 6].into_iter(),
        };
        assert_eq!(
            TempDir::with_prefix_in("test-".as_ref(), &not_a_directory, &mut rng)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotADirectory
        );
    }

    #[tokio::test]
    async fn temp_path_cleanup_removes_all_files_before_flush_returns() {
        let dir = tempdir().unwrap();
        let first = dir.path().join("first.tmp");
        let second = dir.path().join("second.tmp");
        tokio::fs::write(&first, b"first").await.unwrap();
        tokio::fs::write(&second, b"second").await.unwrap();
        let (cleanup, worker) = TempPathCleanup::new();
        let worker = tokio::spawn(worker.run());

        let first_guard = TempPath::new(first.clone(), cleanup.clone());
        let second_guard = TempPath::new(second.clone(), cleanup.clone());
        assert_eq!(first_guard.as_ref(), first.as_path());
        assert_eq!(&*second_guard, second.as_path());
        drop(first_guard);
        drop(second_guard);
        cleanup.flush().await;

        assert!(!first.exists());
        assert!(!second.exists());
        drop(cleanup);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn temp_path_cleanup_tolerates_already_removed_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("gone.tmp");
        let (cleanup, worker) = TempPathCleanup::new();
        let worker = tokio::spawn(worker.run());

        drop(TempPath::new(path, cleanup.clone()));
        cleanup.flush().await;
        drop(cleanup);
        worker.await.unwrap();
    }

    #[test]
    fn temp_dir_is_private_exclusive_and_recursively_removed() {
        let parent = tempdir().unwrap();
        let path = parent.path().join("guarded");
        let directory = TempDir::create(path.clone()).unwrap();
        assert_eq!(directory.path(), path);
        fs::create_dir(path.join("nested")).unwrap();
        fs::write(path.join("nested/artifact"), b"temporary").unwrap();
        TempDir::create(path.clone()).unwrap_err();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        drop(directory);
        assert!(!path.exists());
    }

    #[test]
    fn temp_dir_close_reports_cleanup_and_missing_directory_is_tolerated() {
        let parent = tempdir().unwrap();
        let first = parent.path().join("first");
        TempDir::create(first.clone()).unwrap().close().unwrap();
        assert!(!first.exists());

        let second = parent.path().join("second");
        let directory = TempDir::create(second.clone()).unwrap();
        fs::remove_dir(&second).unwrap();
        directory.close().unwrap();

        let replaced = parent.path().join("replaced-by-file");
        let directory = TempDir::create(replaced.clone()).unwrap();
        fs::remove_dir(&replaced).unwrap();
        fs::write(&replaced, b"not a directory").unwrap();
        assert_ne!(
            directory.close().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(replaced.is_file());

        let not_a_directory = parent.path().join("regular-file");
        fs::write(&not_a_directory, b"keep").unwrap();
        let error = remove_temp_dir(&not_a_directory).unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::NotFound);
        assert!(not_a_directory.is_file());
    }

    #[tokio::test]
    async fn safe_open_reads_a_regular_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        tokio::fs::write(&path, b"hello world").await.unwrap();

        let file = safe_open(&path).await.unwrap();
        assert_eq!(read_to_string(file).await.unwrap(), "hello world");
    }

    #[test]
    fn safe_open_sync_reads_a_regular_file() {
        let dir = tempdir().unwrap();
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
        let dir = tempdir().unwrap();
        let path = dir.path().join("sub/../secret.txt");
        assert_eq!(
            err_kind(safe_open(&path).await),
            Some(io::ErrorKind::InvalidInput),
        );
    }

    #[tokio::test]
    async fn safe_open_missing_file_is_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.txt");
        assert_eq!(
            err_kind(safe_open(&path).await),
            Some(io::ErrorKind::NotFound),
        );
    }

    #[tokio::test]
    async fn safe_open_in_serves_files_within_root() {
        let root = tempdir().unwrap();
        tokio::fs::create_dir(root.path().join("assets"))
            .await
            .unwrap();
        tokio::fs::write(root.path().join("assets/app.js"), b"console.log(1)")
            .await
            .unwrap();

        let file = safe_open_in(root.path(), "assets/app.js").await.unwrap();
        assert_eq!(read_to_string(file).await.unwrap(), "console.log(1)");

        let file = safe_open_in(root.path(), "/assets/app.js").await;
        assert_eq!(err_kind(file), Some(io::ErrorKind::InvalidInput));
    }

    #[tokio::test]
    async fn safe_open_in_rejects_traversal_out_of_root() {
        let parent = tempdir().unwrap();
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
        let parent = tempdir().unwrap();
        tokio::fs::write(parent.path().join("secret.txt"), b"top secret")
            .await
            .unwrap();
        let root = parent.path().join("public");
        tokio::fs::create_dir(&root).await.unwrap();

        std::os::unix::fs::symlink(parent.path().join("secret.txt"), root.join("escape")).unwrap();

        let result = safe_open_in(&root, "escape").await;
        assert_eq!(err_kind(result), Some(io::ErrorKind::InvalidInput));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn safe_open_in_allows_symlink_within_root() {
        let root = tempdir().unwrap();
        tokio::fs::write(root.path().join("real.txt"), b"data")
            .await
            .unwrap();
        std::os::unix::fs::symlink(root.path().join("real.txt"), root.path().join("link")).unwrap();

        let file = safe_open_in(root.path(), "link").await.unwrap();
        assert_eq!(read_to_string(file).await.unwrap(), "data");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn jail_create_rejects_dangling_symlink_escape() {
        let parent = tempdir().unwrap();
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

        assert_eq!(err_kind(result), Some(io::ErrorKind::InvalidInput));
        assert!(!outside_target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn jail_create_sync_rejects_dangling_symlink_escape() {
        let parent = tempdir().unwrap();
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
        let parent = tempdir().unwrap();
        tokio::fs::write(parent.path().join("secret.txt"), b"top secret")
            .await
            .unwrap();
        let root = parent.path().join("public");
        tokio::fs::create_dir(&root).await.unwrap();
        std::os::unix::fs::symlink(parent.path().join("secret.txt"), root.join("escape")).unwrap();

        assert_eq!(
            err_kind(safe_open_in(&root, "escape").await),
            Some(io::ErrorKind::InvalidInput),
        );

        let file = OpenOptions::new()
            .read(true)
            .jail(&root)
            .symlinks(SymlinkPolicy::Allow)
            .open("escape")
            .await
            .unwrap();
        assert_eq!(read_to_string(file).await.unwrap(), "top secret");

        let traversal = OpenOptions::new()
            .read(true)
            .jail(&root)
            .symlinks(SymlinkPolicy::Allow)
            .open("../secret.txt")
            .await;
        assert_eq!(err_kind(traversal), Some(io::ErrorKind::InvalidInput));
    }

    #[tokio::test]
    async fn open_options_can_create_within_jail() {
        let root = tempdir().unwrap();
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

        let root = tempdir().unwrap();
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

        let root = tempdir().unwrap();
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
        let root = tempdir().unwrap();
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
        let root = tempdir().unwrap();
        safe_write_in_sync(root.path(), "nested/file.txt", b"hello").unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("nested/file.txt")).unwrap(),
            "hello",
        );
    }

    #[test]
    fn safe_write_in_sync_rejects_traversal() {
        let root = tempdir().unwrap();
        let err = safe_write_in_sync(root.path(), "../escape.txt", b"nope").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!root.path().parent().unwrap().join("escape.txt").exists());
    }

    #[tokio::test]
    async fn safe_create_dir_all_in_rejects_absolute_paths() {
        let root = tempdir().unwrap();
        let err = safe_create_dir_all_in(root.path(), "/tmp/escape")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn safe_create_dir_all_in_sync_rejects_absolute_paths() {
        let root = tempdir().unwrap();
        let err = safe_create_dir_all_in_sync(root.path(), "/tmp/escape").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn safe_path_in_sync_resolves_plain_relative_path() {
        let root = tempdir().unwrap();
        assert_eq!(
            safe_path_in_sync(root.path(), "nested/file.txt").unwrap(),
            root.path().join("nested/file.txt"),
        );
    }

    #[tokio::test]
    async fn safe_canonicalize_in_resolves_existing_path() {
        let root = tempdir().unwrap();
        tokio::fs::create_dir(root.path().join("nested"))
            .await
            .unwrap();
        assert_eq!(
            safe_canonicalize_in(root.path(), "nested").await.unwrap(),
            root.path().canonicalize().unwrap().join("nested"),
        );
    }

    #[test]
    fn safe_canonicalize_in_sync_resolves_existing_path() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        assert_eq!(
            safe_canonicalize_in_sync(root.path(), "nested").unwrap(),
            root.path().canonicalize().unwrap().join("nested"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn safe_write_in_sync_rejects_symlink_escape() {
        let parent = tempdir().unwrap();
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
        let parent = tempdir().unwrap();
        let root = parent.path().join("root");
        let outside = parent.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let err = safe_create_dir_all_in_sync(&root, "link/nested").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("nested").exists());
    }

    #[cfg(unix)]
    #[test]
    fn safe_canonicalize_in_sync_rejects_symlink_escape() {
        let parent = tempdir().unwrap();
        let root = parent.path().join("root");
        let outside = parent.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let err = safe_canonicalize_in_sync(&root, "link").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn safe_canonicalize_in_rejects_symlink_escape() {
        let parent = tempdir().unwrap();
        let root = parent.path().join("root");
        let outside = parent.path().join("outside");
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::create_dir(&outside).await.unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let err = safe_canonicalize_in(&root, "link").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
