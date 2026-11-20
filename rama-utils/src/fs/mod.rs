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
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{self, Write},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};
#[cfg(not(loom))]
use tokio::io::AsyncWriteExt as _;
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

/// Guard for a private temporary directory that removes it recursively on drop.
/// An outstanding anonymous-file job keeps the directory alive until it finishes.
/// [`Self::close`] runs explicit cleanup on the blocking pool and reports failures.
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
    directory: Arc<TempDirInner>,
}

#[derive(Debug)]
struct TempDirInner {
    path: PathBuf,
    // Explicit close revokes queued opens and waits for any open already
    // inside its filesystem operation. Ordinary drop only releases an owner.
    closed: parking_lot::RwLock<bool>,
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
                    #[cfg(loom)]
                    let result = fs::remove_file(&path);
                    #[cfg(not(loom))]
                    let result = tokio::fs::remove_file(&path).await;
                    if let Err(err) = result
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
    pub async fn new() -> io::Result<Self> {
        run_blocking(Self::new_sync).await
    }

    /// Blocking counterpart to [`Self::new`].
    pub fn new_sync() -> io::Result<Self> {
        Self::with_prefix_sync("rama-")
    }

    /// Create an unpredictably named private temporary directory with
    /// `prefix` below the platform temporary directory.
    ///
    /// The prefix must be one ordinary path component. Creation is exclusive,
    /// so an existing file, directory, or symlink is never reused.
    pub async fn with_prefix(prefix: impl AsRef<OsStr>) -> io::Result<Self> {
        Self::with_prefix_in(prefix, std::env::temp_dir()).await
    }

    /// Blocking counterpart to [`Self::with_prefix`].
    pub fn with_prefix_sync(prefix: impl AsRef<OsStr>) -> io::Result<Self> {
        Self::with_prefix_in_sync(prefix, std::env::temp_dir())
    }

    /// Create an unpredictably named private temporary directory with the given
    /// prefix below the existing `parent`. The prefix must be one ordinary path
    /// component. A relative parent is resolved at creation time, so the guard
    /// keeps referring to the same path if the working directory changes.
    pub async fn with_prefix_in(
        prefix: impl AsRef<OsStr>,
        parent: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let prefix = prefix.as_ref().to_owned();
        let parent = parent.as_ref().to_owned();
        run_blocking(move || Self::with_prefix_in_sync(prefix, parent)).await
    }

    /// Blocking counterpart to [`Self::with_prefix_in`].
    pub fn with_prefix_in_sync(
        prefix: impl AsRef<OsStr>,
        parent: impl AsRef<Path>,
    ) -> io::Result<Self> {
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
        Self::create_with_rng(prefix, &std::path::absolute(parent)?, &mut rng)
    }

    fn create_with_rng(prefix: &OsStr, parent: &Path, rng: &mut impl Rng) -> io::Result<Self> {
        create_temp_entry(prefix, rng, |name| Self::create_sync(parent.join(name)))
    }

    /// Exclusively create an anonymous read/write file in this directory.
    ///
    /// The operation requests removal before returning the open
    /// file. On Unix the file is unlinked immediately. On Windows the standard
    /// file sharing mode permits deletion, which completes when the last
    /// handle closes. Filesystems that reject removal of an open file return
    /// an error before the caller can write data.
    pub async fn anonymous_file(&self) -> io::Result<File> {
        let directory = self.directory.clone();
        let file = run_blocking(move || {
            let closed = directory.closed.read();
            if *closed {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "temporary directory is closed",
                ));
            }
            Self::anonymous_file_in(&directory.path)
        })
        .await?;
        #[cfg(not(loom))]
        let file = File::from_std(file);
        Ok(file)
    }

    /// Blocking counterpart to [`Self::anonymous_file`].
    pub fn anonymous_file_sync(&self) -> io::Result<fs::File> {
        Self::anonymous_file_in(self.path())
    }

    // Create and unlink in the same worker operation. Cancellation can drop the
    // returned descriptor but cannot interrupt the removal of a newly created name.
    fn anonymous_file_in(directory: &Path) -> io::Result<fs::File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .jail(directory)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite);
        let (file, path) = create_temp_entry("file-".as_ref(), &mut HasherRng::new(), |name| {
            let file = options.open_sync(&name)?;
            Ok((file, directory.join(name)))
        })?;
        if let Err(err) = fs::remove_file(&path) {
            drop(file);
            // Some filesystems only allow removal after close. The TempDir
            // also guards this empty entry if the second removal fails.
            if let Err(cleanup) = fs::remove_file(&path)
                && cleanup.kind() != io::ErrorKind::NotFound
            {
                tracing::debug!(?path, "failed to remove empty temporary file: {cleanup}");
            }
            return Err(err);
        }
        Ok(file)
    }

    /// Exclusively create and guard a temporary directory at `path`.
    /// The guard retains its absolute path for cleanup.
    pub async fn create(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        run_blocking(move || Self::create_sync(path)).await
    }

    /// Blocking counterpart to [`Self::create`].
    pub fn create_sync(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = std::path::absolute(path.into())?;
        #[cfg(unix)]
        let builder = {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        builder.create(&path)?;
        Ok(Self {
            directory: Arc::new(TempDirInner {
                path,
                closed: parking_lot::RwLock::new(false),
            }),
        })
    }

    /// Return the guarded directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.directory.path
    }

    /// Remove the directory now and report any cleanup failure.
    pub async fn close(self) -> io::Result<()> {
        run_blocking(move || self.close_sync()).await
    }

    /// Blocking counterpart to [`Self::close`].
    pub fn close_sync(self) -> io::Result<()> {
        *self.directory.closed.write() = true;
        remove_temp_dir(self.path())
    }
}

/// Synchronous shorthand for [`TempDir::new_sync`]. For async callers, use [`TempDir::new`].
pub fn tempdir() -> io::Result<TempDir> {
    TempDir::new_sync()
}

fn create_temp_entry<T>(
    prefix: &OsStr,
    rng: &mut impl Rng,
    mut create: impl FnMut(OsString) -> io::Result<T>,
) -> io::Result<T> {
    const MAX_ATTEMPTS: usize = 16;
    for _ in 0..MAX_ATTEMPTS {
        let mut name = OsString::from(prefix);
        name.push(format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64()));
        match create(name) {
            Ok(entry) => return Ok(entry),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temporary entry",
    ))
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

impl Drop for TempDirInner {
    fn drop(&mut self) {
        if !*self.closed.get_mut()
            && let Err(err) = remove_temp_dir(&self.path)
        {
            tracing::debug!(path = ?self.path, "failed to remove temporary directory: {err}");
        }
    }
}

fn remove_temp_dir(path: &Path) -> io::Result<()> {
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
    OpenOptions::new().read(true).open_sync(path)
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
    let root = root.as_ref();
    let relative = strip_root(root, path.as_ref())?;
    safe_open_in(root, relative).await
}

/// Blocking variant of [`safe_open_under`].
pub fn safe_open_under_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<fs::File> {
    let root = root.as_ref();
    let relative = strip_root(root, path.as_ref())?;
    safe_open_in_sync(root, relative)
}

fn strip_root<'a>(root: &Path, path: &'a Path) -> io::Result<&'a Path> {
    path.strip_prefix(root).map_err(|_err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is outside the confined root",
        )
    })
}

/// Blocking variant of [`safe_open_in`].
pub fn safe_open_in_sync(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<fs::File> {
    OpenOptions::new()
        .read(true)
        .jail(root.as_ref())
        .open_sync(path)
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
    let root = root.as_ref().to_owned();
    let path = path.as_ref().to_owned();
    run_blocking(move || safe_path_in_sync(root, path)).await
}

/// Blocking variant of [`safe_path_in`].
pub fn safe_path_in_sync(root: impl AsRef<Path>, path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = fs::canonicalize(root)?;
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
    let root = root.as_ref().to_owned();
    let path = path.as_ref().to_owned();
    run_blocking(move || safe_canonicalize_in_sync(root, path)).await
}

/// Blocking variant of [`safe_canonicalize_in`].
pub fn safe_canonicalize_in_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<PathBuf> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = fs::canonicalize(root)?;
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
    let root = root.as_ref().to_owned();
    let path = path.as_ref().to_owned();
    run_blocking(move || safe_create_dir_all_in_sync(root, path)).await
}

/// Blocking variant of [`safe_create_dir_all_in`].
pub fn safe_create_dir_all_in_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> io::Result<()> {
    let root = root.as_ref();
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = fs::canonicalize(root)?;
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
    let root = root.as_ref().to_owned();
    let path = path.as_ref().to_owned();
    let (canonical_root, path, file) = run_blocking(move || create_for_write(&root, &path)).await?;
    #[cfg(not(loom))]
    {
        let mut file = File::from_std(file);
        file.write_all(contents.as_ref()).await?;
        file.flush().await?;
    }
    #[cfg(loom)]
    {
        let mut file = file;
        file.write_all(contents.as_ref())?;
    }
    run_blocking(move || ensure_within_canonical_root_sync(&canonical_root, &path)).await
}

/// Blocking variant of [`safe_write_in`].
pub fn safe_write_in_sync(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> io::Result<()> {
    let (canonical_root, path, mut file) = create_for_write(root.as_ref(), path.as_ref())?;
    file.write_all(contents.as_ref())?;
    ensure_within_canonical_root_sync(&canonical_root, &path)
}

fn create_for_write(root: &Path, path: &Path) -> io::Result<(PathBuf, PathBuf, fs::File)> {
    let path = root.join(sanitize_relative_path(path)?);
    let canonical_root = fs::canonicalize(root)?;
    if let Some(parent) = path.parent() {
        ensure_within_canonical_root_sync(&canonical_root, parent)?;
        fs::create_dir_all(parent)?;
        ensure_within_canonical_root_sync(&canonical_root, parent)?;
    }
    ensure_within_canonical_root_sync(&canonical_root, &path)?;
    let file = fs::File::create(&path)?;
    Ok((canonical_root, path, file))
}

// Keep each validated filesystem operation in one blocking-pool job. Loom
// builds use std files and run the same operation on the calling thread.
async fn run_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    #[cfg(not(loom))]
    {
        tokio::task::spawn_blocking(operation).await?
    }
    #[cfg(loom)]
    {
        operation()
    }
}

/// Options to open a file with async path-traversal protection.
///
/// Mirrors the access-mode setters of [`tokio::fs::OpenOptions`]
/// (read/write/append/truncate/create/create_new) and adds
/// [`jail`](Self::jail) to confine every opened path to a trusted root
/// directory.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    options: fs::OpenOptions,
    jail: Option<PathBuf>,
    symlinks: SymlinkPolicy,
    created_file_permissions: CreatedFilePermissions,
}

impl OpenOptions {
    /// Create options with every access mode disabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: fs::OpenOptions::new(),
            jail: None,
            symlinks: SymlinkPolicy::default(),
            created_file_permissions: CreatedFilePermissions::default(),
        }
    }

    /// Set the option for read access.
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.options.read(read);
        self
    }

    /// Set the option for write access.
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.options.write(write);
        self
    }

    /// Set the option for append mode.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.options.append(append);
        self
    }

    /// Set the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.options.truncate(truncate);
        self
    }

    /// Set the option to create a new file, or open it if it already exists.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.options.create(create);
        self
    }

    /// Set the option to create a new file, failing if it already exists.
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.options.create_new(create_new);
        self
    }

    /// Confine every opened path to within `root`.
    ///
    /// The path passed to [`open`](Self::open) is then interpreted as relative
    /// to `root`; absolute paths are rejected, and the resolved path must remain
    /// within `root` or the open fails with [`UnsafePathError::EscapesRoot`].
    /// `root` must exist when opening.
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

    /// Set permissions used when this open operation creates a new file.
    pub fn created_file_permissions(&mut self, permissions: CreatedFilePermissions) -> &mut Self {
        self.created_file_permissions = permissions;
        self
    }

    /// Open a file after applying the configured traversal and jail checks.
    pub async fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        let options = self.clone();
        let path = path.as_ref().to_owned();
        let file = run_blocking(move || options.open_sync(path)).await?;
        #[cfg(not(loom))]
        let file = File::from_std(file);
        Ok(file)
    }

    /// Blocking variant of [`open`](Self::open).
    pub fn open_sync(&self, path: impl AsRef<Path>) -> io::Result<fs::File> {
        let path = match &self.jail {
            Some(root) => root.join(sanitize_relative_path(path)?),
            None => sanitize_path(path)?,
        };
        let confined_root = self
            .jail
            .as_ref()
            .filter(|_| self.symlinks == SymlinkPolicy::RestrictToRoot);
        if let Some(root) = confined_root {
            ensure_within_root_sync(root, &path)?;
        }
        #[cfg(unix)]
        let options = {
            let mut options = self.options.clone();
            if self.created_file_permissions == CreatedFilePermissions::OwnerReadWrite {
                options.mode(0o600);
            }
            options
        };
        #[cfg(not(unix))]
        let options = &self.options;
        let file = options.open(&path)?;
        if let Some(root) = confined_root {
            ensure_within_root_sync(root, &path)?;
        }
        Ok(file)
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking spelling of [`OpenOptions`]. Its `open` method calls [`OpenOptions::open_sync`].
#[derive(Debug, Clone, Default)]
pub struct OpenOptionsSync(OpenOptions);

macro_rules! sync_open_setters {
    ($($name:ident: $arg:ty),+ $(,)?) => {$(
        #[doc = concat!("See [`OpenOptions::", stringify!($name), "`].")]
        pub fn $name(&mut self, value: $arg) -> &mut Self {
            self.0.$name(value);
            self
        }
    )+};
}

impl OpenOptionsSync {
    /// Create options with every access mode disabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    sync_open_setters! {
        read: bool, write: bool, append: bool, truncate: bool, create: bool, create_new: bool,
        jail: impl Into<PathBuf>, symlinks: SymlinkPolicy, created_file_permissions: CreatedFilePermissions,
    }

    /// Open a file with the configured traversal and jail checks.
    pub fn open(&self, path: impl AsRef<Path>) -> io::Result<fs::File> {
        self.0.open_sync(path)
    }
}

/// Verify, by canonicalizing, that `target` resolves to a location within
/// `root`. This defends against symbolic links that point outside the jail.
///
/// Only the portion of `target` that already exists is canonicalized; the
/// lexical sanitization already guarantees the not-yet-existing tail contains
/// no `..` components.
fn ensure_within_root_sync(root: &Path, target: &Path) -> io::Result<()> {
    let canonical_root = fs::canonicalize(root)?;
    ensure_within_canonical_root_sync(&canonical_root, target)
}

fn ensure_within_canonical_root_sync(canonical_root: &Path, target: &Path) -> io::Result<()> {
    if let Some(existing) = target.ancestors().find(|p| fs::symlink_metadata(p).is_ok()) {
        let canonical_target = canonicalize_existing_path_sync(existing)?;
        if !canonical_target.starts_with(canonical_root) {
            return Err(UnsafePathError::EscapesRoot.into());
        }
    }
    Ok(())
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

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use std::io::{Read as _, Seek as _};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
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
        let second = TempDir::with_prefix_sync("rama-test.").unwrap();
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
                TempDir::with_prefix_sync(prefix).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn anonymous_tempfile_lives_until_last_handle_closes() {
        let parent = tempdir().unwrap();
        let directory = TempDir::with_prefix_in_sync("anonymous-", parent.path()).unwrap();
        assert_eq!(directory.path().parent(), Some(parent.path()));
        let mut writer = directory.anonymous_file_sync().unwrap();
        writer.write_all(b"saved").unwrap();
        #[cfg(unix)]
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        let mut reader = writer.try_clone().unwrap();
        drop(writer);
        reader.rewind().unwrap();
        let mut bytes = [0; 5];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"saved");
        drop(reader);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn canceled_tempdir_jobs_still_clean_up_their_resources() {
        // Queue each operation behind a known blocker so cancellation falls
        // between spawning the job and doing any filesystem work.
        async fn cancel_after_start<T>(future: impl Future<Output = T>) {
            let mut future = std::pin::pin!(future);
            std::future::poll_fn(|cx| {
                assert!(future.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let parent = tempdir().unwrap();
        let create = parent.path().join("create");
        let close = parent.path().join("close");
        runtime.block_on(async {
            let directory = TempDir::create(&close).await.unwrap();
            let pending = TempDir::with_prefix_in("opening-", parent.path())
                .await
                .unwrap();
            let pending_path = pending.path().to_owned();
            let file = parent.anonymous_file().await.unwrap();
            drop(file);
            let (release, gate) = std::sync::mpsc::channel();
            let worker = tokio::task::spawn_blocking(move || gate.recv().unwrap());
            cancel_after_start(TempDir::create(&create)).await;
            cancel_after_start(pending.anonymous_file()).await;
            drop(pending);
            assert!(
                pending_path.exists(),
                "queued open still owns its private directory"
            );
            cancel_after_start(directory.close()).await;
            release.send(()).unwrap();
            worker.await.unwrap();
        });
        // Runtime shutdown joins the detached blocking operations.
        drop(runtime);
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    struct SequenceRng {
        values: std::vec::IntoIter<u64>,
        calls: usize,
    }

    impl Rng for SequenceRng {
        fn next_u64(&mut self) -> u64 {
            self.calls += 1;
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
            calls: 0,
        };

        let directory =
            TempDir::create_with_rng("test-".as_ref(), parent.path(), &mut rng).unwrap();
        assert_eq!(
            directory.path().file_name().unwrap(),
            "test-00000000000000030000000000000004"
        );
        assert_eq!(rng.calls, 4);

        let not_a_directory = parent.path().join("regular-file");
        fs::write(&not_a_directory, b"not a directory").unwrap();
        let expected_error = fs::create_dir(not_a_directory.join("direct-attempt")).unwrap_err();
        assert_ne!(expected_error.kind(), io::ErrorKind::AlreadyExists);
        let mut rng = SequenceRng {
            values: vec![5, 6].into_iter(),
            calls: 0,
        };
        assert_eq!(
            TempDir::create_with_rng("test-".as_ref(), &not_a_directory, &mut rng)
                .unwrap_err()
                .kind(),
            expected_error.kind()
        );
        assert_eq!(rng.calls, 2);
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
        let directory = TempDir::create_sync(path.clone()).unwrap();
        assert_eq!(directory.path(), path);
        fs::create_dir(path.join("nested")).unwrap();
        fs::write(path.join("nested/artifact"), b"temporary").unwrap();
        TempDir::create_sync(path.clone()).unwrap_err();

        #[cfg(unix)]
        {
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
        TempDir::create_sync(first.clone())
            .unwrap()
            .close_sync()
            .unwrap();
        assert!(!first.exists());

        let second = parent.path().join("second");
        let directory = TempDir::create_sync(second.clone()).unwrap();
        fs::remove_dir(&second).unwrap();
        directory.close_sync().unwrap();

        let replaced = parent.path().join("replaced-by-file");
        let directory = TempDir::create_sync(replaced.clone()).unwrap();
        fs::remove_dir(&replaced).unwrap();
        fs::write(&replaced, b"not a directory").unwrap();
        assert_ne!(
            directory.close_sync().unwrap_err().kind(),
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
        let root = tempdir().unwrap();
        let path = root.path().join("secret.txt");
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
            .open_sync(&path)
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
