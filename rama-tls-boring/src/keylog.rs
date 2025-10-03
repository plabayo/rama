//! Keylog facility used by any tls implementation
//! supported by rama, and which can be used for your owns as well.
//!
//! Center to this module is the `KeyLogger` which is a wrapper around
//! a FS file

use ahash::HashMap;
use parking_lot::RwLock;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_core::telemetry::tracing;
use std::{
    collections::hash_map::Entry,
    fs::OpenOptions,
    io::Write,
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

/// Get a key log file handle for the given path
/// only one file handle will be opened per unique path String.
///
/// # To be unique or ditto
///
/// Paths are case-sensitive by default for rama, as utf-8 compatible.
/// Normalize yourself prior to passing a path to this function if you're concerned.
pub fn new_key_log_file_handle(path: &str) -> Result<KeyLogFileHandle, OpaqueError> {
    let path: PathBuf = path
        .parse()
        .with_context(|| format!("parse path str as Path: {path}"))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir(s) at {parent:?} for key log file"))?;
    }

    let path = normalize_path(&path);

    let mapping = GLOBAL_KEY_LOG_FILE_MAPPING.get_or_init(Default::default);
    if let Some(handle) = mapping.read().get(&path).cloned() {
        return Ok(handle);
    }
    let mut mut_mapping = mapping.write();
    match mut_mapping.entry(path.clone()) {
        Entry::Occupied(entry) => Ok(entry.get().clone()),
        Entry::Vacant(entry) => {
            let handle = try_init_key_log_file_handle(path)?;
            entry.insert(handle.clone());
            Ok(handle)
        }
    }
}

// copied from
// <https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61>
#[must_use]
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

fn try_init_key_log_file_handle(path: PathBuf) -> Result<KeyLogFileHandle, OpaqueError> {
    tracing::trace!(
        file.path = ?path,
        "KeyLogFileHandle: try to create a new handle",
    );

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create parent dir(s) of key log file")?;
    }

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .with_context(|| format!("create key log file {path:?}"))?;

    let (tx, rx) = flume::unbounded::<String>();

    let path_name = path.clone();
    std::thread::spawn(move || {
        tracing::trace!(
            file.path = ?path_name,
            "KeyLogFileHandle[rx]: receiver task up and running",
        );
        while let Ok(line) = rx.recv() {
            if let Err(err) = file.write_all(line.as_bytes()) {
                tracing::error!(
                    file.path = ?path_name,
                    "KeyLogFileHandle[rx]: failed to write file: {err:?}",
                );
            }
        }
    });

    Ok(KeyLogFileHandle { path, sender: tx })
}

static GLOBAL_KEY_LOG_FILE_MAPPING: OnceLock<RwLock<HashMap<PathBuf, KeyLogFileHandle>>> =
    OnceLock::new();

#[derive(Debug, Clone)]
/// Handle to a (tls) keylog file.
///
/// See [`new_key_log_file_handle`] for more info,
/// as that is the one creating it.
pub struct KeyLogFileHandle {
    path: PathBuf,
    sender: flume::Sender<String>,
}

impl KeyLogFileHandle {
    /// Write a line to the keylogger.
    pub fn write_log_line(&self, line: String) {
        if let Err(err) = self.sender.send(line) {
            tracing::error!(
                file.path = ?self.path,
                "KeyLogFileHandle[tx]: failed to send log line for writing: {err:?}",
            );
        }
    }
}
