//! Keylog facility used by any tls implementation
//! supported by rama, and which can be used for your owns as well.
//!
//! Center to thsi module is the `KeyLogger` which is a wrapper around
//! a FS file

use parking_lot::RwLock;
use rama_core::error::{ErrorContext, OpaqueError};
use std::{
    collections::{hash_map::Entry, HashMap},
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::OnceLock,
};

/// Get a key log file handle for the given path
/// only one file handle will be opened per unique path String.
///
/// # To be unique or ditto
///
/// Paths are case-sensitive by default for rama, as utf-8 compatible.
/// Normalize yourself prior to passing a path to this function if you're concerned.
pub fn new_key_log_file_handle(path: String) -> Result<KeyLogFileHandle, OpaqueError> {
    let path = std::fs::canonicalize(path).context("canonicalize keylog path")?;

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

fn try_init_key_log_file_handle(path: PathBuf) -> Result<KeyLogFileHandle, OpaqueError> {
    tracing::trace!(
        file = ?path,
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
            file = ?path_name,
            "KeyLogFileHandle[rx]: receiver task up and running",
        );
        while let Ok(line) = rx.recv() {
            if let Err(err) = file.write_all(line.as_bytes()) {
                tracing::error!(
                    file = ?path_name,
                    error = %err,
                    "KeyLogFileHandle[rx]: failed to write file",
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
                file = ?self.path,
                error = %err,
                "KeyLogFileHandle[tx]: failed to send log line for writing",
            );
        }
    }
}
