use crate::rustls::dep::rustls::KeyLog;
use rama_core::error::{ErrorContext, OpaqueError};
use std::fmt::{Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use tracing::{trace, warn};

// Internal mutable state for KeyLogFile
struct KeyLogFileInner {
    file: File,
    buf: Vec<u8>,
}

impl KeyLogFileInner {
    fn new(path: impl AsRef<Path>) -> Result<Self, OpaqueError> {
        let path_pref = path.as_ref();
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path_pref)
            .with_context(|| format!("create key log file {path_pref:?}"))?;
        Ok(Self {
            file,
            buf: Vec::new(),
        })
    }

    fn try_write(&mut self, label: &str, client_random: &[u8], secret: &[u8]) -> io::Result<()> {
        self.buf.truncate(0);
        write!(self.buf, "{} ", label)?;
        for b in client_random.iter() {
            write!(self.buf, "{:02x}", b)?;
        }
        write!(self.buf, " ")?;
        for b in secret.iter() {
            write!(self.buf, "{:02x}", b)?;
        }
        writeln!(self.buf)?;
        self.file.write_all(&self.buf)
    }
}

impl Debug for KeyLogFileInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyLogFileInner")
            // Note: we omit self.buf deliberately as it may contain key data.
            .field("file", &self.file)
            .finish()
    }
}

/// [`KeyLog`] implementation that opens a file whose name is
/// given by the `SSLKEYLOGFILE` environment variable, and writes
/// keys into it.
///
/// If `SSLKEYLOGFILE` is not set, this does nothing.
///
/// If such a file cannot be opened, or cannot be written then
/// this does nothing but logs errors at warning-level.
pub(super) struct KeyLogFile(Mutex<KeyLogFileInner>);

impl KeyLogFile {
    /// Makes a new `KeyLogFile`.
    pub(super) fn new(path: impl AsRef<Path>) -> Result<Self, OpaqueError> {
        let path = path.as_ref();
        trace!(?path, "rustls: open keylog file for debug purposes");
        Ok(Self(Mutex::new(KeyLogFileInner::new(path)?)))
    }
}

impl KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        match self
            .0
            .lock()
            .unwrap()
            .try_write(label, client_random, secret)
        {
            Ok(()) => {}
            Err(e) => {
                warn!("error writing to key log file: {}", e);
            }
        }
    }
}

impl Debug for KeyLogFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self.0.try_lock() {
            Ok(key_log_file) => write!(f, "{:?}", key_log_file),
            Err(_) => write!(f, "KeyLogFile {{ <locked> }}"),
        }
    }
}
