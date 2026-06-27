use super::{DirEntry, File};
use crate::fs::{safe_create_dir_all_in_sync, safe_write_in_sync};
use std::path::Path;

/// A directory.
#[derive(Debug, Clone, PartialEq)]
pub struct Dir<'a> {
    path: &'a str,
    entries: &'a [DirEntry<'a>],
}

impl<'a> Dir<'a> {
    /// Create a new [`Dir`].
    #[must_use]
    pub const fn new(path: &'a str, entries: &'a [DirEntry<'a>]) -> Self {
        Dir { path, entries }
    }

    /// The full path for this [`Dir`], relative to the directory passed to
    /// [`include_dir`](super::include_dir).
    #[must_use]
    pub fn path(&self) -> &'a Path {
        Path::new(self.path)
    }

    /// The entries within this [`Dir`].
    #[must_use]
    pub const fn entries(&self) -> &'a [DirEntry<'a>] {
        self.entries
    }

    /// Get a list of the files in this directory.
    pub fn files(&self) -> impl Iterator<Item = &'a File<'a>> + 'a {
        self.entries().iter().filter_map(DirEntry::as_file)
    }

    /// Get a list of the sub-directories inside this directory.
    pub fn dirs(&self) -> impl Iterator<Item = &'a Dir<'a>> + 'a {
        self.entries().iter().filter_map(DirEntry::as_dir)
    }

    /// Recursively search for a [`DirEntry`] with a particular path.
    pub fn get_entry<S: AsRef<Path>>(&self, path: S) -> Option<&'a DirEntry<'a>> {
        let path = path.as_ref();

        for entry in self.entries() {
            if entry.path() == path {
                return Some(entry);
            }

            if let DirEntry::Dir(d) = entry
                && let Some(nested) = d.get_entry(path)
            {
                return Some(nested);
            }
        }

        None
    }

    /// Look up a file by name.
    pub fn get_file<S: AsRef<Path>>(&self, path: S) -> Option<&'a File<'a>> {
        self.get_entry(path).and_then(DirEntry::as_file)
    }

    /// Look up a dir by name.
    pub fn get_dir<S: AsRef<Path>>(&self, path: S) -> Option<&'a Self> {
        self.get_entry(path).and_then(DirEntry::as_dir)
    }

    /// Does this directory contain `path`?
    pub fn contains<S: AsRef<Path>>(&self, path: S) -> bool {
        self.get_entry(path).is_some()
    }

    /// Create directories and extract all files to real filesystem.
    /// Creates parent directories of `path` if they do not already exist.
    /// Fails if some files already exist.
    /// In case of error, partially extracted directory may remain on the filesystem.
    ///
    /// # Security
    ///
    /// This method validates that all entry paths are relative, do not escape
    /// the extraction directory through path traversal, and do not follow
    /// symlinks outside the extraction directory.
    pub fn extract<S: AsRef<Path>>(&self, base_path: S) -> std::io::Result<()> {
        let base_path = base_path.as_ref();
        std::fs::create_dir_all(base_path)?;
        self.extract_entries(base_path)
    }

    fn extract_entries(&self, base_path: &Path) -> std::io::Result<()> {
        for entry in self.entries() {
            match entry {
                DirEntry::Dir(d) => {
                    safe_create_dir_all_in_sync(base_path, d.path())?;
                    d.extract_entries(base_path)?;
                }
                DirEntry::File(f) => {
                    safe_write_in_sync(base_path, f.path(), f.contents())?;
                }
            }
        }

        Ok(())
    }
}
