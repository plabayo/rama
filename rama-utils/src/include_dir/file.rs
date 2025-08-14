use super::Metadata;
use std::{
    fmt::{self, Debug, Formatter},
    path::Path,
};

/// A file with its contents stored in a `&'static [u8]`.
#[derive(Clone, PartialEq, Eq)]
pub struct File<'a> {
    path: &'a str,
    contents: &'a [u8],
    metadata: Option<super::Metadata>,
}

impl<'a> File<'a> {
    /// Create a new [`File`].
    #[must_use]
    pub const fn new(path: &'a str, contents: &'a [u8]) -> Self {
        File {
            path,
            contents,
            metadata: None,
        }
    }

    /// The full path for this [`File`], relative to the directory passed to
    /// [`include_dir`](super::include_dir).
    #[must_use]
    pub fn path(&self) -> &'a Path {
        Path::new(self.path)
    }

    /// The file's raw contents.
    #[must_use]
    pub fn contents(&self) -> &[u8] {
        self.contents
    }

    /// The file's contents interpreted as a string.
    #[must_use]
    pub fn contents_utf8(&self) -> Option<&str> {
        std::str::from_utf8(self.contents()).ok()
    }
}

impl<'a> File<'a> {
    /// Set the [`Metadata`] associated with a [`File`].
    #[must_use]
    pub const fn with_metadata(self, metadata: Metadata) -> Self {
        let File { path, contents, .. } = self;

        File {
            path,
            contents,
            metadata: Some(metadata),
        }
    }

    /// Get the [`File`]'s [`Metadata`] if available.
    #[must_use]
    pub fn metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }
}

impl<'a> Debug for File<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let File {
            path,
            contents,
            metadata,
        } = self;

        let mut d = f.debug_struct("File");

        d.field("path", path)
            .field("contents", &format!("<{} bytes>", contents.len()));
        d.field("metadata", metadata);

        d.finish()
    }
}
