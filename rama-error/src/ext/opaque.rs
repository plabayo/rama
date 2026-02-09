use std::fmt;

use crate::BoxError;

/// Rarely will you need [`OpaqueError`],
/// it can however be a useful last-resort in case you
/// get weird higher-rank Lifetime issues...
pub struct OpaqueError(BoxError);

impl OpaqueError {
    #[inline(always)]
    pub(super) fn from_box_error(e: impl Into<BoxError>) -> Self {
        Self(e.into())
    }
}

impl fmt::Debug for OpaqueError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for OpaqueError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for OpaqueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
