use core::{convert::Infallible, fmt};

use crate::BoxError;

/// Rarely will you need [`OpaqueError`],
/// it can however be a useful last-resort in case you
/// get weird higher-rank Lifetime issues...
///
/// Such lifetime issues often arise when using [`BoxError`]
/// directly as the error for a `BoxService`.
pub struct OpaqueError(BoxError);

impl OpaqueError {
    #[inline(always)]
    pub(super) fn from_box_error(e: impl Into<BoxError>) -> Self {
        Self(e.into())
    }

    #[inline(always)]
    /// Create an opaque error from a static str.
    ///
    /// Use this instead of `"msg".context()` or
    /// some other method that turns it into a BoxError...
    /// Because the std rust library turns this into a `String` otherwise...
    pub fn from_static_str(e: &'static str) -> Self {
        Self(Box::new(StaticStrError(e)))
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

impl core::error::Error for OpaqueError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl From<Infallible> for OpaqueError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

#[derive(Clone, Copy)]
struct StaticStrError(&'static str);

impl fmt::Debug for StaticStrError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for StaticStrError {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for StaticStrError {}
