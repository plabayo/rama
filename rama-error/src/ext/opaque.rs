use core::{convert::Infallible, fmt, panic::Location};

use crate::{BoxError, std::Box};

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
    #[track_caller]
    /// Create an opaque error from a static str.
    ///
    /// Use this instead of `"msg".context()` or
    /// some other method that turns it into a BoxError...
    /// Because the std rust library turns this into a `String` otherwise...
    pub fn from_static_str(e: &'static str) -> Self {
        Self(Box::new(StaticStrError::new(e)))
    }

    #[inline(always)]
    /// Unwrap into the inner [`BoxError`].
    ///
    /// [`OpaqueError`] is a transparent [`BoxError`] wrapper, so this is free.
    /// This shadows the generic `into_box_error` added by `ErrorExt` trait.
    pub fn into_box_error(self) -> BoxError {
        self.0
    }
}

impl OpaqueError {
    pub(super) fn inner(&self) -> &(dyn core::error::Error + 'static) {
        self.0.as_ref()
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
    fn from(infallible: Infallible) -> Self {
        match infallible {}
    }
}

/// A bare static message: the smallest error this crate makes. The first context
/// added to it moves the message into a context node.
#[derive(Clone, Copy)]
pub(crate) struct StaticStrError {
    pub(crate) message: &'static str,
    pub(crate) location: &'static Location<'static>,
}

impl StaticStrError {
    #[inline(always)]
    #[track_caller]
    pub(crate) fn new(message: &'static str) -> Self {
        Self {
            message,
            location: Location::caller(),
        }
    }
}

impl fmt::Debug for StaticStrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticStrError")
            .field("message", &self.message)
            .field("location", &format_args!("{}", self.location))
            .finish()
    }
}

impl fmt::Display for StaticStrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)?;
        if f.alternate() {
            write!(f, "\n  at {}", self.location)?;
        }
        Ok(())
    }
}

impl core::error::Error for StaticStrError {}
