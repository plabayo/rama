use std::fmt;

use crate::value::JsValue;

/// Error returned by all fallible operations in this crate.
///
/// A [`JsError`] either originates from the script side
/// (e.g. [`JsErrorKind::Throw`], [`JsErrorKind::Parse`]) or from the
/// host side (e.g. [`JsErrorKind::Conversion`]). Host functions can
/// return a [`JsError`] to throw an error into the running script.
pub struct JsError {
    kind: JsErrorKind,
    message: Box<str>,
    thrown: Option<JsValue>,
}

/// The kind of a [`JsError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JsErrorKind {
    /// script could not be parsed
    Parse,
    /// script threw an error (or a host function returned one)
    Throw,
    /// a configured runtime limit was exceeded
    LimitExceeded,
    /// a value could not be converted across the js boundary
    Conversion,
    /// a global (function) with the given name does not exist
    NotFound,
    /// runtime could not be set up or is no longer available
    Setup,
    /// a job did not complete within the configured timeout
    Timeout,
}

impl JsError {
    pub(crate) fn new(kind: JsErrorKind, message: impl Into<Box<str>>) -> Self {
        Self {
            kind,
            message: message.into(),
            thrown: None,
        }
    }

    pub(crate) fn with_thrown(mut self, thrown: JsValue) -> Self {
        self.thrown = Some(thrown);
        self
    }

    /// Create a new [`JsErrorKind::Conversion`] error.
    ///
    /// This is the error to return from custom
    /// [`JsArg`][crate::JsArg] implementations.
    pub fn conversion(message: impl Into<Box<str>>) -> Self {
        Self::new(JsErrorKind::Conversion, message)
    }

    /// Create a new [`JsErrorKind::Throw`] error.
    ///
    /// When returned from a host function it is
    /// thrown as an error inside the running script.
    pub fn throw(message: impl Into<Box<str>>) -> Self {
        Self::new(JsErrorKind::Throw, message)
    }

    /// The kind of this error.
    #[must_use]
    pub fn kind(&self) -> JsErrorKind {
        self.kind
    }

    /// The human-readable error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The thrown script value, if this error
    /// carries one (only for [`JsErrorKind::Throw`]).
    #[must_use]
    pub fn thrown(&self) -> Option<&JsValue> {
        self.thrown.as_ref()
    }
}

impl fmt::Debug for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("JsError");
        dbg.field("kind", &self.kind)
            .field("message", &self.message);
        if let Some(thrown) = &self.thrown {
            dbg.field("thrown", thrown);
        }
        dbg.finish()
    }
}

impl fmt::Display for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "js error ({:?}): {}", self.kind, self.message)
    }
}

impl std::error::Error for JsError {}
