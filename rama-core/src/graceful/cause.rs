use std::{error::Error, fmt, sync::Arc};

use crate::error::BoxError;

/// Why a [`Scope`] entered its graceful or hard phase.
///
/// A scope cancelled through its parent reports the parent's cause.
///
/// [`Scope`]: super::Scope
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Cause {
    /// A signal future attached to the scope completed.
    Signal,
    /// A deadline or timeout attached to the scope was reached.
    Deadline,
    /// The grace period after the graceful phase elapsed.
    GraceElapsed,
    /// Cancelled by the code that owns the scope.
    Owner,
    /// Cancelled by code, with a static reason.
    Reason(&'static str),
    /// Cancelled by code because of an error.
    Error(Arc<dyn Error + Send + Sync + 'static>),
}

impl Cause {
    /// Create a [`Cause::Error`] from any error.
    pub fn error(error: impl Into<BoxError>) -> Self {
        Self::Error(Arc::from(error.into()))
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal => f.write_str("signal"),
            Self::Deadline => f.write_str("deadline reached"),
            Self::GraceElapsed => f.write_str("grace period elapsed"),
            Self::Owner => f.write_str("cancelled by owner"),
            Self::Reason(reason) => f.write_str(reason),
            Self::Error(error) => write!(f, "error: {error}"),
        }
    }
}
