use std::{fmt, time::Duration};

use super::cause::Cause;

#[cfg(doc)]
use super::Scope;

/// Returned by [`Scope::join`] when the scope reached its hard phase before it drained.
#[derive(Debug, Clone)]
pub struct JoinAborted {
    elapsed: Duration,
    cause: Option<Cause>,
}

impl JoinAborted {
    pub(super) fn new(elapsed: Duration, cause: Option<Cause>) -> Self {
        Self { elapsed, cause }
    }

    /// Time between the call to [`Scope::join`] and the hard phase.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Why the scope was aborted.
    #[must_use]
    pub fn cause(&self) -> Option<&Cause> {
        self.cause.as_ref()
    }
}

impl fmt::Display for JoinAborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "join aborted after {:?}", self.elapsed)?;
        if let Some(cause) = &self.cause {
            write!(f, ": {cause}")?;
        }
        Ok(())
    }
}

impl std::error::Error for JoinAborted {}
