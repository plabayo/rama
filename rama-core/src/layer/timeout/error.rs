//! Default Error type for Timeout middleware.

use std::{error, fmt, time::Duration};

/// The timeout elapsed.
#[derive(Debug, Clone, Default)]
pub struct Elapsed(Option<Duration>);

impl Elapsed {
    /// Construct a new elapsed error
    pub(crate) const fn new(duration: Option<Duration>) -> Self {
        Self(duration)
    }
}

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(dur) => write!(f, "timeout elapsed after {dur:?}"),
            None => write!(f, "timeout without duration"),
        }
    }
}

impl error::Error for Elapsed {}
