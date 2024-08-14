//! Default Error type for Timeout middleware.

use std::{error, fmt, time::Duration};

/// The timeout elapsed.
#[derive(Debug, Clone, Default)]
pub struct Elapsed(Duration);

impl Elapsed {
    /// Construct a new elapsed error
    pub(crate) const fn new(duration: Duration) -> Self {
        Self(duration)
    }
}

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "timeout elapsed after {:?}", self.0)
    }
}

impl error::Error for Elapsed {}
