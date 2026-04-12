//! Shutdown management for graceful shutdown of async-first applications.

use crate::extensions::Extension;

#[doc(inline)]
pub use ::tokio_graceful::{
    Shutdown, ShutdownBuilder, ShutdownGuard, WeakShutdownGuard, default_signal,
};

// TODO @glendc, remove usage from this in TransparentProxyEngine
impl Extension for ShutdownGuard {}
