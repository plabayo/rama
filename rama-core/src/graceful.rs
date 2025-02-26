//! Shutdown management for graceful shutdown of async-first applications.

#[doc(inline)]
pub use ::tokio_graceful::{
    Shutdown, ShutdownBuilder, ShutdownGuard, WeakShutdownGuard, default_signal,
};
