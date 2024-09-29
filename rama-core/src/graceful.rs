//! Shutdown management for graceful shutdown of async-first applications.

#[doc(inline)]
pub use ::tokio_graceful::{
    default_signal, Shutdown, ShutdownBuilder, ShutdownGuard, WeakShutdownGuard,
};
