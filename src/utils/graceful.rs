//! Shutdown management for graceful shutdown of async-first applications.

pub use tokio_graceful::{default_signal, Shutdown, ShutdownGuard, WeakShutdownGuard};
