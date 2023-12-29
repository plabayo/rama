//! Shutdown management for graceful shutdown of async-first applications.

pub use tokio_graceful::{Shutdown, ShutdownGuard, WeakShutdownGuard};
