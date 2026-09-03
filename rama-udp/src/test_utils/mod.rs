//! Utilities for testing datagram protocols without operating-system sockets.

mod memory;
pub use memory::{MemoryDatagramSender, MemoryDatagramSocket};
