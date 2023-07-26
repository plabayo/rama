//! Provides the Tcp transport server functionality
//! for Rama, which at the very least will be used
//! as the entrypoint of pretty much any Rama server.

pub mod error;
pub mod factory;

mod listener;
pub use listener::*;
