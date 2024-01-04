//! Runtime utilities used by Rama.
//!
//! The Executor is used to spawn futures, from within a service.
//! This is also for example what happens by the built in bttp
//! client and servers, when serving protocols such as h2 and h3.

mod executor;
pub use executor::Executor;
