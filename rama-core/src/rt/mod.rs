//! Runtime utilities used by Rama.
//!
//! The Executor is used to spawn futures, from within a service.
//! This is also for example what happens by the built in http
//! client and servers, when serving protocols such as h2 and h3.
//!
//! See the [`Executor`] for more information on how to use it.
//!
//! [`Executor`]: crate::rt::Executor

mod executor;
#[doc(inline)]
pub use executor::Executor;

pub mod future;
