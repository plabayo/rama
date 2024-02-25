//! Runtime utilities used by Rama.
//!
//! The Executor is used to spawn futures, from within a service.
//! This is also for example what happens by the built in http
//! client and servers, when serving protocols such as h2 and h3.
//!
//! See the [`Executor`] for more information on how to use it.
//! It is used in [`crate::http::server::service::HttpServer`] and is also
//! internal to [`crate::service::Context`] to drive the creation of tasks.
//!
//! [`Executor`]: crate::rt::Executor

mod executor;
pub use executor::Executor;
