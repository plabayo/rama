//! Rama Runtime
//!
//! This crate provides a runtime for Rama applications.
//!
//! For now only Tokio is implemented and supported.
//! There is no plan to support other runtimes.
//! If you want to use other runtimes, you can
//! provide feedback, input and motivation at
//! <https://github.com/plabayo/rama/issues/6.
//!
//! This crate serves to keep track of what
//! runtime features we use and might wish to provide.
//! It is usually not used as a crate directly but instead
//! is aliased and used typically through `rama::rt`.
//!
//! Note that crates like Hyper and Tower do rely on `tokio::sync`
//! for some parts. While this is independent from the `tokio` runtime,
//! it does mean that users of `rama-rt` will pull in the full tokio library
//! even if we would support another runtime that they use.
//! This is on purpose as there are some optimizations that a runtime like tokio
//! can do that are not possible cross runtimes due to limitations of the choices
//! made by Rust regarding the entire async story.

mod rt_tokio;

pub use rt_tokio::{graceful, io, net, sync, task, time, tls};

pub use rt_tokio::{select, spawn};

pub use rt_tokio::pin;

pub use rt_tokio::{Builder, Runtime};

pub use rt_tokio::test as test_util;
