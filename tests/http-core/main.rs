#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::dbg_macro,
    clippy::allow_attributes,
    clippy::let_underscore_future,
    clippy::assertions_on_result_states,
    clippy::map_err_ignore,
    clippy::unreachable,
    clippy::unused_result_ok,
    reason = "vendored from upstream hyper test suite"
)]

#[cfg(feature = "http-full")]
mod h2;

#[macro_use]
#[cfg(feature = "http-full")]
mod support;

#[cfg(feature = "http-full")]
mod client;
#[cfg(feature = "http-full")]
mod h1_server;
#[cfg(feature = "http-full")]
mod integration;
#[cfg(feature = "http-full")]
mod server;

#[cfg(feature = "http-full")]
mod ready_on_poll_stream;
#[cfg(feature = "http-full")]
mod unbuffered_stream;

mod examples;
