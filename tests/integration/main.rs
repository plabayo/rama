#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::dbg_macro,
    clippy::unreachable,
    clippy::allow_attributes,
    reason = "integration tests: panic-on-error and print-for-output are the standard patterns for harnesses"
)]

mod cli;
mod examples;

#[cfg(all(feature = "http-full", feature = "boring", feature = "ua"))]
mod ua_emulation;

#[cfg(all(feature = "http-full", feature = "boring"))]
mod client;
