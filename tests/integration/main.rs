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

#[cfg(all(feature = "http-full", feature = "boring", feature = "ua"))]
mod ua_emulation;

#[cfg(all(feature = "http-full", feature = "boring"))]
mod client;

#[cfg(all(feature = "http-full", feature = "rustls", feature = "aws-lc"))]
mod tls_close_notify;

#[cfg(all(feature = "dns", feature = "tcp"))]
mod localhost;

#[cfg(all(feature = "boring", feature = "tcp"))]
mod posted_recv_tls;

#[cfg(all(
    target_vendor = "apple",
    feature = "net-apple-networkextension",
    feature = "http-full"
))]
mod apple_http_linger;
