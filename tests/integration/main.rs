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

#[cfg(all(
    feature = "http-full",
    feature = "boring",
    feature = "ua",
    feature = "quic",
    feature = "test-utils"
))]
mod ua_h3_settings;

#[cfg(all(
    feature = "http-full",
    feature = "quic",
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    )
))]
mod h3_early_data;

#[cfg(all(feature = "http-full", feature = "boring"))]
mod http_version_compat;

#[cfg(all(feature = "http-full", feature = "boring", feature = "quic"))]
mod masque;
