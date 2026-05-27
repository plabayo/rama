#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::dbg_macro,
    clippy::allow_attributes,
    reason = "integration test (turmoil): panic-on-error and print-for-output are the standard patterns for harnesses"
)]

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
pub mod http;

#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
pub mod types;

#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
pub mod stream;
