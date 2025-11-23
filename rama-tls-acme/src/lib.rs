//! Provides types and logic for interacting with an ACME-compliant server, or to implement
//! an ACME server directly.
//!
//! The **A**utomatic **C**ertificate **M**anagement **E**nvironment (ACME) protocol
//! is a communications protocol for automating interactions between certificate
//! authorities and their users' web servers.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

pub mod proto;

mod client;
#[doc(inline)]
pub use client::{Account, AcmeClient, AcmeProvider, ClientError, Order};
