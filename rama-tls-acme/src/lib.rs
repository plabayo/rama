//! Provides types and logic for interacting with an ACME-compliant server, or to implement
//! an ACME server directly.
//!
//! The **A**utomatic **C**ertificate **M**anagement **E**nvironment (ACME) protocol
//! is a communications protocol for automating interactions between certificate
//! authorities and their users' web servers.

pub mod proto;

mod client;
#[doc(inline)]
pub use client::{Account, AcmeClient, AcmeProvider, ClientError, Order};
