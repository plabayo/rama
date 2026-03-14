//! Boring(ssl) proxy support for Rama.
//!
//! While a proxy can be seen as a combination of a server and a client,
//! this module provides explicit support for certain proxy flows.
//!
//! For example MITM support found in this module
//! is there to facilitate an explicit MITM flow such that
//! high level you have the following handshake:
//!
//! ```plain
//! client | --- client hello (A) ----> | proxy |                               | server |
//!        |                            |       | ------- client hello (B) ---> |        |
//!        |                            |       | <------ server hello (C) ---- |        |
//!        | <--- server hello (D) ---- |       |                               |        |
//! ```
//!
//! Where:
//!
//! 1. Client Hello of (B) is based on Client Hello of (A);
//! 2. Server config of (C) is based on server hello of (B);
//! 3. Issued cert for (C) is based on a mirror from the server cert used in (B).
//!
//! NOTE that (1) requires that you provide the CH converted
//! as connector data to the [`TlsMitmRelay`] prior to handshake (relay).
//! In other words, even though it is recommended, it is optional.

mod mitm;
pub use self::mitm::issuer as cert_issuer;
pub use self::mitm::{TlsMitmRelay, TlsMitmRelayService};
