//! Boring(ssl) server support for Rama.
//!
//! This module provides a [`TlsAcceptorLayer`] to accept TLS connections and a [`TlsAcceptorService`] to handle them.
//!
//! # Examples
//!
//! See the [Examples Directory](https://github.com/plabayo/rama/tree/main/examples):
//!
//! - [/examples/tls_boring_termination.rs](https://github.com/plabayo/rama/tree/main/examples/tls_boring_termination.rs):
//!   Spawns a mini handmade http server, as well as a TLS termination proxy, forwarding the
//!   plain text stream to the first.

mod acceptor_data;
#[doc(inline)]
pub use acceptor_data::TlsAcceptorData;

mod service;
#[doc(inline)]
pub use service::TlsAcceptorService;

mod layer;
#[doc(inline)]
pub use layer::TlsAcceptorLayer;
