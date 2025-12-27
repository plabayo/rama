//! Batteries included server and client.
//!
//! This module provides a set of batteries included, fully featured and
//! fast set of HTTP/2 server and client's. These components each provide a
//! `rustls` tls backend when the respective feature flag is enabled, and
//! provides builders to configure transport behavior.
//!
//! # Features
//!
//! - TLS support TODO[TLS]
//! - Load balancing // TOOD: confirm
//! - Timeouts
//! - Concurrency Limits
//! - Rate limiting

#[cfg(feature = "transport")]
pub mod channel;
#[cfg(feature = "transport")]
pub mod server;

mod error;
mod service;
// TOOD[TLS]
// #[cfg(feature = "_tls-any")]
// mod tls;

#[doc(inline)]
#[cfg(feature = "transport")]
pub use self::channel::{Channel, Endpoint};
pub use self::error::Error;
#[doc(inline)]
#[cfg(feature = "transport")]
pub use self::server::Server;

// TOOD[TLS}
// #[cfg(feature = "_tls-any")]
// pub use self::tls::Certificate;
pub use rama_http_types::{Uri, body::Body};
// TOOD[TLS}
// #[cfg(feature = "_tls-any")]
// pub use tokio_rustls::rustls::pki_types::CertificateDer;

// TOOD[TLS}
// #[cfg(all(feature = "transport", feature = "_tls-any"))]
// pub use self::channel::ClientTlsConfig;
// #[cfg(all(feature = "transport", feature = "_tls-any"))]
// pub use self::server::ServerTlsConfig;
// #[cfg(feature = "_tls-any")]
// pub use self::tls::Identity;
