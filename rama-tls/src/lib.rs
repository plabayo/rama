//! rama TLS-agnostic types and utilities.
//!
//! The TLS-implementation-agnostic vocabulary (protocol versions, cipher suites,
//! ALPN, client/server config, `ClientHello`, fingerprints, keylog, …) shared by
//! the backend crates (`rama-tls-boring` / `rama-tls-rustls`).
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

use std::borrow::Cow;

use rama_core::extensions::Extension;
use rama_utils::collections::smallvec::{SmallVec, smallvec};

mod enums;
pub use enums::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm,
    ECPointFormat, ExtensionId, ProtocolVersion, SignatureScheme, SupportedGroup,
};

pub mod client;
pub mod fingerprint;
pub mod keylog;
pub mod server;

#[cfg(feature = "http")]
mod http;

#[cfg(feature = "dial9")]
mod dial9;

/// ALPN protocols to offer.
#[derive(Clone, Debug, Extension)]
#[extension(tags(tls))]
pub struct TlsAlpn(pub SmallVec<[ApplicationProtocol; 2]>);

impl TlsAlpn {
    /// Offer HTTP/2 and HTTP/1.1.
    #[must_use]
    pub fn http_auto() -> Self {
        Self(smallvec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ])
    }

    /// Offer HTTP/1.1 only.
    #[must_use]
    pub fn http_1() -> Self {
        Self(smallvec![ApplicationProtocol::HTTP_11])
    }

    /// Offer HTTP/2 only.
    #[must_use]
    pub fn http_2() -> Self {
        Self(smallvec![ApplicationProtocol::HTTP_2])
    }
}

/// Keylog intent (e.g. `SSLKEYLOGFILE`) for the connection.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsKeyLog(pub KeyLogIntent);

/// Supported protocol versions, as a list (backends derive min/max as needed,
/// preserving any GREASE entries in the wire list).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsSupportedVersions(pub Vec<ProtocolVersion>);

#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
/// Context information that can be provided by `tls` connectors,
/// to configure the connection in function on an tls tunnel.
pub struct TlsTunnel {
    /// The server name to use for the connection.
    pub sni: Option<rama_net::address::Host>,
}

#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(tls))]
/// Metadata that can be added to the [`Extensions`]
/// of a transport layer to signal that the transport is secure.
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct SecureTransport {
    client_hello: Option<client::ClientHello>,
}

impl SecureTransport {
    /// Create a [`SecureTransport`] with a [`ClientHello`]
    /// attached to it, containing the client hello info
    /// used to establish this secure transport.
    ///
    /// [`ClientHello`]: crate::client::ClientHello
    #[must_use]
    pub fn with_client_hello(hello: client::ClientHello) -> Self {
        Self {
            client_hello: Some(hello),
        }
    }

    /// Return the [`ClientHello`] used to establish this secure transport,
    /// only available if the tls service stored it.
    ///
    /// [`ClientHello`]: crate::client::ClientHello
    #[must_use]
    pub fn client_hello(&self) -> Option<&client::ClientHello> {
        self.client_hello.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
/// Intent for a (tls) keylogger to be used.
///
/// Applicable to both a client- and server- config. Consumers (the
/// boring / rustls integrations) resolve this into a concrete sink
/// via [`keylog::open_intent_sink`].
pub enum KeyLogIntent {
    #[default]
    /// `SSLKEYLOGFILE` env var: if set, log to that file.
    Environment,
    /// Keylog explicitly disabled.
    Disabled,
    /// Log to the given file path (append).
    File(String),
    /// Use the supplied sink as-is. Lets callers plug in a rotating
    /// sink, a toggle wrapper, an in-memory capture, etc., without
    /// the consumer needing to know which.
    Custom(std::sync::Arc<dyn keylog::KeyLogSink>),
}

impl KeyLogIntent {
    /// `SSLKEYLOGFILE` env value, if set.
    #[must_use]
    pub fn env_file_path() -> Option<String> {
        std::env::var("SSLKEYLOGFILE").ok()
    }

    /// File path for the [`File`] and [`Environment`] variants;
    /// `None` for [`Disabled`] and [`Custom`] (no path to surface).
    ///
    /// [`File`]: Self::File
    /// [`Environment`]: Self::Environment
    /// [`Disabled`]: Self::Disabled
    /// [`Custom`]: Self::Custom
    #[must_use]
    pub fn file_path(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::Disabled | Self::Custom(_) => None,
            Self::Environment => Self::env_file_path().map(Into::into),
            Self::File(keylog_filename) => Some(keylog_filename.into()),
        }
    }
}
