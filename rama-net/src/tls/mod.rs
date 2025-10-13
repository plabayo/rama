//! rama common tls types
//!

use std::borrow::Cow;

use rama_utils::str::NonEmptyString;

mod enums;
pub use enums::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm,
    ECPointFormat, ExtensionId, ProtocolVersion, SignatureScheme, SupportedGroup,
};

pub mod client;
pub mod keylog;
pub mod server;

#[derive(Debug, Clone)]
/// Context information that can be provided by `tls` connectors`,
/// to configure the connection in function on an tls tunnel.
pub struct TlsTunnel {
    /// The server name to use for the connection.
    pub server_host: crate::address::Host,
}

#[derive(Debug, Clone, Default)]
/// An [`Extensions`] value that can be added to the [`Context`]
/// of a transport layer to signal that the transport is secure.
///
/// [`Extensions`]: rama_core::extensions::Extensions
/// [`Context`]: rama_core::Context
pub struct SecureTransport {
    client_hello: Option<client::ClientHello>,
}

impl SecureTransport {
    /// Create a [`SecureTransport`] with a [`ClientHello`]
    /// attached to it, containing the client hello info
    /// used to establish this secure transport.
    #[must_use]
    pub fn with_client_hello(hello: client::ClientHello) -> Self {
        Self {
            client_hello: Some(hello),
        }
    }

    /// Return the [`ClientHello`] used to establish this secure transport,
    /// only available if the tls service stored it.
    #[must_use]
    pub fn client_hello(&self) -> Option<&client::ClientHello> {
        self.client_hello.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
/// Intent for a (tls) keylogger to be used.
///
/// Applicable to both a client- and server- config.
pub enum KeyLogIntent {
    #[default]
    /// By default `SSLKEYLOGFILE` env variable is respected
    /// as the path to key log to, if defined
    Environment,
    /// You can choose to disable the key logging explicitly
    Disabled,
    /// Request a keys to be logged to the given file path.
    File(String),
}

impl KeyLogIntent {
    /// Return the [`Default`] "SSLKEYLOGFILE" env-based file path as a [`String`].
    #[must_use]
    pub fn env_file_path() -> Option<String> {
        std::env::var("SSLKEYLOGFILE").ok()
    }

    /// get the file path if intended
    #[must_use]
    pub fn file_path(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::Disabled => None,
            Self::Environment => Self::env_file_path().map(Into::into),
            Self::File(keylog_filename) => Some(keylog_filename.into()),
        }
    }

    /// consume itself into the file path if intended
    #[must_use]
    pub fn into_file_path(self) -> Option<String> {
        match self {
            Self::Disabled => None,
            Self::Environment => std::env::var("SSLKEYLOGFILE").ok(),
            Self::File(keylog_filename) => Some(keylog_filename),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Implementation agnostic encoding of common data such
/// as certificates and keys.
pub enum DataEncoding {
    /// Distinguished Encoding Rules (DER) (binary)
    Der(Vec<u8>),
    /// Same as [`DataEncoding::Der`], but multiple
    DerStack(Vec<Vec<u8>>),
    /// Privacy Enhanced Mail (PEM) (plain text)
    Pem(NonEmptyString),
}
