//! rama common tls types
//!

use rama_utils::str::NonEmptyString;

mod enums;
pub use enums::{
    ApplicationProtocol, CipherSuite, CompressionAlgorithm, ECPointFormat, ExtensionId,
    ProtocolVersion, SignatureScheme, SupportedGroup,
};

pub mod client;
pub mod server;

#[derive(Debug, Clone)]
/// Context information that can be provided `https` connectors`,
/// to configure the connection in function on an https tunnel.
pub struct HttpsTunnel {
    /// The server name to use for the connection.
    pub server_host: crate::address::Host,
}

#[derive(Debug, Clone, Default)]
/// An [`Extensions`] value that can be added to the [`Context`]
/// of a transport layer to signal that the transport is secure.
///
/// [`Extensions`]: rama_core::context::Extensions
/// [`Context`]: rama_core::Context
pub struct SecureTransport {
    client_hello: Option<client::ClientHello>,
}

impl SecureTransport {
    /// Create a [`SecureTransport`] with a [`ClientHello`]
    /// attached to it, containing the client hello info
    /// used to establish this secure transport.
    pub fn with_client_hello(hello: client::ClientHello) -> Self {
        Self {
            client_hello: Some(hello),
        }
    }

    /// Return the [`ClientHello`] used to establish this secure transport,
    /// only available if the tls service stored it.
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
    /// By default no key logging is used.
    Disabled,
    /// Request a keys to be logged to the given file path.
    File(std::path::PathBuf),
}

#[derive(Debug, Clone)]
/// Implementation agnostic encoding of common data such
/// as certificates and keys.
pub enum DataEncoding {
    /// Distinguished Encoding Rules (DER) (binary)
    Der(Vec<u8>),
    /// Privacy Enhanced Mail (PEM) (plain text)
    Pem(NonEmptyString),
}
