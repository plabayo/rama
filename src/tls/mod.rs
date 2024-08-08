//! TLS module for Rama.

mod enums;
use client::ClientHello;
pub use enums::{
    ApplicationProtocol, CipherSuite, ECPointFormat, ExtensionId, ProtocolVersion, SignatureScheme,
    SupportedGroup,
};

pub mod client;
pub mod rustls;

#[cfg(feature = "boring")]
pub mod boring;

#[derive(Debug, Clone)]
/// Context information that can be provided `https` connectors`,
/// to configure the connection in function on an https tunnel.
pub struct HttpsTunnel {
    /// The server name to use for the connection.
    pub server_name: String,
}

pub mod dep {
    //! Dependencies for rama tls modules.
    //!
    //! Exported for your convenience.

    pub mod rcgen {
        //! Re-export of the [`rcgen`] crate.
        //!
        //! [`rcgen`]: https://docs.rs/rcgen

        pub use rcgen::*;
    }
}

#[derive(Debug, Clone, Default)]
/// An [`Extensions`] value that can be added to the [`Context`]
/// of a transport layer to signal that the transport is secure.
///
/// [`Extensions`]: crate::service::context::Extensions
/// [`Context`]: crate::service::Context
pub struct SecureTransport {
    client_hello: Option<ClientHello>,
}

impl SecureTransport {
    /// Create a [`SecureTransport`] with a [`ClientHello`]
    /// attached to it, containing the client hello info
    /// used to establish this secure transport.
    pub fn with_client_hello(hello: ClientHello) -> Self {
        Self {
            client_hello: Some(hello),
        }
    }

    /// Return the [`ClientHello`] used to establish this secure transport,
    /// only available if the tls service stored it.
    pub fn client_hello(&self) -> Option<&ClientHello> {
        self.client_hello.as_ref()
    }
}
