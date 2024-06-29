//! TLS module for Rama.

pub mod rustls;

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
#[non_exhaustive]
pub struct SecureTransport;
