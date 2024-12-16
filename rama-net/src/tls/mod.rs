//! rama common tls types
//!

use rama_utils::str::NonEmptyString;

mod enums;
#[cfg(feature = "boring")]
pub use enums::openssl_cipher_list_str_from_cipher_list;
pub use enums::{
    ApplicationProtocol, CipherSuite, CompressionAlgorithm, ECPointFormat, ExtensionId,
    ProtocolVersion, SignatureScheme, SupportedGroup,
};

pub mod client;
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
    /// By default `SSLKEYLOGFILE` env variable is respected
    /// as the path to key log to, if defined
    Environment,
    /// You can choose to disable the key logging explicitly
    Disabled,
    /// Request a keys to be logged to the given file path.
    File(String),
}

impl KeyLogIntent {
    /// get the file path if intended
    pub fn file_path(&self) -> Option<String> {
        match self {
            KeyLogIntent::Disabled => None,
            KeyLogIntent::Environment => std::env::var("SSLKEYLOGFILE").ok().clone(),
            KeyLogIntent::File(keylog_filename) => Some(keylog_filename.clone()),
        }
    }

    /// consume itself into the file path if intended
    pub fn into_file_path(self) -> Option<String> {
        match self {
            KeyLogIntent::Disabled => None,
            KeyLogIntent::Environment => std::env::var("SSLKEYLOGFILE").ok().clone(),
            KeyLogIntent::File(keylog_filename) => Some(keylog_filename),
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

#[cfg(feature = "boring")]
mod boring {
    use super::*;
    use ::boring::stack::StackRef;
    use ::boring::x509::X509;
    use rama_core::error::{ErrorContext, OpaqueError};

    impl TryFrom<&X509> for DataEncoding {
        type Error = OpaqueError;

        fn try_from(value: &X509) -> Result<Self, Self::Error> {
            let der = value.to_der().context("boring X509 to Der DataEncoding")?;
            Ok(DataEncoding::Der(der))
        }
    }

    impl TryFrom<&StackRef<X509>> for DataEncoding {
        type Error = OpaqueError;

        fn try_from(value: &StackRef<X509>) -> Result<Self, Self::Error> {
            let der = value
                .into_iter()
                .map(|cert| {
                    cert.to_der()
                        .context("boring X509 stackref to DerStack DataEncoding")
                })
                .collect::<Result<Vec<Vec<u8>>, _>>()?;
            Ok(DataEncoding::DerStack(der))
        }
    }
}

#[cfg(feature = "rustls")]
mod rustls {
    use super::*;
    use ::rustls::pki_types::CertificateDer;

    impl From<&CertificateDer<'static>> for DataEncoding {
        fn from(value: &CertificateDer<'static>) -> Self {
            DataEncoding::Der(value.as_ref().into())
        }
    }

    impl From<&[CertificateDer<'static>]> for DataEncoding {
        fn from(value: &[CertificateDer<'static>]) -> Self {
            DataEncoding::DerStack(
                value
                    .into_iter()
                    .map(|cert| Into::<Vec<u8>>::into(cert.as_ref()))
                    .collect(),
            )
        }
    }
}
