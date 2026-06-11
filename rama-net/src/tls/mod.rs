//! rama common tls types
//!

use std::borrow::Cow;
use std::fmt;

use rama_core::extensions::Extension;
use rama_utils::str::NonEmptyStr;

mod enums;
pub use enums::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm,
    ECPointFormat, ExtensionId, ProtocolVersion, SignatureScheme, SupportedGroup,
};

pub mod client;
pub mod keylog;
pub mod server;

#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
/// Context information that can be provided by `tls` connectors,
/// to configure the connection in function on an tls tunnel.
pub struct TlsTunnel {
    /// The server name to use for the connection.
    pub sni: Option<crate::address::Host>,
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
    /// [`ClientHello`]: crate::tls::client::ClientHello
    #[must_use]
    pub fn with_client_hello(hello: client::ClientHello) -> Self {
        Self {
            client_hello: Some(hello),
        }
    }

    /// Return the [`ClientHello`] used to establish this secure transport,
    /// only available if the tls service stored it.
    ///
    /// [`ClientHello`]: crate::tls::client::ClientHello
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

// TODO move this to rama crypto and use native types
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Implementation agnostic encoding of common data such
/// as certificates and keys.
pub enum DataEncoding {
    /// Distinguished Encoding Rules (DER) (binary)
    Der(Vec<u8>),
    /// Same as [`DataEncoding::Der`], but multiple
    DerStack(Vec<Vec<u8>>),
    /// Privacy Enhanced Mail (PEM) (plain text)
    Pem(NonEmptyStr),
}

impl fmt::Debug for DataEncoding {
    /// Renders the variant and payload size only — never the bytes. This
    /// type also carries **private keys** (e.g. behind `ServerAuthData` /
    /// `ClientAuthData`), so emitting the contents would leak key material
    /// into logs; the raw DER/PEM bytes are noise in a debug line anyway.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Der(der) => write!(f, "Der({} bytes)", der.len()),
            Self::DerStack(stack) => write!(f, "DerStack({} entries)", stack.len()),
            Self::Pem(pem) => write!(f, "Pem({} bytes)", pem.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_encoding_debug_does_not_leak_contents() {
        // The payload of every variant can be private key material, so its
        // bytes must never reach the Debug output — in text or byte form.
        let secret = "TOP_SECRET_KEY_MATERIAL";
        let byte_repr = format!("{:?}", secret.as_bytes());

        let encodings = [
            DataEncoding::Der(secret.as_bytes().to_vec()),
            DataEncoding::DerStack(vec![secret.as_bytes().to_vec()]),
            DataEncoding::Pem(
                NonEmptyStr::try_from(format!("-----BEGIN PRIVATE KEY-----\n{secret}\n")).unwrap(),
            ),
        ];

        for enc in encodings {
            let out = format!("{enc:?}");
            assert!(!out.contains(secret), "leaked key as text: {out}");
            assert!(!out.contains(&byte_repr), "leaked key as bytes: {out}");
        }
    }
}
