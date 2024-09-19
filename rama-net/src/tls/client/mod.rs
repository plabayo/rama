//! TLS implementation agnostic client types
//!
//! [`ClientHello`] is used in Rama as the implementation agnostic type
//! to convey what client hello was set by the incoming TLS Connection,
//! if the server middleware is configured to store it.
//!
//! By being implementation agnostic we have the advantage to be able to bridge
//! easily between different implementations. Making it possible to run for example
//! a Rustls proxy service but establish connections using BoringSSL.

mod hello;
#[doc(inline)]
pub use hello::{ClientHello, ClientHelloExtension};

#[cfg(feature = "boring")]
mod parser;

mod config;
#[doc(inline)]
pub use config::{ClientAuth, ClientAuthData, ClientConfig, ServerVerifyMode};

use super::{ApplicationProtocol, ProtocolVersion};

#[derive(Debug, Clone)]
/// Indicate (some) of the negotiated tls parameters that
/// can be added to the service context by Tls implementations.
pub struct NegotiatedTlsParameters {
    /// The used [`ProtocolVersion`].
    ///
    /// e.g. [`ProtocolVersion::TLSv1_3`]
    pub protocol_version: ProtocolVersion,
    /// Indicates the agreed upon [`ApplicationProtocol`]
    /// in case the tls implementation can surfice this
    /// AND there is such a protocol negotiated and agreed upon.
    ///
    /// e.g. [`ApplicationProtocol::HTTP_2`]
    pub application_layer_protocol: Option<ApplicationProtocol>,
}
