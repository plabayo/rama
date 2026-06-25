use rama_core::extensions::Extension;
use rama_tls::ApplicationProtocol;
use rama_tls::fingerprint::{PeetComputeError, PeetPrint};
use rama_tls::{
    ProtocolVersion,
    client::ClientHello,
    fingerprint::{Ja3, Ja3ComputeError, Ja4, Ja4ComputeError},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Extension, Serialize, Deserialize)]
#[extension(tags(ua, tls))]
/// Profile of the user-agent's TLS (client) configuration.
///
/// It is used to emulate the TLS configuration of the user-agent: the captured
/// [`ClientHello`] is the fingerprint to reproduce.
pub struct TlsProfile {
    /// The captured ClientHello (the TLS fingerprint to emulate).
    pub client_hello: ClientHello,

    /// Optional WebSocket-specific client config overwrites.
    pub ws_client_config_overwrites: Option<WsClientConfigOverwrites>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Client Config (overwrites) specific to WebSocket traffic.
pub struct WsClientConfigOverwrites {
    pub alpn: Option<Vec<ApplicationProtocol>>,
}

impl TlsProfile {
    /// Compute the [`Ja3`] (hash) based on this [`TlsProfile`].
    ///
    /// This can be useful in case you want to compare profiles
    /// loaded into memory of your service with the profile
    /// of an incoming request.
    ///
    /// As specified by <https://github.com/salesforce/ja3`>.
    pub fn compute_ja3(
        &self,
        negotiated_tls_version: Option<ProtocolVersion>,
    ) -> Result<Ja3, Ja3ComputeError> {
        Ja3::compute_from_client_hello(&self.client_hello, negotiated_tls_version)
    }

    /// Compute the [`Ja4`] (hash) on this [`TlsProfile`].
    ///
    /// This can be useful in case you want to compare profiles
    /// loaded into memory of your service with the profile
    /// of an incoming request.
    ///
    /// As specified by <https://blog.foxio.io/ja4%2B-network-fingerprinting>
    /// and reference implementations found at <https://github.com/FoxIO-LLC/ja4>.
    pub fn compute_ja4(
        &self,
        negotiated_tls_version: Option<ProtocolVersion>,
    ) -> Result<Ja4, Ja4ComputeError> {
        Ja4::compute_from_client_hello(&self.client_hello, negotiated_tls_version)
    }

    /// Compute the [`PeetPrint`] (hash) on this [`TlsProfile`].
    ///
    /// This can be useful in case you want to compare profiles
    /// loaded into memory of your service with the profile
    /// of an incoming request.
    ///
    /// As specified by <https://github.com/pagpeter/TrackMe?tab=readme-ov-file#custom-fingerpint-peetprint>
    pub fn compute_peet(&self) -> Result<PeetPrint, PeetComputeError> {
        PeetPrint::compute_from_client_hello(&self.client_hello)
    }
}
