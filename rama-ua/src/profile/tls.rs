use std::sync::Arc;

use rama_net::fingerprint::{PeetComputeError, PeetPrint};
use rama_net::tls::ApplicationProtocol;
use rama_net::{
    fingerprint::{Ja3, Ja3ComputeError, Ja4, Ja4ComputeError},
    tls::{
        ProtocolVersion,
        client::{ClientConfig, ClientHello, ServerVerifyMode},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
/// Profile of the user-agent's TLS (client) configuration.
///
/// It is used to emulate the TLS configuration of the user-agent.
///
/// See [`ClientConfig`] for more information.
///
/// [`ClientConfig`]: rama_net::tls::client::ClientConfig
pub struct TlsProfile {
    /// The TLS client configuration.
    pub client_config: Arc<ClientConfig>,
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
        Ja3::compute_from_client_hello(self.client_config.as_ref(), negotiated_tls_version)
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
        Ja4::compute_from_client_hello(self.client_config.as_ref(), negotiated_tls_version)
    }

    /// Compute the [`PeetPrint`] (hash) on this [`TlsProfile`].
    ///
    /// This can be useful in case you want to compare profiles
    /// loaded into memory of your service with the profile
    /// of an incoming request.
    ///
    /// As specified by <https://github.com/pagpeter/TrackMe?tab=readme-ov-file#custom-fingerpint-peetprint>
    pub fn compute_peet(&self) -> Result<PeetPrint, PeetComputeError> {
        PeetPrint::compute_from_client_hello(self.client_config.as_ref())
    }
}

impl<'de> Deserialize<'de> for TlsProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = TlsProfileSerde::deserialize(deserializer)?;
        let mut cfg = ClientConfig::from(input.client_hello);
        if input.insecure {
            cfg.server_verify_mode = Some(ServerVerifyMode::Disable);
        }
        Ok(Self {
            client_config: Arc::new(cfg),
            ws_client_config_overwrites: input.ws_client_config_overwrites,
        })
    }
}

impl Serialize for TlsProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let insecure = matches!(
            self.client_config.server_verify_mode,
            Some(ServerVerifyMode::Disable)
        );
        TlsProfileSerde {
            client_hello: self.client_config.as_ref().clone().into(),
            ws_client_config_overwrites: self.ws_client_config_overwrites.clone(),
            insecure,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsProfileSerde {
    client_hello: ClientHello,
    ws_client_config_overwrites: Option<WsClientConfigOverwrites>,
    insecure: bool,
}
