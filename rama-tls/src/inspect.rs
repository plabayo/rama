//! TLS observations belong to a transport connection, independently of its application protocol.

use rama_core::extensions::{Extension, Extensions};
use rama_inspect::search::matches_display;
use rama_net::tls::ApplicationProtocol;
use serde::{Deserialize, Serialize};

use crate::{
    ProtocolVersion, SecureTransport,
    client::{ClientHello, NegotiatedTlsParameters},
    fingerprint::{Ja3, Ja4, PeetPrint},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedTlsParameters {
    pub protocol_version: ProtocolVersion,
    pub application_layer_protocol: Option<ApplicationProtocol>,
    pub peer_certificate_count: Option<usize>,
}

impl From<&NegotiatedTlsParameters> for CapturedTlsParameters {
    fn from(parameters: &NegotiatedTlsParameters) -> Self {
        Self {
            protocol_version: parameters.protocol_version,
            application_layer_protocol: parameters.application_layer_protocol.clone(),
            peer_certificate_count: parameters.peer_certificate_chain.as_ref().map(Vec::len),
        }
    }
}

#[derive(Debug, Clone, Extension, Serialize)]
pub struct TlsObservation {
    pub client_hello: Option<ClientHello>,
    pub parameters: Option<CapturedTlsParameters>,
    pub ja3: Option<Ja3>,
    pub ja4: Option<Ja4>,
    pub peetprint: Option<PeetPrint>,
}

impl TlsObservation {
    /// Retain one typed observation per observed connection. Repeated HTTP streams
    /// share this value instead of copying TLS fingerprints into every exchange.
    pub fn capture(source: &Extensions, observations: &rama_inspect::Observations) {
        if observations.contains::<Self>() {
            return;
        }
        let transport = source.get_ref::<SecureTransport>();
        let parameters = source.get_ref::<NegotiatedTlsParameters>();
        if transport.is_none() && parameters.is_none() {
            return;
        }
        observations.get_or_insert(|| Self {
            client_hello: transport.and_then(SecureTransport::client_hello).cloned(),
            parameters: parameters.map(CapturedTlsParameters::from),
            ja3: Ja3::compute(source).ok(),
            ja4: Ja4::compute(source).ok(),
            peetprint: PeetPrint::compute(source).ok(),
        });
    }
}

impl TlsObservation {
    pub fn matches_search(&self, query: &str) -> bool {
        self.ja3
            .as_ref()
            .is_some_and(|value| matches_display(&format_args!("{value:x}"), query))
            || self
                .ja4
                .as_ref()
                .is_some_and(|value| matches_display(value, query))
            || self
                .peetprint
                .as_ref()
                .is_some_and(|value| matches_display(value, query))
    }
}
