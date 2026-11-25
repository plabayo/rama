//! TLS observations belong to a transport connection, independently of its application protocol.

use rama_core::extensions::{Extension, Extensions};
use rama_inspect::search::matches_display;
use rama_net::tls::ApplicationProtocol;
use serde::{Deserialize, Serialize};

use crate::{
    ProtocolVersion, SecureTransport,
    client::{ClientHello, NegotiatedTlsAlgorithms, NegotiatedTlsParameters},
    fingerprint::{Ja3, Ja4, PeetPrint},
    server::{EchServerObservation, ServerEchAccepted, ServerHandshakeHellos},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedTlsParameters {
    pub protocol_version: ProtocolVersion,
    pub application_layer_protocol: Option<ApplicationProtocol>,
    pub peer_certificate_count: Option<usize>,
    #[serde(default)]
    pub algorithms: NegotiatedTlsAlgorithms,
}

impl From<&NegotiatedTlsParameters> for CapturedTlsParameters {
    fn from(parameters: &NegotiatedTlsParameters) -> Self {
        Self {
            protocol_version: parameters.protocol_version,
            application_layer_protocol: parameters.application_layer_protocol.clone(),
            peer_certificate_count: parameters.peer_certificate_chain.as_ref().map(Vec::len),
            algorithms: parameters.algorithms,
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
        let parameters = source.get_ref::<NegotiatedTlsParameters>();
        if !source.contains::<ServerHandshakeHellos>()
            && !source.contains::<SecureTransport>()
            && parameters.is_none()
        {
            return;
        }
        let hellos = observations
            .get_or_insert(|| ServerHandshakeHellos::capture(source))
            .hellos();
        if let Some(accepted) = hellos.ech_accepted() {
            observations.get_or_insert(|| ServerEchAccepted::new(accepted));
            if accepted && let Some(outer) = hellos.wire() {
                observations.get_or_insert(|| EchServerObservation::new(outer.clone()));
            }
        }
        let client_hello = hellos.effective();
        observations.get_or_insert(|| Self {
            client_hello: client_hello.cloned(),
            parameters: parameters.map(CapturedTlsParameters::from),
            ja3: client_hello.and_then(|hello| Ja3::compute_from_client_hello(hello).ok()),
            ja4: client_hello.and_then(|hello| Ja4::compute_from_client_hello(hello).ok()),
            peetprint: client_hello
                .and_then(|hello| PeetPrint::compute_from_client_hello(hello).ok()),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rama_inspect::Observations;

    use super::*;
    use crate::{CipherSuite, CompressionAlgorithm, server::publish_server_client_hellos};

    fn hello(suite: u16) -> ClientHello {
        ClientHello::new(
            ProtocolVersion::TLSv1_3,
            vec![CipherSuite::from(suite)],
            vec![CompressionAlgorithm::from(0)],
            vec![],
        )
    }

    fn suite(hello: Option<&ClientHello>) -> Option<CipherSuite> {
        hello.map(|hello| hello.cipher_suites()[0])
    }

    #[test]
    fn capturing_before_tls_publication_does_not_freeze_an_empty_view() {
        let source = Extensions::new();
        let observations = Observations::default();
        TlsObservation::capture(&source, &observations);
        assert!(!observations.contains::<Arc<ServerHandshakeHellos>>());
        source.insert(SecureTransport::with_client_hello(hello(2)));
        publish_server_client_hellos(&source, Some(true), Some(hello(1)));
        TlsObservation::capture(&source, &observations);
        let observed = observations.get_ref::<TlsObservation>().unwrap();
        assert_eq!(
            suite(observed.client_hello.as_ref()),
            Some(CipherSuite::from(1))
        );
        assert_eq!(observed.ja3, Ja3::compute_from_client_hello(&hello(1)).ok());
    }

    #[test]
    fn fingerprints_use_the_same_view_as_the_retained_hello_snapshot() {
        let source = Extensions::new();
        source.insert(SecureTransport::with_client_hello(hello(2)));
        let observations = Observations::default();
        observations.get_or_insert(|| ServerHandshakeHellos::capture(&source));
        publish_server_client_hellos(&source, Some(true), Some(hello(1)));
        TlsObservation::capture(&source, &observations);
        let hellos = observations
            .get_ref::<Arc<ServerHandshakeHellos>>()
            .unwrap()
            .hellos();
        assert_eq!(hellos.ech_accepted(), None);
        assert_eq!(
            suite(hellos.effective()),
            suite(
                observations
                    .get_ref::<TlsObservation>()
                    .unwrap()
                    .client_hello
                    .as_ref()
            )
        );
    }

    #[test]
    fn a_capture_during_ech_publication_records_one_consistent_state() {
        // Publication has inserted its snapshot but none of the separate values yet.
        let published = Extensions::new();
        published.insert(SecureTransport::with_client_hello(hello(2)));
        publish_server_client_hellos(&published, Some(true), Some(hello(1)));
        let half = Extensions::new();
        half.insert(SecureTransport::with_client_hello(hello(2)));
        half.insert(
            published
                .get_ref::<ServerHandshakeHellos>()
                .unwrap()
                .clone(),
        );

        for source in [&half, &published] {
            let observations = Observations::default();
            TlsObservation::capture(source, &observations);
            assert_eq!(
                observations.get_ref::<ServerEchAccepted>().copied(),
                Some(ServerEchAccepted::new(true))
            );
            assert_eq!(
                suite(
                    observations
                        .get_ref::<EchServerObservation>()
                        .map(|observation| &observation.outer)
                ),
                Some(CipherSuite::from(2))
            );
            let hellos = observations
                .get_ref::<Arc<ServerHandshakeHellos>>()
                .unwrap()
                .hellos();
            assert_eq!(hellos.ech_accepted(), Some(true));
            assert_eq!(suite(hellos.wire()), Some(CipherSuite::from(2)));
            let observed = observations.get_ref::<TlsObservation>().unwrap();
            assert_eq!(
                suite(observed.client_hello.as_ref()),
                Some(CipherSuite::from(1))
            );
            assert_eq!(observed.ja3, Ja3::compute_from_client_hello(&hello(1)).ok());
        }
    }
}
