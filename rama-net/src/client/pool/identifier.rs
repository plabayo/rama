use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
};

use crate::{
    AuthorityInputExt, ConnectorTransportProtocolInputExt, Protocol, ProtocolInputExt,
    address::{HostWithOptPort, ProxyAddress},
    client::{ConnectorTarget, ProxyRoute},
    transport::TransportProtocol,
};

use super::{ConnID, ReqToConnID};

/// Basic connection-pool identifier derived from connection input.
///
/// Inputs share a pool identity only when their application protocol, logical
/// authority, selected proxy, physical connector target and physical transport
/// all match. The identity also records whether a route was requested: an
/// explicitly direct route differs from an input without a route decision,
/// preserving the presence or absence of established route metadata on reuse.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct BasicConnIdentifier;

impl BasicConnIdentifier {
    /// Create a basic connection-pool identifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Connection identity produced by [`BasicConnIdentifier`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BasicConnId {
    pub protocol: Option<Protocol>,
    pub authority: HostWithOptPort,
    /// Whether the input selected a route, including an explicitly direct route.
    /// An explicit direct route and no route both have no [`Self::proxy_address`],
    /// but differ in whether established route metadata must be present.
    pub proxy_route_requested: bool,
    pub proxy_address: Option<ProxyAddress>,
    pub connector_target: Option<ConnectorTarget>,
    pub connector_transport_protocol: Option<TransportProtocol>,
}

impl ConnID for BasicConnId {
    #[cfg(feature = "opentelemetry")]
    fn attributes(&self) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> {
        self.protocol
            .as_ref()
            .map(|protocol| {
                rama_core::telemetry::opentelemetry::KeyValue::new("protocol", protocol.to_string())
            })
            .into_iter()
            .chain([rama_core::telemetry::opentelemetry::KeyValue::new(
                "authority",
                self.authority.to_string(),
            )])
    }
}

impl<Input> ReqToConnID<Input> for BasicConnIdentifier
where
    Input:
        AuthorityInputExt + ConnectorTransportProtocolInputExt + ExtensionsRef + ProtocolInputExt,
{
    type ID = BasicConnId;

    fn id(&self, input: &Input) -> Result<Self::ID, BoxError> {
        let authority = input
            .authority()
            .ok_or_else(|| BoxError::from_static_str("no authority found in connection input"))?;
        let proxy_route = input.extensions().get_ref::<ProxyRoute>();

        Ok(BasicConnId {
            protocol: input.protocol().cloned(),
            authority,
            proxy_route_requested: proxy_route.is_some(),
            proxy_address: proxy_route.and_then(ProxyRoute::proxy_address).cloned(),
            connector_target: input.extensions().get_ref().cloned(),
            connector_transport_protocol: input.connector_transport_protocol(),
        })
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use rama_core::{Service as _, ServiceInput, service::service_fn};

    use super::*;
    use crate::{
        address::HostWithPort,
        client::{ConnectRequest, EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute},
    };

    #[test]
    fn separates_application_protocols() {
        let authority = "icap.test:11344".parse::<HostWithPort>().unwrap();
        let plain =
            ConnectRequest::new(authority.clone()).with_application_protocol(Protocol::ICAP);
        let secure = ConnectRequest::new(authority).with_application_protocol(Protocol::ICAPS);

        assert_ne!(
            BasicConnIdentifier::new().id(&plain).unwrap(),
            BasicConnIdentifier::new().id(&secure).unwrap(),
        );
    }

    #[test]
    fn separates_logical_and_physical_targets() {
        let authority = "icap.test:11344".parse::<HostWithPort>().unwrap();
        let first = ConnectRequest::new(authority.clone());
        first.extensions.insert(ConnectorTarget(
            "127.0.0.1:11344".parse::<HostWithPort>().unwrap(),
        ));
        let second = ConnectRequest::new(authority);
        second.extensions.insert(ConnectorTarget(
            "127.0.0.1:11345".parse::<HostWithPort>().unwrap(),
        ));

        assert_ne!(
            BasicConnIdentifier::new().id(&first).unwrap(),
            BasicConnIdentifier::new().id(&second).unwrap(),
        );
    }

    #[test]
    fn separates_physical_transport_protocols() {
        use crate::client::ConnectorTransportProtocol;

        let authority = "example.com:443".parse::<HostWithPort>().unwrap();
        let tcp = ConnectRequest::new(authority.clone());
        tcp.extensions
            .insert(ConnectorTransportProtocol(TransportProtocol::Tcp));
        let udp = ConnectRequest::new(authority);
        udp.extensions
            .insert(ConnectorTransportProtocol(TransportProtocol::Udp));

        assert_ne!(
            BasicConnIdentifier::new().id(&tcp).unwrap(),
            BasicConnIdentifier::new().id(&udp).unwrap(),
        );
    }

    #[test]
    fn equivalent_physical_transports_share_an_identity() {
        use crate::client::ConnectorTransportProtocol;

        let authority = "example.com:443".parse::<HostWithPort>().unwrap();
        let logical_tcp =
            ConnectRequest::new(authority.clone()).with_transport_protocol(TransportProtocol::Tcp);
        let routed_tcp =
            ConnectRequest::new(authority).with_transport_protocol(TransportProtocol::Udp);
        routed_tcp
            .extensions
            .insert(ConnectorTransportProtocol(TransportProtocol::Tcp));

        assert_eq!(
            BasicConnIdentifier::new().id(&logical_tcp).unwrap(),
            BasicConnIdentifier::new().id(&routed_tcp).unwrap(),
        );
    }

    #[test]
    fn uses_only_selected_proxy_route() {
        let request = ConnectRequest::new(HostWithPort::example_domain_https());
        request.extensions.insert(ProxyRoute::Direct);
        assert_eq!(
            BasicConnIdentifier::new()
                .id(&request)
                .unwrap()
                .proxy_address,
            None,
        );

        let proxy_address = "http://proxy.example:8080".parse::<ProxyAddress>().unwrap();
        request
            .extensions
            .insert(ProxyRoute::Proxy(proxy_address.clone()));
        assert_eq!(
            BasicConnIdentifier::new()
                .id(&request)
                .unwrap()
                .proxy_address,
            Some(proxy_address),
        );
    }

    #[tokio::test]
    async fn pool_preserves_absent_and_explicit_direct_route_metadata() {
        for requested_first in [false, true] {
            let dials = Arc::new(AtomicUsize::new(0));
            let inner = service_fn({
                let dials = Arc::clone(&dials);
                move |input: ConnectRequest| {
                    dials.fetch_add(1, Ordering::Relaxed);
                    async move {
                        let conn = ServiceInput::new(());
                        if input.extensions.contains::<ProxyRoute>() {
                            conn.extensions.insert(EstablishedProxyRoute::Direct);
                        }
                        Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
                    }
                }
            });
            let pool = super::super::LruDropPool::try_new(1, 2)
                .unwrap()
                .with_drop_connection_if_no_response(false);
            let connector =
                super::super::PooledConnector::new(inner, pool, BasicConnIdentifier::new());

            for route_requested in [
                requested_first,
                !requested_first,
                requested_first,
                !requested_first,
            ] {
                let request = ConnectRequest::new(HostWithPort::example_domain_https());
                if route_requested {
                    request.extensions.insert(ProxyRoute::Direct);
                }
                let established = connector.serve(request).await.unwrap();
                assert_eq!(
                    established
                        .conn
                        .extensions()
                        .get_ref::<EstablishedProxyRoute>(),
                    route_requested.then_some(&EstablishedProxyRoute::Direct),
                );
                drop(established.conn);
            }

            assert_eq!(dials.load(Ordering::Relaxed), 2);
        }
    }

    #[tokio::test]
    async fn pool_reuses_each_protocol_without_crossing_protocols() {
        let dials = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let dials = Arc::clone(&dials);
            move |input| {
                dials.fetch_add(1, Ordering::Relaxed);
                async move {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input,
                        conn: ServiceInput::new(()),
                    })
                }
            }
        });
        let pool = super::super::LruDropPool::try_new(1, 2)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let connector = super::super::PooledConnector::new(inner, pool, BasicConnIdentifier::new());
        let authority = "icap.test:11344".parse::<HostWithPort>().unwrap();

        for protocol in [
            Protocol::ICAP,
            Protocol::ICAP,
            Protocol::ICAPS,
            Protocol::ICAPS,
        ] {
            let established = connector
                .serve(ConnectRequest::new(authority.clone()).with_application_protocol(protocol))
                .await
                .unwrap();
            drop(established.conn);
        }

        assert_eq!(dials.load(Ordering::Relaxed), 2);
    }
}
