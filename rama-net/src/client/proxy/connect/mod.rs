use rama_core::{
    Layer, Service,
    extensions::{Extension, Extensions, ExtensionsRef, ExtensionsTransfer as _},
};
use rama_utils::macros::define_inner_service_accessors;

use crate::{
    address::ProxyAddress,
    client::{
        ConnectRequest, ConnectionError, ConnectorService, ConnectorTarget,
        ConnectorTransportProtocol, EstablishedClientConnection, ProxyRoute, pool::PoolPartition,
    },
    http::{FallbackHttpVersion, HttpRequestVersion, TargetHttpVersion, Version},
    stream::DefaultExtensionsTransfer,
    transport::TransportProtocol,
};

mod extensions;
pub use extensions::{ProxyConnectionExtensions, ProxyConnectionExtensionsTransfer};

mod per_credential;
use per_credential::credential_partition;
pub use per_credential::{
    ProxyConnectionPerCredential, ProxyConnectionPerCredentialLayer,
    ProxyConnectionPerCredentialService,
};

/// Create the request to establish the connection to `proxy` itself.
///
/// Its extensions are forked from those of the request that will travel through the
/// proxy, so per-request configuration reaches the connection to the proxy while its
/// own writes stay local.
///
/// The origin's connection facts, such as its [`TargetHttpVersion`], do not carry over:
/// this request writes its own [`ConnectorTarget`], [`ConnectorTransportProtocol`] and a
/// direct [`ProxyRoute`]. An HTTP proxy whose address names no version negotiates one,
/// whatever the origin request asks.
///
/// A TLS input belongs to the connection it configures, so the origin's stop at this
/// boundary. The hop's own identity and ALPN follow from the route: its address is the
/// authority the TLS connector names, its protocol and version the ALPN that connector
/// offers. Anything else this hop needs comes from [`ProxyConnectionExtensions`], whose
/// contents land on this request's own level. The route still decides where the dial
/// goes: this writes its own route, target and transport after that.
#[must_use]
pub fn proxy_request(proxy: &ProxyAddress, origin: &Extensions) -> ConnectRequest {
    let version = proxy.protocol.http_version();
    let transport_protocol = match version {
        Some(Version::HTTP_3) => TransportProtocol::Udp,
        _ => TransportProtocol::Tcp,
    };

    let extensions =
        origin.fork_connection(&DefaultExtensionsTransfer.and(ProxyConnectionExtensionsTransfer));
    extensions.insert(ProxyRoute::Direct);
    extensions.insert(ConnectorTarget(proxy.address.clone()));
    extensions.insert(ConnectorTransportProtocol(transport_protocol));
    if let Some(version) = version {
        extensions.insert(TargetHttpVersion(version));
    } else if proxy.protocol.is_http() {
        extensions.insert(HttpRequestVersion(Version::HTTP_11));
        extensions.insert(FallbackHttpVersion(Version::HTTP_11));
    }
    if let Some(partition) = leg_partition(proxy, origin, &extensions) {
        extensions.insert(partition);
    }

    ConnectRequest::new_with_extensions(proxy.address.clone(), extensions)
        .maybe_with_application_protocol(proxy.protocol.as_protocol())
        .with_transport_protocol(transport_protocol)
}

fn leg_partition(
    proxy: &ProxyAddress,
    origin: &Extensions,
    leg: &Extensions,
) -> Option<PoolPartition> {
    let origin_partition = origin.get_ref::<PoolPartition>();
    // The hop's own crossed onto the connection to the proxy, where it shadows the origin's.
    let hop_partition = leg
        .get_ref::<PoolPartition>()
        .filter(|partition| Some(*partition) != origin_partition);
    let narrowed = match (origin_partition, hop_partition) {
        (Some(origin), Some(hop)) => Some(origin.and(hop)),
        (Some(partition), None) | (None, Some(partition)) => Some(partition.clone()),
        (None, None) => None,
    };
    let Some(credential) = credential_partition(proxy, leg) else {
        return narrowed;
    };
    Some(match narrowed {
        Some(narrowed) => narrowed.and(&credential),
        None => credential,
    })
}

/// What a [`ProxyDialer`] dials: the connection to `proxy`, for the origin request
/// whose extensions are `origin`.
#[derive(Debug, Clone)]
pub struct ProxyDialRequest {
    pub proxy: ProxyAddress,
    pub origin: Extensions,
}

/// Dials the connection to a proxy: [`proxy_request`] through the connector towards
/// proxies it wraps, which hands back that connection.
///
/// The proxy connectors run on top of it. The connector towards proxies decides
/// whether that connection is secured: a TLS stage secures it when the proxy or
/// the request asks for TLS, and [`PlaintextProxyOnly`] refuses such a proxy where
/// there is no TLS stage.
///
/// [`PlaintextProxyOnly`]: crate::client::PlaintextProxyOnly
#[derive(Debug, Clone)]
pub struct ProxyDialer<S> {
    inner: S,
}

impl<S> ProxyDialer<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S> Service<ProxyDialRequest> for ProxyDialer<S>
where
    S: ConnectorService<ConnectRequest>,
{
    type Output = EstablishedClientConnection<S::Connection, ProxyDialRequest>;
    type Error = ConnectionError;

    async fn serve(&self, request: ProxyDialRequest) -> Result<Self::Output, Self::Error> {
        match self
            .inner
            .connect(proxy_request(&request.proxy, &request.origin))
            .await
        {
            Ok(established) => {
                let conn = established.conn;
                let partition = established.input.extensions().get_ref::<PoolPartition>();
                conn.extensions().insert(DialedProxyConnection {
                    partition: partition.cloned(),
                });
                // The version spoken over this connection, as a fact of it: the one the
                // proxy address names, else the one the connection negotiated.
                if request.proxy.protocol.is_http()
                    && let Some(version) = request.proxy.protocol.http_version().or_else(|| {
                        conn.extensions()
                            .get_ref::<TargetHttpVersion>()
                            .map(|target| target.0)
                    })
                {
                    conn.extensions().insert(TargetHttpVersion(version));
                }
                Ok(EstablishedClientConnection {
                    input: request,
                    conn,
                })
            }
            Err(error) => Err(error
                .context("establish connection to proxy")
                .context_field("address", request.proxy.address)
                .context_debug_field("protocol", request.proxy.protocol)),
        }
    }
}

/// Wraps a connector towards proxies in a [`ProxyDialer`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProxyDialerLayer;

impl<S> Layer<S> for ProxyDialerLayer {
    type Service = ProxyDialer<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyDialer::new(inner)
    }
}

/// Marks a connection to a proxy made by a [`ProxyDialer`], for
/// [`proxy_connection_reuse`](super::proxy_connection_reuse).
#[derive(Debug, Clone, Extension)]
#[extension(tags(net, proxy), scope(connection))]
pub(crate) struct DialedProxyConnection {
    pub(super) partition: Option<PoolPartition>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConnectorTargetInputExt as _, ConnectorTransportProtocolInputExt as _, Protocol,
        ProtocolInputExt as _, TargetHttpVersionInputExt as _, TransportProtocolInputExt as _,
        address::HostWithPort,
    };
    use rama_core::extensions::{Extension, ExtensionsRef};

    #[derive(Debug, Extension, PartialEq)]
    struct OriginMarker(u8);

    fn socks_proxy() -> ProxyAddress {
        "socks5://user:secret@proxy.example:1080".parse().unwrap()
    }

    #[test]
    fn the_connection_to_a_proxy_is_direct() {
        let origin = Extensions::new();
        origin.insert(ProxyRoute::Proxy(socks_proxy()));
        let request = proxy_request(&socks_proxy(), &origin);

        assert_eq!(
            request.extensions.get_ref::<ProxyRoute>(),
            Some(&ProxyRoute::Direct),
        );
    }

    #[test]
    fn proxy_request_targets_the_proxy_with_its_own_protocol() {
        let proxy = socks_proxy();
        let request = proxy_request(&proxy, &Extensions::new());

        assert_eq!(request.authority, proxy.address);
        assert_eq!(request.protocol(), Some(&Protocol::SOCKS5));
        assert_eq!(request.transport_protocol(), Some(TransportProtocol::Tcp));
    }

    #[test]
    fn an_http3_proxy_is_dialed_over_udp_with_its_version() {
        let proxy: ProxyAddress = "https://proxy.example:443".parse().unwrap();
        let proxy = proxy.with_http_version(Version::HTTP_3);
        let request = proxy_request(&proxy, &Extensions::new());

        assert_eq!(request.transport_protocol(), Some(TransportProtocol::Udp));
        assert_eq!(request.target_http_version(), Some(Version::HTTP_3));
    }

    #[test]
    fn proxy_request_forks_the_origin_extensions() {
        let origin = Extensions::new();
        origin.insert(OriginMarker(1));

        let request = proxy_request(&socks_proxy(), &origin);
        assert_eq!(request.extensions.get_ref(), Some(&OriginMarker(1)));

        request.extensions.insert(OriginMarker(2));
        assert_eq!(origin.get_ref(), Some(&OriginMarker(1)));
    }

    #[test]
    fn origin_connector_overrides_do_not_decide_how_the_proxy_is_dialed() {
        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        let origin = Extensions::new();
        origin.insert(ConnectorTarget(
            HostWithPort::try_from("alternative.example:8443").unwrap(),
        ));
        origin.insert(ConnectorTransportProtocol(TransportProtocol::Udp));
        origin.insert(TargetHttpVersion(Version::HTTP_2));

        let request = proxy_request(&proxy, &origin);
        assert_eq!(request.connector_target(), Some(proxy.address));
        assert_eq!(
            request.connector_transport_protocol(),
            Some(TransportProtocol::Tcp)
        );
        assert_eq!(request.target_http_version(), Some(Version::HTTP_11));
    }

    #[test]
    fn a_proxy_without_a_version_negotiates_whatever_the_origin_asks_for() {
        let proxy: ProxyAddress = "https://proxy.example:443".parse().unwrap();
        let origin = Extensions::new();
        origin.insert(TargetHttpVersion(Version::HTTP_3));
        origin.insert(HttpRequestVersion(Version::HTTP_3));

        let request = proxy_request(&proxy, &origin);
        assert_eq!(request.target_http_version(), None);
        assert_eq!(
            request.extensions.get_ref::<HttpRequestVersion>(),
            Some(&HttpRequestVersion(Version::HTTP_11))
        );
        assert_eq!(
            request.connector_transport_protocol(),
            Some(TransportProtocol::Tcp)
        );
    }

    fn credentialed(user: &str) -> ProxyAddress {
        format!("http://{user}:secret@proxy.example:8080")
            .parse()
            .unwrap()
    }

    fn leg_partition(proxy: &ProxyAddress, origin: &Extensions) -> Option<PoolPartition> {
        proxy_request(proxy, origin)
            .extensions
            .get_ref::<PoolPartition>()
            .cloned()
    }

    #[test]
    fn connections_to_a_proxy_are_shared_across_credentials() {
        let origin = Extensions::new();
        assert_eq!(leg_partition(&credentialed("alice"), &origin), None);
        assert_eq!(leg_partition(&credentialed("bob"), &origin), None);
    }

    #[test]
    fn a_leg_per_credential_separates_the_credentials_and_shares_the_rest() {
        let origin = Extensions::new();
        origin.insert(ProxyConnectionPerCredential);

        let alice = leg_partition(&credentialed("alice"), &origin);
        let bob = leg_partition(&credentialed("bob"), &origin);
        assert!(alice.is_some());
        assert_ne!(alice, bob);
        assert_eq!(alice, leg_partition(&credentialed("alice"), &origin));

        let anonymous: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        assert_eq!(leg_partition(&anonymous, &origin), None);
    }

    #[test]
    fn a_credential_partition_narrows_the_one_the_request_has() {
        let origin = Extensions::new();
        origin.insert(ProxyConnectionPerCredential);
        let plain = leg_partition(&credentialed("alice"), &origin);

        origin.insert(PoolPartition::of::<ProxyRoute>());
        let narrowed = leg_partition(&credentialed("alice"), &origin);
        assert_ne!(narrowed, plain);
        assert_ne!(narrowed, Some(PoolPartition::of::<ProxyRoute>()));
    }

    #[test]
    fn a_credential_partition_never_debugs_the_secret() {
        let origin = Extensions::new();
        origin.insert(ProxyConnectionPerCredential);
        let partition = leg_partition(&credentialed("alice"), &origin).expect("a partition");
        let debug = format!("{partition:?}");
        assert!(!debug.contains("secret"), "{debug}");
        assert!(!debug.contains("alice"), "{debug}");
    }

    #[tokio::test]
    async fn the_layer_asks_for_a_leg_per_credential() {
        use rama_core::{Layer as _, Service as _, service::service_fn};

        let proxy = credentialed("alice");
        let partition = {
            let proxy = proxy.clone();
            service_fn(move |input: ConnectRequest| {
                let proxy = proxy.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        proxy_request(&proxy, input.extensions())
                            .extensions
                            .get_ref::<PoolPartition>()
                            .cloned(),
                    )
                }
            })
        };

        let input = || ConnectRequest::new(HostWithPort::example_domain_http());
        assert_eq!(partition.serve(input()).await.unwrap(), None);
        assert!(
            ProxyConnectionPerCredentialLayer
                .into_layer(partition)
                .serve(input())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Extension)]
    #[extension(scope(connection))]
    struct HopSetting(u8);

    #[derive(Debug, Clone, Copy, PartialEq, Extension)]
    #[extension(scope(connection))]
    struct OtherHopSetting(u8);

    fn with_hop_settings(settings: HopSetting) -> Extensions {
        let origin = Extensions::new();
        let bag = Extensions::new();
        bag.insert(settings);
        origin.insert(ProxyConnectionExtensions(bag));
        origin
    }

    #[test]
    fn hop_settings_configure_the_leg() {
        let origin = with_hop_settings(HopSetting(7));
        let request = proxy_request(&socks_proxy(), &origin);

        assert_eq!(
            request.extensions.get_ref::<HopSetting>(),
            Some(&HopSetting(7)),
            "the hop's settings configure the connection to the proxy"
        );
    }

    #[test]
    fn the_route_still_decides_where_the_leg_dials() {
        let origin = Extensions::new();
        let bag = Extensions::new();
        bag.insert(ConnectorTarget(
            HostWithPort::try_from("elsewhere.example:443").unwrap(),
        ));
        origin.insert(ProxyConnectionExtensions(bag));

        let proxy = socks_proxy();
        let request = proxy_request(&proxy, &origin);
        assert_eq!(request.connector_target(), Some(proxy.address));
    }

    #[test]
    fn a_bagged_marker_asks_for_a_leg_per_credential() {
        let origin = Extensions::new();
        let bag = Extensions::new();
        bag.insert(ProxyConnectionPerCredential);
        origin.insert(ProxyConnectionExtensions(bag));

        assert!(leg_partition(&credentialed("alice"), &origin).is_some());
    }

    #[test]
    fn the_route_decides_the_legs_http_version() {
        let origin = Extensions::new();
        let bag = Extensions::new();
        bag.insert(TargetHttpVersion(Version::HTTP_2));
        origin.insert(ProxyConnectionExtensions(bag));

        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        let request = proxy_request(&proxy.with_http_version(Version::HTTP_11), &origin);
        assert_eq!(request.target_http_version(), Some(Version::HTTP_11));
    }

    #[test]
    fn a_bag_keeps_the_settings_of_the_level_it_was_forked_from() {
        let base = Extensions::new();
        base.insert(HopSetting(1));
        base.insert(OtherHopSetting(3));
        let bag = base.fork();
        bag.insert(HopSetting(2));

        let origin = Extensions::new();
        origin.insert(ProxyConnectionExtensions(bag));

        let request = proxy_request(&socks_proxy(), &origin);
        assert_eq!(
            request.extensions.get_ref::<HopSetting>(),
            Some(&HopSetting(2)),
            "the newest level of the bag wins"
        );
        assert_eq!(
            request.extensions.get_ref::<OtherHopSetting>(),
            Some(&OtherHopSetting(3)),
            "and the levels it was forked from still cross"
        );
    }

    #[test]
    fn the_route_decides_the_legs_http_version_when_it_names_none() {
        let origin = Extensions::new();
        let bag = Extensions::new();
        bag.insert(HttpRequestVersion(Version::HTTP_2));
        bag.insert(FallbackHttpVersion(Version::HTTP_2));
        origin.insert(ProxyConnectionExtensions(bag));

        let proxy: ProxyAddress = "https://proxy.example:443".parse().unwrap();
        let request = proxy_request(&proxy, &origin);
        assert_eq!(
            request.extensions.get_ref::<HttpRequestVersion>(),
            Some(&HttpRequestVersion(Version::HTTP_11))
        );
        assert_eq!(
            request.extensions.get_ref::<FallbackHttpVersion>(),
            Some(&FallbackHttpVersion(Version::HTTP_11))
        );
    }

    #[test]
    fn a_hop_partition_narrows_the_one_the_origin_asks_for() {
        let leg_partition_of = |origin_partition: PoolPartition| {
            let origin = Extensions::new();
            origin.insert(origin_partition);
            let bag = Extensions::new();
            bag.insert(PoolPartition::of::<u32>());
            origin.insert(ProxyConnectionExtensions(bag));
            proxy_request(&socks_proxy(), &origin)
                .extensions
                .get_ref::<PoolPartition>()
                .cloned()
                .expect("a partitioned proxy connection")
        };

        assert_ne!(
            leg_partition_of(PoolPartition::of::<u8>()),
            leg_partition_of(PoolPartition::of::<u16>()),
            "the hop's partition narrows the origin's, it does not replace it"
        );
        assert_eq!(
            leg_partition_of(PoolPartition::of::<u8>()),
            leg_partition_of(PoolPartition::of::<u8>()),
        );
    }
}
