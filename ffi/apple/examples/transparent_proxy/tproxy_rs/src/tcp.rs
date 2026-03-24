use std::{convert::Infallible, sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    http::{
        Request, Response,
        layer::{
            compression::{MirrorDecompressed, stream::StreamCompressionLayer},
            decompression::DecompressionLayer,
            dpi_proxy_credential::DpiProxyCredentialExtractorLayer,
            map_response_body::MapResponseBodyLayer,
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
            upgrade::{
                HttpProxyConnectRelayServiceRequestMatcher, mitm::HttpUpgradeMitmRelayLayer,
            },
        },
        matcher::DomainMatcher,
        proxy::mitm::HttpMitmRelay,
        ws::handshake::{
            matcher::HttpWebSocketRelayServiceRequestMatcher, mitm::WebSocketRelayService,
        },
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer},
    net::{
        address::Domain,
        apple::networkextension::{TcpFlow, tproxy::TransparentProxyServiceContext},
        client::ConnectorService,
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
        socket::{SocketOptions, opts::TcpKeepAlive},
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    service::MirrorService,
    tcp::{client::service::TcpConnector, proxy::IoToProxyBridgeIoLayer},
    tls::boring::proxy::{TlsMitmRelay, cert_issuer::BoringMitmCertIssuer},
};

use crate::{
    config::DemoProxyConfig, demo_trace_traffic::DemoTraceTrafficLayer,
    tls::mitm_relay_policy::TlsMitmRelayPolicyLayer,
};

const HIJACK_DOMAIN: Domain = Domain::from_static("mitm.ramaproxy.org");

const TCP_KEEPALIVE_TIME: Duration = Duration::from_mins(1);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_RETRIES: u32 = 5;

pub(super) async fn try_new_service(
    ctx: TransparentProxyServiceContext,
) -> Result<impl Service<TcpFlow, Output = (), Error = Infallible>, BoxError> {
    let demo_config = DemoProxyConfig::from_opaque_config(ctx.opaque_config())?;
    let executor = ctx.executor;
    let (ca_crt, ca_key) = crate::tls::certs::load_or_create_mitm_ca_crt_key_pair()
        .context("load/create MITM CA Crt/Key pair")?;
    let ca_crt_pem_bytes: &[u8] = ca_crt
        .to_pem()
        .context("encode root ca cert to pem")?
        .leak();

    let excluded_domains =
        crate::policy::DomainExclusionList::new(demo_config.exclude_domains.iter());
    let tls_mitm_relay_policy =
        TlsMitmRelayPolicyLayer::new().with_excluded_domains(excluded_domains);
    let tls_mitm_relay = TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key);

    let mitm_svc = new_tcp_service_inner(
        executor.clone(),
        demo_config,
        tls_mitm_relay_policy,
        tls_mitm_relay,
        ca_crt_pem_bytes,
        false,
    );

    Ok((
        ConsumeErrLayer::trace_as_debug(),
        IoToProxyBridgeIoLayer::extension_proxy_target_with_connector(tcp_connector_service(
            executor,
        )),
    )
        .into_layer(mitm_svc))
}

fn new_tcp_service_inner<Issuer, Ingress, Egress>(
    exec: Executor,
    demo_config: DemoProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    ca_crt_pem_bytes: &'static [u8],
    within_connect_tunnel: bool,
) -> impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone
where
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
    Ingress: Io + Unpin + ExtensionsMut,
    Egress: Io + Unpin + ExtensionsMut,
{
    let peek_duration = Duration::from_secs_f64(demo_config.peek_duration_s.max(0.5));

    let http_mitm_svc =
        HttpMitmRelay::new(exec.clone()).with_http_middleware(http_relay_middleware(
            exec,
            demo_config,
            tls_mitm_relay_policy.clone(),
            tls_mitm_relay.clone(),
            ca_crt_pem_bytes,
            within_connect_tunnel,
        ));

    let maybe_http_mitm_svc = HttpPeekRouter::new(http_mitm_svc)
        .with_peek_timeout(peek_duration)
        .with_fallback(IoForwardService::new());

    let app_mitm_layer = PeekTlsClientHelloService::new(
        (tls_mitm_relay_policy, tls_mitm_relay).into_layer(maybe_http_mitm_svc.clone()),
    )
    .with_peek_timeout(peek_duration)
    .with_fallback(maybe_http_mitm_svc);

    if within_connect_tunnel {
        return Either::A(ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_layer));
    }

    let socks5_mitm_relay = Socks5MitmRelayService::new(app_mitm_layer.clone());
    let mitm_svc = Socks5PeekRouter::new(socks5_mitm_relay)
        .with_peek_timeout(peek_duration)
        .with_fallback(app_mitm_layer);

    Either::B(ConsumeErrLayer::trace_as_debug().into_layer(mitm_svc))
}

fn http_relay_middleware<S, Issuer>(
    exec: Executor,
    demo_config: DemoProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    ca_crt_pem_bytes: &'static [u8],
    within_connect_tunnel: bool,
) -> impl Layer<S, Service: Service<Request, Output = Response, Error = BoxError> + Clone>
+ Send
+ Sync
+ 'static
+ Clone
where
    S: Service<Request, Output = Response, Error = BoxError>,
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
{
    let excluded_domains =
        crate::policy::DomainExclusionList::new(demo_config.exclude_domains.iter());
    (
        MapResponseBodyLayer::new_boxed_streaming_body(),
        StreamCompressionLayer::new().with_compress_predicate(MirrorDecompressed::new()),
        crate::http::html::HtmlBadgeLayer::new()
            .with_enabled(demo_config.html_badge_enabled)
            .with_badge_label(&demo_config.html_badge_label)
            .with_excluded_domains(excluded_domains),
        DecompressionLayer::new(),
        SetResponseHeaderLayer::if_not_present_typed(
            crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
        ),
        DemoTraceTrafficLayer,
        SetRequestHeaderLayer::if_not_present_typed(
            crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
        ),
        HttpUpgradeMitmRelayLayer::new(
            exec.clone(),
            (
                HttpWebSocketRelayServiceRequestMatcher::new(WebSocketRelayService::new(
                    DemoTraceTrafficLayer.into_layer(MirrorService::new()),
                )),
                HttpProxyConnectRelayServiceRequestMatcher::new(if within_connect_tunnel {
                    ConsumeErrLayer::trace_as_debug()
                        .into_layer(IoForwardService::new())
                        .boxed()
                } else {
                    new_tcp_service_inner(
                        exec,
                        demo_config,
                        tls_mitm_relay_policy,
                        tls_mitm_relay,
                        ca_crt_pem_bytes,
                        true,
                    )
                    .boxed()
                }),
            ),
        ),
        DpiProxyCredentialExtractorLayer::new(),
        HijackLayer::new(
            DomainMatcher::exact(HIJACK_DOMAIN),
            Arc::new(crate::http::hijack::new_service(ca_crt_pem_bytes)),
        ),
        ArcLayer::new(),
    )
}

fn tcp_connector_service(
    exec: Executor,
) -> impl ConnectorService<rama::tcp::client::Request, Connection: Io + Unpin> + Clone {
    TcpConnector::new(exec).with_connector(Arc::new(SocketOptions {
        keep_alive: Some(true),
        tcp_keep_alive: Some(TcpKeepAlive {
            time: Some(TCP_KEEPALIVE_TIME),
            interval: Some(TCP_KEEPALIVE_INTERVAL),
            retries: Some(TCP_KEEPALIVE_RETRIES),
        }),
        ..SocketOptions::default_tcp()
    }))
}
