use std::{convert::Infallible, sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
    extensions::ExtensionsRef,
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
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer, TimeoutLayer},
    net::{
        address::Domain,
        apple::networkextension::{TcpFlow, tproxy::TransparentProxyServiceContext},
        client::{ConnectorService, EstablishedClientConnection},
        http::server::HttpPeekRouter,
        proxy::{IoForwardService, ProxyTarget},
        socket::{SocketOptions, opts::TcpKeepAlive},
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    service::MirrorService,
    service::service_fn,
    tcp::client::service::TcpConnector,
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
    let tcp_connect_timeout_ms = demo_config.tcp_connect_timeout_ms.max(50);

    let mitm_svc = new_tcp_service_inner(
        executor,
        demo_config,
        tls_mitm_relay_policy,
        tls_mitm_relay,
        ca_crt_pem_bytes,
        false,
    );

    let connect_timeout = Duration::from_millis(tcp_connect_timeout_ms);
    let svc = service_fn(move |ingress: TcpFlow| {
        let mitm_svc = mitm_svc.clone();
        async move {
            let Some(ProxyTarget(egress_addr)) = ingress.extensions().get_ref().cloned() else {
                return Err(OpaqueError::from_static_str(
                    "missing ProxyTarget in transparent proxy example tcp service",
                )
                .into_box_error());
            };

            let flow_exec = ingress.executor().cloned().unwrap_or_default();
            let connector = tcp_connector_service(flow_exec, connect_timeout);
            let tcp_req = rama::tcp::client::Request::new_with_extensions(
                egress_addr.clone(),
                ingress.extensions().clone(),
            );

            let EstablishedClientConnection { conn: egress, .. } = connector
                .connect(tcp_req)
                .await
                .context("establish tcp connection")
                .context_field("address", egress_addr)?;

            mitm_svc.serve(BridgeIo(ingress, egress)).await.into_box_error()
        }
    });

    Ok(ConsumeErrLayer::trace_as_debug().into_layer(svc))
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
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
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
    let html_badge_layer = crate::http::html::HtmlBadgeLayer::new()
        .with_enabled(demo_config.html_badge_enabled)
        .with_badge_label(&demo_config.html_badge_label)
        .with_excluded_domains(excluded_domains);

    let decompressor_matcher = html_badge_layer.decompression_matcher();

    (
        MapResponseBodyLayer::new_boxed_streaming_body(),
        StreamCompressionLayer::new().with_compress_predicate(MirrorDecompressed::new()),
        html_badge_layer,
        DecompressionLayer::new()
            .with_insert_accept_encoding_header(false)
            .with_matcher(decompressor_matcher),
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
    connect_timeout: Duration,
) -> impl ConnectorService<rama::tcp::client::Request, Connection: Io + Unpin> + Clone {
    TimeoutLayer::new(connect_timeout).into_layer(TcpConnector::new(exec).with_connector(Arc::new(
        SocketOptions {
            keep_alive: Some(true),
            tcp_keep_alive: Some(TcpKeepAlive {
                time: Some(TCP_KEEPALIVE_TIME),
                interval: Some(TCP_KEEPALIVE_INTERVAL),
                retries: Some(TCP_KEEPALIVE_RETRIES),
            }),
            ..SocketOptions::default_tcp()
        },
    )))
}
