use std::{convert::Infallible, sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    http::{
        Request, Response,
        layer::{
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
            upgrade::HttpProxyConnectMitmRelayLayer,
        },
        matcher::DomainMatcher,
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer},
    net::{
        address::Domain,
        apple::networkextension::TcpFlow,
        client::ConnectorService,
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
        socket::{SocketOptions, opts::TcpKeepAlive},
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    tcp::{client::service::TcpConnector, proxy::IoToProxyBridgeIoLayer},
    tls::boring::proxy::{TlsMitmRelay, cert_issuer::BoringMitmCertIssuer},
};

const HIJACK_DOMAIN: Domain = Domain::from_static("tproxy.example.rama.internal");

const HTTP_PEEK_DURATION: Duration = Duration::from_secs(8);

const TCP_KEEPALIVE_TIME: Duration = Duration::from_mins(1);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_RETRIES: u32 = 5;

pub(super) fn try_new_service()
-> Result<impl Service<TcpFlow, Output = (), Error = Infallible>, BoxError> {
    let (ca_crt, ca_key) = crate::tls::certs::load_or_create_mitm_ca_crt_key_pair()
        .context("load/create MITM CA Crt/Key pair")?;
    let ca_crt_pem_bytes: &[u8] = ca_crt
        .to_pem()
        .context("encode root ca cert to pem")?
        .leak();

    let tls_mitm_relay = TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key);

    // TODO: get actual graceful executor here...
    let exec = Executor::default();

    let mitm_svc = new_tcp_service_inner(exec.clone(), tls_mitm_relay, ca_crt_pem_bytes, false);

    Ok((
        ConsumeErrLayer::trace_as_debug(),
        IoToProxyBridgeIoLayer::extension_proxy_target_with_connector(tcp_connector_service(exec)),
    )
        .into_layer(mitm_svc))
}

fn new_tcp_service_inner<Issuer, Ingress, Egress>(
    exec: Executor,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    ca_crt_pem_bytes: &'static [u8],
    within_connect_tunnel: bool,
) -> impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone
where
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
    Ingress: Io + Unpin + ExtensionsMut,
    Egress: Io + Unpin + ExtensionsMut,
{
    let http_mitm_svc = if within_connect_tunnel {
        Either::A(HttpMitmRelay::new(exec).with_http_middleware(
            http_relay_middleware_within_connect_tunnel(ca_crt_pem_bytes),
        ))
    } else {
        Either::B(
            HttpMitmRelay::new(exec.clone()).with_http_middleware(http_relay_middleware(
                exec,
                tls_mitm_relay.clone(),
                ca_crt_pem_bytes,
            )),
        )
    };

    let maybe_http_mitm_svc = HttpPeekRouter::new(http_mitm_svc)
        .with_peek_timeout(HTTP_PEEK_DURATION)
        .with_fallback(IoForwardService::new());

    let app_mitm_layer =
        PeekTlsClientHelloService::new(tls_mitm_relay.into_layer(maybe_http_mitm_svc.clone()))
            .with_fallback(maybe_http_mitm_svc);

    if within_connect_tunnel {
        return Either::A(ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_layer));
    }

    let socks5_mitm_relay = Socks5MitmRelayService::new(app_mitm_layer.clone());
    let mitm_svc = Socks5PeekRouter::new(socks5_mitm_relay).with_fallback(app_mitm_layer);

    Either::B(ConsumeErrLayer::trace_as_debug().into_layer(mitm_svc))
}

fn http_relay_middleware<S, Issuer>(
    exec: Executor,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    ca_crt_pem_bytes: &'static [u8],
) -> impl Layer<S, Service: Service<Request, Output = Response, Error = Infallible> + Clone>
+ Send
+ Sync
+ 'static
+ Clone
where
    S: Service<Request, Output = Response, Error = BoxError>,
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
{
    (
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
        SetResponseHeaderLayer::if_not_present_typed(
            crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
        ),
        HttpProxyConnectMitmRelayLayer::new(
            exec.clone(),
            new_tcp_service_inner(exec, tls_mitm_relay, ca_crt_pem_bytes, true).boxed(),
        ),
        SetRequestHeaderLayer::if_not_present_typed(
            crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
        ),
        HijackLayer::new(
            DomainMatcher::exact(HIJACK_DOMAIN),
            Arc::new(crate::http::hijack::new_service(ca_crt_pem_bytes)),
        ),
        ArcLayer::new(),
    )
}

fn http_relay_middleware_within_connect_tunnel<S>(
    ca_crt_pem_bytes: &'static [u8],
) -> impl Layer<S, Service: Service<Request, Output = Response, Error = Infallible> + Clone>
+ Send
+ Sync
+ 'static
+ Clone
where
    S: Service<Request, Output = Response, Error = BoxError>,
{
    (
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
        SetResponseHeaderLayer::if_not_present_typed(
            crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
        ),
        SetRequestHeaderLayer::if_not_present_typed(
            crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
        ),
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
