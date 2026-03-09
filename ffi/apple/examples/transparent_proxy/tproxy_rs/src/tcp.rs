// mod http;
// mod tunnel;

use std::{convert::Infallible, time::Duration};

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsRef,
    http::{
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
        },
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::{
        apple::networkextension::TcpFlow, http::server::HttpPeekRouter, proxy::IoForwardService,
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{
        proxy::mitm::{Socks5MitmRelay, Socks5MitmRelayService},
        server::Socks5PeekRouter,
    },
    rt::Executor,
    tcp::proxy::IoToProxyBridgeIoLayer,
    telemetry::tracing,
    tls::boring::proxy::{TlsMitmRelay, TlsMitmRelayService},
};

use crate::utils::executor_from_input;

// use self::{http::build_entry_router, state::TcpProxyState};

// const ECHO_DOMAIN: &str = "echo.ramaproxy.org";
// const HIJACK_DOMAIN: &str = "tproxy.example.rama.internal";
// const OBSERVED_HEADER_NAME: &str = "x-rama-tproxy-observed";

pub(super) fn try_new_service()
-> Result<impl Service<TcpFlow, Output = (), Error = Infallible>, BoxError> {
    let (ca_crt, ca_key) = crate::tls::certs::load_or_create_mitm_ca_crt_key_pair()
        .context("load/create MITM CA Crt/Key pair")?;
    let tls_mitm_relay = TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key);

    // TODO: get actual graceful executor here...
    let exec = Executor::default();

    let http_mitm_svc = HttpMitmRelay::new(exec.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
        (
            SetResponseHeaderLayer::if_not_present_typed(
                crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
            ),
            RemoveResponseHeaderLayer::hop_by_hop(),
        ),
        // TODO: HTTP CONNECTOR support
        // TODO: Hijack support
        (
            RemoveRequestHeaderLayer::hop_by_hop(),
            SetRequestHeaderLayer::if_not_present_typed(
                crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
            ),
        ),
        ArcLayer::new(),
    ));

    let maybe_http_mitm_svc = HttpPeekRouter::new(http_mitm_svc)
        .with_peek_timeout(Duration::from_secs(3))
        .with_fallback(IoForwardService::new());

    let app_mitm_layer =
        PeekTlsClientHelloService::new(tls_mitm_relay.into_layer(maybe_http_mitm_svc.clone()))
            .with_fallback(maybe_http_mitm_svc);

    let socks5_mitm_relay = Socks5MitmRelayService::new(app_mitm_layer.clone());

    let mitm_svc = Socks5PeekRouter::new(socks5_mitm_relay).with_fallback(app_mitm_layer);

    Ok((
        ConsumeErrLayer::trace_as_debug(),
        IoToProxyBridgeIoLayer::extension_proxy_target(exec),
    )
        .into_layer(mitm_svc))
}
