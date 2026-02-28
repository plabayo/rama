use std::{convert::Infallible, sync::Arc};

use rama::{
    Layer, Service,
    extensions::{ExtensionsMut as _, ExtensionsRef as _},
    http::{
        Body, HeaderValue, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        header::{CONTENT_TYPE, HOST},
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    net::{
        apple::networkextension::{TcpFlow, tproxy::TransparentProxyFlowMeta},
        http::{RequestContext, server::HttpPeekRouter},
        proxy::ProxyTarget,
    },
    proxy::socks5::{
        Socks5Acceptor,
        server::{LazyConnector, Socks5PeekRouter},
    },
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
};

use super::{HIJACK_DOMAIN, OBSERVED_HEADER_NAME, state::TcpProxyState, tunnel::TunnelService};
use crate::utils::resolve_target_from_extensions;

pub(super) fn build_entry_router(
    exec: Executor,
) -> impl Service<TcpFlow, Output = (), Error = rama::error::BoxError> + Clone {
    let http_server =
        HttpServer::auto(exec.clone()).service(build_http_request_service(exec.clone()));
    let http_peek = HttpPeekRouter::new(http_server).with_fallback(TunnelService);
    let socks5_acceptor =
        Socks5Acceptor::new(exec).with_connector(LazyConnector::new(http_peek.clone()));

    Socks5PeekRouter::new(socks5_acceptor).with_fallback(http_peek)
}

pub(super) fn build_http_request_service(
    exec: Executor,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    (
        ConsumeErrLayer::trace_as_debug(),
        UpgradeLayer::new(
            exec,
            MethodMatcher::CONNECT,
            service_fn(http_connect_accept),
            service_fn(http_connect_proxy),
        ),
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
    )
        .into_layer(HttpObservedProxy)
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
        Ok(authority) => {
            req.extensions_mut().insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to parse CONNECT authority");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), req))
}

async fn http_connect_proxy(upgraded: Upgraded) -> Result<(), Infallible> {
    if let Err(err) = TunnelService.serve(upgraded).await {
        tracing::error!(error = %err, "CONNECT tunnel failed");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct HttpObservedProxy;

impl Service<Request> for HttpObservedProxy {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, mut req: Request) -> Result<Self::Output, Self::Error> {
        let Some(state) = req.extensions().get::<Arc<TcpProxyState>>().cloned() else {
            tracing::error!("missing proxy state in HTTP request extensions");
            return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        };

        let Some(host) = request_host(&req) else {
            tracing::warn!("missing host in intercepted HTTP request");
            return Ok(StatusCode::BAD_REQUEST.into_response());
        };

        if host.eq_ignore_ascii_case(HIJACK_DOMAIN) {
            return Ok(hijack_response(req, &state));
        }

        req.headers_mut()
            .insert(OBSERVED_HEADER_NAME, state.observed_header_value.clone());

        let client = EasyHttpWebClient::default();
        match client.serve(req).await {
            Ok(mut resp) => {
                resp.headers_mut()
                    .insert(OBSERVED_HEADER_NAME, state.observed_header_value.clone());
                Ok(resp)
            }
            Err(err) => {
                tracing::error!(error = %err, "upstream HTTP request failed");
                Ok(StatusCode::BAD_GATEWAY.into_response())
            }
        }
    }
}

fn hijack_response(req: Request, state: &TcpProxyState) -> Response {
    if req.uri().path() == "/data/root.ca.pem" {
        let mut resp = Response::new(Body::from(state.root_ca_pem.to_string()));
        resp.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-pem-file"),
        );
        resp.headers_mut()
            .insert(OBSERVED_HEADER_NAME, state.observed_header_value.clone());
        return resp;
    }

    let mut resp = Response::new(Body::from(home_page_html()));
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp.headers_mut()
        .insert(OBSERVED_HEADER_NAME, state.observed_header_value.clone());
    resp
}

fn request_host(req: &Request) -> Option<String> {
    RequestContext::try_from(req)
        .ok()
        .map(|ctx| ctx.authority.host.to_string())
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .and_then(normalize_host)
}

fn normalize_host(host: String) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    if let Some(stripped) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return Some(stripped.to_owned());
    }
    Some(
        host.split_once(':')
            .map(|(h, _)| h.to_owned())
            .unwrap_or(host),
    )
}

pub(super) fn prepare_flow_extensions(flow: &mut TcpFlow) {
    if flow.extensions().contains::<ProxyTarget>() {
        return;
    }

    if let Some(target) = flow
        .extensions()
        .get::<TransparentProxyFlowMeta>()
        .and_then(|meta| meta.remote_endpoint.clone())
    {
        flow.extensions_mut().insert(ProxyTarget(target));
    }
}

fn home_page_html() -> &'static str {
    r#"<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Rama Transparent Proxy Demo</title>
    <style>
        body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 2rem; line-height: 1.45; }
        main { max-width: 860px; margin: 0 auto; }
        h1 { margin-bottom: 0.25rem; }
        .meta { color: #555; margin-top: 0; }
        a.button { display: inline-block; margin-top: 1rem; padding: 0.65rem 1rem; background: #111; color: #fff; text-decoration: none; border-radius: 8px; }
        code { background: #f4f4f4; padding: 0.1rem 0.25rem; border-radius: 4px; }
    </style>
</head>
<body>
    <main>
        <h1>Rama Transparent Proxy Demo</h1>
        <p class="meta">Domain hijacked by the transparent proxy runtime.</p>
        <p>Your proxy is active. This endpoint is served locally by the Rust MITM stack.</p>
        <p>Install the proxy root certificate to trust MITM traffic:</p>
        <p><a class="button" href="/data/root.ca.pem">Download Root CA PEM</a></p>
    </main>
</body>
</html>
"#
}
