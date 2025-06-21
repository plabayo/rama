//! An example to showcase how you can provide a kind of connectivity check
//! using protocol inspection and hijacking utilities provided by rama
//! for both http and socks5 proxies. We do not showcase it for all possible
//! proxy flows and protocols, neither for MITM proxies. You can however
//! apply the techniques demonstrated here there as well.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example proxy_connectivity_check --features=socks5,http-full,tls
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62030`. You can use `curl` to interact with the service:
//!
//! ```
//! curl -v -x http://127.0.0.1:62030 --proxy-user 'tom:clancy' http://example.com/
//! curl -v -x socks5://127.0.0.1:62030 --proxy-user 'john:secret' http://example.com/
//! ```
//!
//! You should see in all the above examples the hijacked page by rama
//! proving you are correctly connected via a proxy built with rama.
//!
//! If you instead go to the example website directly you'll see the
//! original example site:
//!
//! ```sh
//! curl -v http://example.com/
//! ```
//!
//! Note that in an actual production setting you would usually do this with a (sub)domain
//! that you control rather than a thirdparty external web service.

use rama::{
    Context, Layer, Service,
    context::RequestContextExt,
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::UpgradeLayer,
        },
        matcher::{DomainMatcher, MethodMatcher},
        server::HttpServer,
        service::web::{
            StaticService,
            response::{Html, IntoResponse},
        },
    },
    layer::{ConsumeErrLayer, HijackLayer},
    net::{
        address::{Domain, SocketAddress},
        http::{RequestContext, server::HttpPeekRouter},
        proxy::ProxyTarget,
        stream::ClientSocketInfo,
        tls::SecureTransport,
        user::Basic,
    },
    proxy::socks5::{
        Socks5Acceptor, Socks5Auth,
        server::{LazyConnector, Socks5PeekRouter},
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use std::{convert::Infallible, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

fn new_example_hijack_svc()
-> impl Clone + Service<(), Request, Response = Response, Error = Infallible> {
    StaticService::new(Html(
        r##"<!doctype html>
<html>
<head>
    <title>Connectivity Example</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;

    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>
</head>

<body>
<div>
    <h1>Connectivity Example</h1>
    <p>This example demonstrates how you can provide a kind of connectivity check
    using protocol inspection and hijacking utilities provided by rama
    for both http and socks5 proxies.</p>
    <p><a href="https://ramaproxy.org">More information...</a></p>
</div>
</body>
</html>
"##,
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(62030))
        .await
        .expect("bind tcp interface for connectivity example");

    let proxy_service = (
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        HijackLayer::new(
            DomainMatcher::exact(Domain::from_static("example.com")),
            new_example_hijack_svc(),
        ),
    )
        .into_layer(service_fn(http_plain_proxy));

    let http_service = HttpServer::auto(Executor::graceful(graceful.guard())).service(
        (
            TraceLayer::new_for_http(),
            ProxyAuthLayer::new(Basic::new("tom", "clancy")),
            UpgradeLayer::new(
                MethodMatcher::CONNECT,
                service_fn(http_connect_accept),
                ConsumeErrLayer::default().into_layer(Forwarder::ctx()),
            ),
        )
            .into_layer(proxy_service.clone()),
    );

    let exec = Executor::graceful(graceful.guard());
    let socks5_svc = HttpPeekRouter::new(HttpServer::auto(exec).service(proxy_service))
        .with_fallback(Forwarder::ctx());
    let socks5_acceptor = Socks5Acceptor::new()
        .with_auth(Socks5Auth::username_password("john", "secret"))
        .with_connector(LazyConnector::new(socks5_svc));

    let auto_socks5_acceptor = Socks5PeekRouter::new(socks5_acceptor).with_fallback(http_service);

    graceful.spawn_task_fn(|guard| tcp_service.serve_graceful(guard, auto_socks5_acceptor));

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_connect_accept(
    mut ctx: Context<()>,
    req: Request,
) -> Result<(Response, Context<()>, Request), Response> {
    match ctx
        .get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into())
        .map(|ctx| ctx.authority.clone())
    {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host(),
                server.port = %authority.port(),
                "accept CONNECT (lazy): insert proxy target into context",
            );
            ctx.insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    tracing::info!(
        "proxy secure transport ingress: {:?}",
        ctx.get::<SecureTransport>()
    );

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_plain_proxy(ctx: Context<()>, req: Request) -> Result<Response, Infallible> {
    let client = EasyHttpWebClient::default();
    match client.serve(ctx, req).await {
        Ok(resp) => {
            match resp
                .extensions()
                .get::<RequestContextExt>()
                .and_then(|ext| ext.get::<ClientSocketInfo>())
            {
                Some(client_socket_info) => tracing::info!(
                    http.response.status_code = %resp.status(),
                    network.local.port = client_socket_info.local_addr().map(|addr| addr.port().to_string()).unwrap_or_default(),
                    network.local.address = client_socket_info.local_addr().map(|addr| addr.ip().to_string()).unwrap_or_default(),
                    network.peer.port = %client_socket_info.peer_addr().port(),
                    network.peer.address = %client_socket_info.peer_addr().ip(),
                    "http plain text proxy received response",
                ),
                None => tracing::info!(
                    http.response.status_code = %resp.status(),
                    "http plain text proxy received response, IP info unknown",
                ),
            };
            Ok(resp)
        }
        Err(err) => {
            tracing::error!("error in client request: {err:?}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}
