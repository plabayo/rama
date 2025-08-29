//! An example to showcase how one can build a proxy that is both a SOCKS5 and HTTP Proxy in one.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example socks5_and_http_proxy --features=dns,socks5,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62023`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62023 --proxy-user 'tom:clancy' http://www.example.com/
//! curl -v -x http://127.0.0.1:62023 --proxy-user 'tom:clancy' https://www.example.com/
//! curl -v -x socks5://127.0.0.1:62023 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x socks5h://127.0.0.1:62023 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x socks5://127.0.0.1:62023 --proxy-user 'john:secret' https://www.example.com/
//! curl -v -x socks5h://127.0.0.1:62023 --proxy-user 'john:secret' https://www.example.com/
//! ```
//!
//! You should see in all the above examples the responses from the server.

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
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    net::{http::RequestContext, proxy::ProxyTarget, stream::ClientSocketInfo, user::Basic},
    proxy::socks5::{Socks5Acceptor, server::Socks5PeekRouter},
    rt::Executor,
    service::service_fn,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use std::{convert::Infallible, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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

    let tcp_service = TcpListener::bind("127.0.0.1:62023")
        .await
        .expect("bind socks5+http proxy to 127.0.0.1:62023");

    let socks5_acceptor = Socks5Acceptor::default()
        .with_authorizer(Basic::new_static("john", "secret").into_authorizer());

    let exec = Executor::graceful(graceful.guard());
    let http_service = HttpServer::auto(exec).service(
        (
            TraceLayer::new_for_http(),
            ProxyAuthLayer::new(Basic::new_static("tom", "clancy")),
            UpgradeLayer::new(
                MethodMatcher::CONNECT,
                service_fn(http_connect_accept),
                ConsumeErrLayer::default().into_layer(Forwarder::ctx()),
            ),
            RemoveResponseHeaderLayer::hop_by_hop(),
            RemoveRequestHeaderLayer::hop_by_hop(),
        )
            .into_layer(service_fn(http_plain_proxy)),
    );

    let auto_socks5_acceptor = Socks5PeekRouter::new(socks5_acceptor).with_fallback(http_service);

    graceful.spawn_task_fn(|guard| tcp_service.serve_graceful(guard, auto_socks5_acceptor));

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_connect_accept(
    mut ctx: Context,
    req: Request,
) -> Result<(Response, Context, Request), Response> {
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

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_plain_proxy(ctx: Context, req: Request) -> Result<Response, Infallible> {
    let client = EasyHttpWebClient::default();
    match client.serve(ctx, req).await {
        Ok(resp) => {
            if let Some(client_socket_info) = resp
                .extensions()
                .get::<RequestContextExt>()
                .and_then(|ext| ext.get::<ClientSocketInfo>())
            {
                tracing::info!(
                    http.response.status_code = %resp.status(),
                    network.local.port = client_socket_info.local_addr().map(|addr| addr.port().to_string()).unwrap_or_default(),
                    network.local.address = client_socket_info.local_addr().map(|addr| addr.ip().to_string()).unwrap_or_default(),
                    network.peer.port = %client_socket_info.peer_addr().port(),
                    network.peer.address = %client_socket_info.peer_addr().ip(),
                    "http plain text proxy received response",
                )
            } else {
                tracing::info!(
                    http.response.status_code = %resp.status(),
                    "http plain text proxy received response, IP info unknown",
                )
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
