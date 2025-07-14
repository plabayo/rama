//! This example demonstrates how to create an https proxy.
//!
//! This proxy example does not perform any TLS termination on the actual proxied traffic.
//! It is an adaptation of the `http_connect_proxy` example with tls termination for the incoming connections.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example https_connect_proxy --features=http-full,rustls
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62016`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl --proxy-insecure -v -x https://127.0.0.1:62016 --proxy-user 'john:secret' http://www.example.com
//! curl --proxy-insecure -k -v https://127.0.0.1:62016 --proxy-user 'john:secret' https://www.example.com
//! ```
//!
//! You should see in both cases the responses from the example domains.
//!
//! In case you want to use it in a standard browser,
//! you'll need to first import and trust the generated certificate.

use rama::{
    Context, Layer, Service,
    graceful::Shutdown,
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{proxy_auth::ProxyAuthLayer, trace::TraceLayer, upgrade::UpgradeLayer},
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    net::{
        http::RequestContext,
        proxy::ProxyTarget,
        stream::layer::http::BodyLimitLayer,
        tls::{SecureTransport, server::SelfSignedData},
        user::Basic,
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter},
};

#[cfg(feature = "boring")]
use rama::{
    net::tls::{
        ApplicationProtocol,
        server::{ServerAuth, ServerConfig},
    },
    tls::boring::server::TlsAcceptorLayer,
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use rama::tls::rustls::server::{TlsAcceptorDataBuilder, TlsAcceptorLayer};

use std::convert::Infallible;
use std::time::Duration;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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

    let shutdown = Shutdown::default();

    #[cfg(feature = "boring")]
    let tls_service_data = {
        let tls_server_config = ServerConfig {
            application_layer_protocol_negotiation: Some(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ]),
            ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
                organisation_name: Some("Example Server Acceptor".to_owned()),
                ..Default::default()
            }))
        };
        tls_server_config
            .try_into()
            .expect("create tls server config")
    };

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    let tls_service_data = {
        TlsAcceptorDataBuilder::new_self_signed(SelfSignedData {
            organisation_name: Some("Example Server Acceptor".to_owned()),
            ..Default::default()
        })
        .expect("self signed acceptor data")
        .with_alpn_protocols_http_auto()
        .with_env_key_logger()
        .expect("with env key logger")
        .build()
    };

    // create tls proxy
    shutdown.spawn_task_fn(async |guard| {
        let tcp_service = TcpListener::build()
            .bind("127.0.0.1:62016")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62016");

        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec.clone()).service(
            (
                TraceLayer::new_for_http(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filter
                ProxyAuthLayer::new(Basic::new_static("john", "secret")),
                UpgradeLayer::new(
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    ConsumeErrLayer::default().into_layer(Forwarder::ctx()),
                ),
            )
                .into_layer(service_fn(http_plain_proxy)),
        );

        tcp_service
            .serve_graceful(
                guard,
                (
                    // protect the http proxy from too large bodies, both from request and response end
                    BodyLimitLayer::symmetric(2 * 1024 * 1024),
                    TlsAcceptorLayer::new(tls_service_data).with_store_client_hello(true),
                )
                    .into_layer(http_service),
            )
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_connect_accept<S>(
    mut ctx: Context<S>,
    req: Request,
) -> Result<(Response, Context<S>, Request), Response>
where
    S: Clone + Send + Sync + 'static,
{
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

async fn http_plain_proxy<S>(ctx: Context<S>, req: Request) -> Result<Response, Infallible>
where
    S: Clone + Send + Sync + 'static,
{
    let client = EasyHttpWebClient::default();
    let uri = req.uri().clone();
    tracing::debug!(
        url.full = %req.uri(),
        "proxy connect plain text request",
    );
    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(
                url.full = %uri,
                "error in client request: {err:?}",
            );
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}
