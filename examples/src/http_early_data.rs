//! A local HTTP/3 client -> HTTP/3 gateway -> HTTP/1 origin.
//! The original client owns 425 recovery.
//!
//! Run: `cargo run -p rama-examples --bin http_early_data --features http-full,boring`
//! (`http-full,rustls,ring` also works.) The example generates a temporary identity,
//! warms a TLS ticket, closes the warm connection, then performs one operation.
//! The origin rejects inherited replay exposure; the gateway passes its 425 back;
//! the ordinary client performs one confirmed recovery. If the handshake finishes
//! before early sending wins the race, the operation simply succeeds once.
//!
//! The gateway's upstream is ordinary HTTP/1: accepting early input does not
//! require early output. For an origin without Early-Data/425 support,
//! run with `-- --incapable-origin`; the gateway waits and the client does not
//! receive 425.

#![expect(
    clippy::expect_used,
    clippy::print_stderr,
    reason = "example: fixed local fixtures and demonstration output"
)]

use clap::Parser;

use rama::{
    Layer as _, Service as _,
    error::{BoxError, BoxErrorExt as _, extra::OpaqueError},
    extensions::{Egress, Extensions, ExtensionsRef as _},
    graceful::Scope,
    http::{
        Body, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        client::{EasyHttpConnectorBuilder, Http3Connector},
        conn::TargetHttpVersion,
        layer::{
            retry::{RetryBody, early_data::prepare_bodyless, managed::DoNotRetry},
            rewrite_uri::RewriteUriLayer,
            validate_request::{
                ValidateRequestHeaderLayer,
                early_data::{forward_to, require_confirmed},
            },
        },
        server::HttpServer,
    },
    net::{
        address::{HostWithPort, SocketAddress},
        client::ConnectorTarget,
        conn::{ConnectionHealth, ConnectionHealthWatcher},
        tls::{ApplicationProtocol, ForbidEarlyData},
        uri::{Uri, UriMatchReplaceOrigin},
    },
    quic::{Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

#[derive(Parser)]
struct Args {
    /// Treat the origin as unable to handle Early-Data: wait instead of forwarding early.
    #[arg(long)]
    incapable_origin: bool,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tokio::time::timeout(Duration::from_secs(30), run(Args::parse())).await?
}

async fn run(args: Args) -> Result<(), BoxError> {
    let (stop, stopped) = oneshot::channel();
    let scope = Scope::new()
        .with_grace(Duration::from_secs(10))
        .with_signal(async {
            _ = stopped.await;
        });
    let exec = Executor::from(scope.clone());
    let processed = Arc::new(AtomicUsize::new(0));
    let origin_count = processed.clone();
    let origin = ValidateRequestHeaderLayer::custom_fn(require_confirmed).into_layer(service_fn(
        move |request: Request| {
            if request.uri().path_or_root() != "/warm" {
                origin_count.fetch_add(1, Ordering::Relaxed);
            }
            async {
                Ok::<_, Infallible>(Response::new(Body::from(
                    "origin processed the operation\n",
                )))
            }
        },
    ));
    let listener = TcpListener::bind_address("127.0.0.1:0", exec.clone()).await?;
    let origin_address = listener.local_addr()?;
    let origin_server = HttpServer::new_http1(exec.clone()).service(origin);
    let _origin = exec.spawn_task(listener.serve(origin_server));

    // A generic application retry rule may retry other 4xx responses. The 425
    // recovery helper handles 425 first, forwarding marked 425 unchanged. The
    // application rule permits at most one ordinary retry per request.
    let origin_uri: Uri = format!("http://{origin_address}").parse()?;
    let origin = UriMatchReplaceOrigin::new(
        origin_uri.scheme().expect("local origin scheme").clone(),
        origin_uri
            .host_with_opt_port()
            .expect("local origin authority"),
    );
    let upstream = Arc::new(
        RewriteUriLayer::new(origin).into_layer(
            EasyHttpConnectorBuilder::new()
                .with_default_transport_connector()
                .without_dns_connector()
                .without_tls_proxy_support()
                .without_proxy_support()
                .without_tls_support()
                .with_default_http_connector::<RetryBody>(exec.clone())
                .with_default_connection_pool()
                .build_client_with_early_data(
                    async |request: Request<RetryBody>, result: Result<Response, OpaqueError>| {
                        let retry = result
                            .as_ref()
                            .is_ok_and(|response| response.status().is_client_error());
                        if retry {
                            request.extensions().insert(DoNotRetry::default());
                        }
                        (request, result, retry)
                    },
                    prepare_bodyless,
                ),
        ),
    );
    let gateway = forward_to(move |_: &Request| !args.incapable_origin).into_layer(service_fn(
        move |mut request: Request| {
            let upstream = upstream.clone();
            async move {
                request.headers_mut().remove(rama::http::header::HOST);
                request
                    .extensions()
                    .insert(TargetHttpVersion(Version::HTTP_11));
                let response = upstream.serve(request).await.unwrap_or_else(|error| {
                    let mut response = Response::new(Body::from(error.to_string()));
                    *response.status_mut() = StatusCode::BAD_GATEWAY;
                    response
                });
                Ok::<_, Infallible>(response)
            }
        },
    ));

    let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;
    let client_tls = TlsClientConfig::new().try_with_server_trust_anchors([identity
        .cert_chain
        .last()
        .expect("generated chain")
        .clone()])?;
    let server_tls = TlsServerConfig::new()
        .with_server_auth(identity)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut server = HttpServer::new_http3(exec.clone());
    server.http3_mut().early_dispatch = true;
    let options = TlsOptions::default()
        .with_early_data(true)
        .with_early_data_context(server.http3().early_data_context()?);
    let mut transport = TransportConfig::default();
    server.http3().configure_transport(&mut transport)?;
    let mut config = ServerConfig::try_from_rama_tls(&server_tls, options)?;
    config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(Executor::new())
        .with_server_config(config)
        .bind_address(SocketAddress::local_ipv4(0))
        .await?;
    let port = endpoint.local_addr()?.port();
    let accepting = endpoint.clone();
    let (connections, mut accepted) = mpsc::unbounded_channel();
    let service = server.service(gateway);
    let serving = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        while let Some(incoming) = accepting.accept().await {
            let connection = incoming
                .accept()?
                .into_0rtt()
                .map_err(|_connecting| {
                    BoxError::from_static_str("server early handle unavailable")
                })?
                .0;
            _ = connections.send(connection.clone());
            let service = service.clone();
            tasks.spawn(async move { service.serve(connection).await });
        }
        while tasks.join_next().await.is_some() {}
        Ok::<_, BoxError>(())
    });

    let connector = Http3Connector::builder(exec.clone())
        .with_tls_config(client_tls)
        .with_config(rama::http::core::h3::connection::Config {
            early_requests: true,
            ..Default::default()
        })
        .build_lazy()?;
    let client = EasyHttpConnectorBuilder::new()
        .with_custom_transport_connector(connector)
        .without_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .without_tls_support()
        .with_default_http_connector::<RetryBody>(exec.clone())
        .with_default_connection_pool()
        .build_client_with_early_data(
            async |request, result: Result<Response, OpaqueError>| (request, result, false),
            prepare_bodyless,
        );
    let request = |path| {
        let request = Request::builder()
            .uri(format!("https://localhost:{port}/{path}"))
            .body(Body::empty())
            .expect("local request");
        request
            .extensions()
            .insert(ConnectorTarget(HostWithPort::local_ipv4(port)));
        request
    };
    let warm = client.serve(request("warm")).await?;
    assert_eq!(warm.status(), StatusCode::OK);
    let egress = warm
        .extensions()
        .get_ref::<Egress<Extensions>>()
        .expect("egress")
        .0
        .clone();
    let health = egress
        .get_ref::<ConnectionHealthWatcher>()
        .expect("connection health");
    let mut changes = health.watch();
    warm.into_body().collect().await?;
    accepted
        .recv()
        .await
        .expect("warm connection")
        .close(0u32, b"resume for demonstration");
    while health.health() != ConnectionHealth::Broken {
        changes
            .changed()
            .await
            .ok_or_else(|| BoxError::from_static_str("connection health watcher ended"))?;
    }
    let response =
        tokio::time::timeout(Duration::from_secs(10), client.serve(request("operation"))).await??;
    assert_eq!(response.status(), StatusCode::OK);
    // Recovery sets this in the caller extension store, which this response shares.
    let recovered = response.extensions().contains::<ForbidEarlyData>();
    if args.incapable_origin {
        assert!(!recovered, "waiting gateway must not force a client retry");
    }
    response.into_body().collect().await?;
    assert_eq!(processed.load(Ordering::Relaxed), 1);
    eprintln!("origin processed once; client recovered from 425: {recovered}");
    drop(client);
    _ = stop.send(());
    endpoint.close(0u32, b"complete");
    serving.await??;
    endpoint.shutdown().await;
    drop(exec);
    scope.join().await?;
    Ok(())
}
