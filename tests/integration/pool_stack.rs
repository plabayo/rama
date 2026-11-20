//! A custom connector that opens its transport through another HTTP client
//! must fit a default worker stack, also unoptimized as in the `ci` profile.

use rama::{
    Service, ServiceInput,
    graceful::WeakScope,
    http::{
        Body, Request, Response, Version, body::util::BodyExt as _, client::EasyHttpWebClient,
        server::HttpServer,
    },
    net::{
        client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
        tls::ApplicationProtocol,
    },
    quic::{
        ServerConfig, TransportConfig,
        test_utils::MockQuicConnectorService,
        tls::{BoringTlsProvider, TlsOptions},
    },
    service::service_fn,
    tls::{
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
};
use std::{
    convert::Infallible,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[test]
fn pooled_http1() {
    check("pool_stack::pooled_http1", Version::HTTP_11, true);
}

#[test]
fn pooled_http2() {
    check("pool_stack::pooled_http2", Version::HTTP_2, true);
}

#[test]
fn unpooled_http1() {
    check("pool_stack::unpooled_http1", Version::HTTP_11, false);
}

#[test]
fn unpooled_http2() {
    check("pool_stack::unpooled_http2", Version::HTTP_2, false);
}

#[test]
fn pooled_http3() {
    check("pool_stack::pooled_http3", Version::HTTP_3, true);
}

#[test]
fn unpooled_http3() {
    check("pool_stack::unpooled_http3", Version::HTTP_3, false);
}

fn check(name: &str, version: Version, pooled: bool) {
    // A stack overflow aborts the process. Also discard CI's larger test stack.
    if std::env::var("RAMA_POOL_STACK_CHILD").as_deref() != Ok(name) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("RAMA_POOL_STACK_CHILD", name)
            .env_remove("RUST_MIN_STACK")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        // block_on itself runs on the caller; spawn exercises a default worker stack.
        tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), exercise(version, pooled))
                .await
                .unwrap();
        })
        .await
        .unwrap();
    });
}

async fn exercise(version: Version, pooled: bool) {
    let connections = Arc::new(AtomicUsize::new(0));
    let transport = service_fn({
        let connections = connections.clone();
        move |input: ConnectRequest| {
            connections.fetch_add(1, Ordering::Relaxed);
            async move {
                let (client, server) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    HttpServer::auto(WeakScope::detached())
                        .serve(
                            ServiceInput::new(server),
                            service_fn(|_: Request| async {
                                Ok::<_, Infallible>(Response::new(Body::from("ok")))
                            }),
                        )
                        .await
                        .unwrap();
                });
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(client),
                })
            }
        }
    });
    let transport = transport.boxed();
    let control = EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_custom_tcp_connector(transport.clone())
        .without_dns_connector()
        .with_default_proxy_support()
        .with_tls_support_using_rustls(TlsClientConfig::default_http())
        .with_default_http_connector()
        .with_default_connection_pool()
        .build_client()
        .boxed();
    let quic = MockQuicConnectorService::new(quic_server_config(), |_: &ConnectRequest| {
        HttpServer::new_http3(WeakScope::detached()).service(service_fn(|_: Request| async {
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        }))
    });
    let quic = service_fn({
        let control = control.clone();
        let connections = connections.clone();
        move |input: ConnectRequest| {
            connections.fetch_add(1, Ordering::Relaxed);
            let control = control.clone();
            let quic = quic.clone();
            async move {
                control_request(&control).await;
                quic.serve(input).await
            }
        }
    });
    let transport = service_fn(move |input: ConnectRequest| {
        let control = control.clone();
        let transport = transport.clone();
        async move {
            control_request(&control).await;
            transport.serve(input).await
        }
    });
    let builder = EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_custom_tcp_connector(transport)
        .with_custom_quic_connector(quic)
        .without_dns_connector()
        .with_default_proxy_support()
        .with_tls_support_using_rustls(
            TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
        )
        .with_default_http_connector();
    let client = if pooled {
        builder
            .with_default_connection_pool()
            .build_client()
            .boxed()
    } else {
        builder.without_connection_pool().build_client().boxed()
    };
    for _ in 0..2 {
        let uri = if version == Version::HTTP_3 {
            "https://127.0.0.1/"
        } else {
            "http://127.0.0.1/"
        };
        let request = Request::builder()
            .uri(uri)
            .version(version)
            .body(Body::empty())
            .unwrap();
        let response = client.serve(request).await.unwrap();
        assert_eq!(response.version(), version);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok"
        );
    }
    assert_eq!(
        connections.load(Ordering::Relaxed),
        if pooled { 2 } else { 3 }
    );
}

// Establishing a tunnel can itself require an HTTP control request.
async fn control_request(
    control: &impl Service<Request, Output = Response, Error: std::fmt::Debug>,
) {
    let response = control
        .serve(
            Request::builder()
                .uri("http://127.0.0.1/connect")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response.into_body().collect().await.unwrap();
}

fn quic_server_config() -> ServerConfig {
    let mut transport = TransportConfig::default();
    HttpServer::new_http3(WeakScope::detached())
        .http3()
        .configure_transport(&mut transport)
        .unwrap();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let mut config = ServerConfig::try_from_rama_tls_with_provider(
        &TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect()),
        TlsOptions::default(),
        &BoringTlsProvider::new(),
    )
    .unwrap();
    config.set_transport_config(Arc::new(transport));
    config
}
