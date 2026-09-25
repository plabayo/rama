#![expect(clippy::unwrap_used, reason = "benchmark fixtures must be valid")]

#[cfg(feature = "rustls")]
use rama::tls::client::TlsClientConfig;
use rama::{
    Service,
    http::{Body, Request, client::EasyHttpWebClient},
    rt::Executor,
};
use std::hint::black_box;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

#[cfg(feature = "tls")]
mod policy_identity {
    use rama::tls::{
        KeyLogIntent, TlsKeyLog,
        client::{TlsComponentIdentity, TlsPoolComponent, TlsPoolId},
        keylog::NoopKeyLogSink,
    };
    use std::{hint::black_box, sync::Arc};

    #[divan::bench]
    fn ordinary_keylog(bencher: divan::Bencher) {
        let keylog = TlsKeyLog(KeyLogIntent::Disabled);
        bencher.bench_local(|| TlsPoolId::builder().with_keylog(black_box(&keylog)).build());
    }

    #[divan::bench]
    fn shared_keylog(bencher: divan::Bencher) {
        let keylog = TlsKeyLog(KeyLogIntent::Custom(Arc::new(NoopKeyLogSink)));
        bencher.bench_local(|| TlsPoolId::builder().with_keylog(black_box(&keylog)).build());
    }

    #[divan::bench]
    fn capture_shared_instance(bencher: divan::Bencher) {
        let hook = Arc::new(());
        bencher.bench_local(|| TlsPoolId::builder().with_shared_instance(black_box(&hook)));
    }

    #[divan::bench]
    fn shared_instance(bencher: divan::Bencher) {
        let hook = Arc::new(());
        bencher.bench_local(|| {
            TlsPoolId::builder()
                .with_shared_instance(black_box(&hook))
                .build()
        });
    }

    struct Verifier(Arc<()>);

    impl TlsPoolComponent for Verifier {
        type Identity = TlsComponentIdentity<()>;

        fn pool_component_identity(&self) -> Self::Identity {
            TlsComponentIdentity::shared(&self.0)
        }
    }

    struct ConfigHook(Arc<()>);

    impl TlsPoolComponent for ConfigHook {
        type Identity = TlsComponentIdentity<()>;

        fn pool_component_identity(&self) -> Self::Identity {
            TlsComponentIdentity::shared(&self.0)
        }
    }

    #[divan::bench]
    fn shared_verifier_hook_and_keylog(bencher: divan::Bencher) {
        let keylog = TlsKeyLog(KeyLogIntent::Custom(Arc::new(NoopKeyLogSink)));
        let verifier = Arc::new(Verifier(Arc::new(())));
        let hook = Arc::new(ConfigHook(Arc::new(())));
        bencher.bench_local(|| {
            TlsPoolId::builder()
                .with_keylog(black_box(&keylog))
                .with_component(black_box(verifier.as_ref()))
                .with_component(black_box(hook.as_ref()))
                .build()
        });
    }

    #[divan::bench]
    fn verifier_with_shared_hook_and_keylog(bencher: divan::Bencher) {
        let keylog = TlsKeyLog(KeyLogIntent::Custom(Arc::new(NoopKeyLogSink)));
        let verifier = Verifier(Arc::new(()));
        let hook = Arc::new(());
        bencher.bench_local(|| {
            TlsPoolId::builder()
                .with_keylog(black_box(&keylog))
                .with_component(black_box(&verifier))
                .with_shared_instance(black_box(&hook))
                .build()
        });
    }

    struct PolicyRevision(u64);

    impl TlsPoolComponent for PolicyRevision {
        type Identity = u64;

        fn pool_component_identity(&self) -> Self::Identity {
            self.0
        }
    }

    #[divan::bench]
    fn value_identity(bencher: divan::Bencher) {
        let policy = PolicyRevision(1);
        bencher.bench_local(|| {
            TlsPoolId::builder()
                .with_component(black_box(&policy))
                .build()
        });
    }

    #[divan::bench]
    fn clone_shared_identity(bencher: divan::Bencher) {
        let keylog = TlsKeyLog(KeyLogIntent::Custom(Arc::new(NoopKeyLogSink)));
        let identity = TlsPoolId::builder().with_keylog(&keylog).build().unwrap();
        bencher.bench_local(|| black_box(&identity).clone());
    }
}

/// Boxing an unpolled connector isolates future storage from network and TLS
/// work. Pooled requests still construct this future, so its allocation size
/// matters even when no new handshake runs.
#[divan::bench]
fn pooled_connector_future(bencher: divan::Bencher) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let connector = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .without_tls_support()
        .with_default_http_connector::<Body>(Executor::default())
        .with_default_connection_pool()
        .build_connector();

    bencher
        .with_inputs(|| {
            Request::get("http://example.com/")
                .body(Body::empty())
                .unwrap()
        })
        .bench_local_values(|request| black_box(Box::pin(connector.serve(request))));
}

#[cfg(feature = "rustls")]
#[divan::bench]
fn pooled_tls_connector_future(bencher: divan::Bencher) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let connector = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_rustls(TlsClientConfig::new())
        .with_default_http_connector::<Body>(Executor::default())
        .with_default_connection_pool()
        .build_connector();

    bencher
        .with_inputs(|| {
            Request::get("https://example.com/")
                .body(Body::empty())
                .unwrap()
        })
        .bench_local_values(|request| black_box(Box::pin(connector.serve(request))));
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
mod roundtrip {
    use rama::{
        Layer, Service,
        bytes::Bytes,
        http::{
            Body, Request, Version, body::util::BodyExt as _, client::EasyHttpWebClient,
            server::HttpServer, service::web::response::IntoResponse as _,
        },
        net::{address::SocketAddress, tls::ApplicationProtocol},
        rt::Executor,
        service::service_fn,
        tcp::server::TcpListener,
        tls::{
            client::{ServerVerifyMode, TlsClientConfig},
            rustls::server::TlsAcceptorLayer,
            server::{GeneratedServerAuthConfig, TlsServerConfig},
        },
    };
    use std::{convert::Infallible, hint::black_box};

    const WARMUP_REQUESTS: usize = 200;

    /// Measure complete pooled requests, including inner connector futures and
    /// selection. The server runs on another thread so its allocations do not
    /// appear in the client thread's allocation profile.
    fn measure(bencher: divan::Bencher, version: Version, discovery: bool) {
        let server_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let protocol = if version == Version::HTTP_2 {
            ApplicationProtocol::HTTP_2
        } else {
            ApplicationProtocol::HTTP_11
        };
        let address = server_runtime.block_on(async {
            let listener = TcpListener::build(Executor::new())
                .bind_address(SocketAddress::local_ipv4(0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let tls = TlsServerConfig::new()
                .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
                .unwrap()
                .with_alpn([protocol.clone()].into_iter().collect());
            let http =
                HttpServer::auto(Executor::new()).service(service_fn(|_request: Request| async {
                    Ok::<_, Infallible>(Bytes::from_static(b"ok").into_response())
                }));
            server_runtime.spawn(async move {
                listener
                    .serve(TlsAcceptorLayer::new(tls).into_layer(http))
                    .await;
            });
            address
        });
        let client_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = client_runtime.enter();
        let tls = TlsClientConfig::new()
            .with_alpn([protocol].into_iter().collect())
            .with_server_verify(ServerVerifyMode::Disable);
        let builder = EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .with_tls_support_using_rustls(tls)
            .with_default_http_connector::<Body>(Executor::new())
            .with_default_connection_pool();
        let builder = if discovery {
            builder
        } else {
            builder.without_alt_svc()
        };
        let client = builder.build_client().boxed();
        let uri = format!("https://{address}/");
        let request = || {
            Request::builder()
                .uri(uri.as_str())
                .version(version)
                .body(Body::empty())
                .unwrap()
        };
        client_runtime.block_on(async {
            for _ in 0..WARMUP_REQUESTS {
                let response = client.serve(request()).await.unwrap();
                assert_eq!(response.version(), version);
                assert_eq!(
                    response.into_body().collect().await.unwrap().to_bytes(),
                    "ok"
                );
            }
        });
        bencher.with_inputs(request).bench_local_values(|request| {
            let bytes = client_runtime.block_on(async {
                let response = client.serve(request).await.unwrap();
                response.into_body().collect().await.unwrap().to_bytes()
            });
            // Release each receive buffer before the next pooled request.
            drop(black_box(bytes));
        });
    }

    #[divan::bench(args = [Version::HTTP_11, Version::HTTP_2], sample_count = 100)]
    fn pooled_tls_requests(bencher: divan::Bencher, version: Version) {
        measure(bencher, version, true);
    }

    #[divan::bench(args = [Version::HTTP_11, Version::HTTP_2], sample_count = 100)]
    fn pooled_tls_requests_without_discovery(bencher: divan::Bencher, version: Version) {
        measure(bencher, version, false);
    }
}
