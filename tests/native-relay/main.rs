//! Loopback native TLS/HTTP relay fixture for independent packet comparisons.
//!
//! Build this target with `--no-default-features --features http-full,boring`.
//! The external driver supplies an origin, a local CA and an owned readiness
//! file through RAMA_NATIVE_RELAY_FIXTURE_CONFIG. SSLKEYLOGFILE records both
//! terminated legs. No user-agent profile layer or dependency is needed.

use rama::{
    Layer,
    combinators::Either,
    error::BoxError,
    graceful::Shutdown,
    http::proxy::mitm::HttpMitmRelay,
    layer::ConsumeErrLayer,
    rt::Executor,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    tls::{
        boring::{
            core::{pkey::PKey, x509::X509},
            proxy::TlsMitmRelay,
        },
        server::PeekTlsClientHelloService,
    },
};
use serde::Deserialize;
use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Deserialize)]
struct Config {
    origin: SocketAddr,
    ca: PathBuf,
    key: PathBuf,
    ready: PathBuf,
    mirror: bool,
}

#[tokio::test]
#[ignore = "long-lived fixture driven by the external native relay runner"]
async fn tcp_relay_fixture() -> Result<(), BoxError> {
    let path = std::env::var("RAMA_NATIVE_RELAY_FIXTURE_CONFIG")?;
    let config: Config = serde_json::from_slice(&fs::read(path)?)?;
    let certificate = X509::from_pem(&fs::read(config.ca)?)?;
    let key = PKey::private_key_from_pem(&fs::read(config.key)?)?;

    let shutdown = Shutdown::default();
    let executor = Executor::graceful(shutdown.guard());
    let listener = TcpListener::bind_address("127.0.0.1:0", executor.clone()).await?;
    let address = listener.local_addr()?;
    let http = HttpMitmRelay::new(executor);
    let tls = TlsMitmRelay::new_cached_in_memory(certificate, key).into_layer(http);

    // The negative control omits only ingress-derived ClientHello mirroring.
    // Both branches still terminate TLS and use the same native HTTP relay.
    let application = if config.mirror {
        Either::A(ConsumeErrLayer::default().into_layer(PeekTlsClientHelloService::new(tls)))
    } else {
        Either::B(ConsumeErrLayer::default().into_layer(tls))
    };
    let service = IoToProxyBridgeIoLayer::new(config.origin).into_layer(application);
    shutdown.spawn_task_fn(move |_guard| async move {
        listener.serve(service).await;
    });

    let pending = config.ready.with_extension("pending");
    fs::write(
        &pending,
        serde_json::to_vec(
            &serde_json::json!({ "listen": address, "ua_enabled": cfg!(feature = "ua") }),
        )?,
    )?;
    fs::rename(pending, config.ready)?;
    shutdown.shutdown_with_limit(Duration::from_secs(5)).await?;
    Ok(())
}
