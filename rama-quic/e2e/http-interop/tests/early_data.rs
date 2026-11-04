//! Early HTTP and explicit 425 recovery against the independent quic-go peer.
//! The Rama client deliberately uses no Retry layer or RetryBody.
use interop_common::{backend, identity};
use rama::{
    Service as _,
    crypto::pem::PemEncode as _,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    http::{
        Body, Request, Response, StatusCode,
        body::util::BodyExt as _,
        core::h3::{client, connection::Config},
        proto::ext::early_data::{EarlyDataAttempt, EarlyDataReceived},
        server::HttpServer,
    },
    net::tls::{ApplicationProtocol, EarlyDataPermit, ForbidEarlyData},
    quic::{Endpoint, TransportConfig},
    rt::Executor,
    service::service_fn,
    tls::{client::TlsClientConfig, server::TlsServerConfig},
    utils::fs::tempdir,
};
use std::{
    convert::Infallible,
    net::SocketAddr,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    process::Command,
    task::JoinSet,
    time::timeout,
};

fn peer() -> Command {
    let mut command =
        Command::new(std::env::var("RAMA_HTTP_INTEROP_PEER").expect("build the Go interop peer"));
    command.arg("early").kill_on_drop(true);
    command
}

fn request(address: SocketAddr, path: &str, caller: &Extensions) -> Request {
    Request::builder_with_extensions(caller.fork())
        .uri(format!("https://{address}/{path}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
#[ignore = "requires the independent Go peer; run with the interop recipe"]
async fn custom_rama_owner_recovers_quic_go_425_without_retry_layer() -> Result<(), BoxError> {
    timeout(Duration::from_secs(30), async {
        let directory = tempdir()?;
        let auth = identity::server_identity();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, auth.cert_chain.iter().map(|c| c.to_pem()).collect::<String>())?;
        std::fs::write(&key, auth.private_key.to_pem())?;
        let mut process = peer().args(["-mode", "server", "-cert"]).arg(cert).arg("-key").arg(key)
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
        let mut lines = BufReader::new(process.stdout.take().unwrap()).lines();
        let ready: serde_json::Value = serde_json::from_str(&lines.next_line().await?.ok_or("no readiness")?)?;
        let address: SocketAddr = ready["address"].as_str().ok_or("no address")?.parse()?;
        let executor = Executor::new();
        let endpoint = Endpoint::build(executor.clone()).bind_address("127.0.0.1:0".parse::<SocketAddr>()?).await?;
        let tls = TlsClientConfig::new().try_with_server_trust_anchors(auth.cert_chain)?
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let config = backend::tls_provider().client_config(&tls, backend::options().with_early_data(true))?;
        let caller = Extensions::new();
        let warm = endpoint.connect_with(config.clone(), address, "localhost")?.await?;
        let (mut sender, driver) = client::handshake::<Body, _>(warm.clone(), Config::default(), executor.clone())?;
        let driving = tokio::spawn(driver.run());
        let response = sender.send_request(request(address, "warm", &caller)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        warm.close(0u32, b"warm complete");
        drop(sender);
        let _ = driving.await?;
        endpoint.wait_idle().await;

        let (connection, accepted) = endpoint.connect_with(config, address, "localhost")?
            .into_0rtt().map_err(|_| "missing early ticket")?;
        let (mut sender, driver) = client::handshake::<Body, _>(connection.clone(), Config { early_requests: true, ..Config::default() }, executor)?;
        let driving = tokio::spawn(driver.run());
        let first = request(address, "operation", &caller);
        first.extensions().insert(EarlyDataPermit::with_recovery_owner());
        let response = sender.send_request(first).await?;
        assert_eq!(response.status(), StatusCode::TOO_EARLY);
        assert!(response.extensions().get_ref::<EarlyDataAttempt>().is_some_and(|attempt| attempt.permits_425_recovery()));
        assert!(accepted.await?, "TLS accepted actual early data");
        assert_eq!(response.headers()["x-quic-used-0rtt"], "true");
        assert_eq!(response.headers()["x-rejection"], "preserved");
        assert_eq!(response.into_body().collect().await?.to_bytes(), "retry after confirmation");
        assert!(!caller.contains::<EarlyDataPermit>(), "permit is attempt-local");

        // This custom owner reconstructs a known-empty request and bounds recovery
        // to one attempt. Forbid remains in the caller store for future attempts.
        caller.insert(ForbidEarlyData::default());
        connection.handshake_confirmed().await?;
        let mut retry = request(address, "operation", &caller);
        retry.headers_mut().insert("x-confirmed", "1".parse()?);
        let response = sender.send_request(retry).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.extensions().contains::<EarlyDataAttempt>());
        assert_eq!(response.into_body().collect().await?.to_bytes(), "processed once");
        println!("Rama -> quic-go: actual early send, 425 preserved, one confirmed recovery without Retry");
        connection.close(0u32, b"done");
        let _ = driving.await?;
        endpoint.shutdown().await;
        process.kill().await?;
        process.wait().await?;
        Ok(())
    }).await?
}

#[tokio::test]
#[ignore = "requires the independent Go peer; run with the interop recipe"]
async fn quic_go_early_client_recovers_rama_425() -> Result<(), BoxError> {
    timeout(Duration::from_secs(30), async {
        let directory = tempdir()?;
        let auth = identity::server_identity();
        let cert = directory.path().join("cert.pem");
        std::fs::write(
            &cert,
            auth.cert_chain
                .iter()
                .map(|c| c.to_pem())
                .collect::<String>(),
        )?;
        let executor = Executor::new();
        let mut server = HttpServer::new_http3(executor.clone());
        server.http3_mut().early_dispatch = true;
        let tls = TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let options = backend::options()
            .with_early_data(true)
            .with_early_data_context(server.http3().early_data_context()?);
        let mut transport = TransportConfig::default();
        server.http3().configure_transport(&mut transport)?;
        let config = backend::server_tls_provider()
            .server_config(&tls, options)?
            .with_transport_config(Arc::new(transport));
        let endpoint = Endpoint::build(executor)
            .with_server_config(config)
            .bind_address("127.0.0.1:0".parse::<SocketAddr>()?)
            .await?;
        let early = Arc::new(AtomicUsize::new(0));
        let processed = Arc::new(AtomicUsize::new(0));
        let service = server.service(service_fn({
            let early = early.clone();
            let processed = processed.clone();
            move |request: Request| {
                let status = if request.uri().path_or_root() == "/warm" {
                    StatusCode::OK
                } else if request.extensions().contains::<EarlyDataReceived>() {
                    early.fetch_add(1, Ordering::SeqCst);
                    StatusCode::TOO_EARLY
                } else {
                    assert_eq!(request.headers()["x-confirmed"], "1");
                    processed.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK
                };
                async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Body::from("processed once"))
                            .unwrap(),
                    )
                }
            }
        }));
        let accepting = endpoint.clone();
        let serving = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            while let Some(incoming) = accepting.accept().await {
                let connection = incoming
                    .accept()?
                    .into_0rtt()
                    .map_err(|_| "no server early handle")?
                    .0;
                let service = service.clone();
                handlers.spawn(async move { service.serve(connection).await });
            }
            while let Some(result) = handlers.join_next().await {
                result??;
            }
            Ok::<_, BoxError>(())
        });
        let output = peer()
            .args([
                "-mode",
                "client",
                "-address",
                &endpoint.local_addr()?.to_string(),
                "-ca",
            ])
            .arg(cert)
            .output()
            .await?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result["used_0rtt"], true);
        assert_eq!(result["recovered_425"], true);
        assert_eq!(early.load(Ordering::SeqCst), 1);
        assert_eq!(processed.load(Ordering::SeqCst), 1);
        println!("quic-go -> Rama: actual early receipt, 425, one confirmed request processed");
        endpoint.close(0u32, b"done");
        serving.await??;
        endpoint.shutdown().await;
        Ok(())
    })
    .await?
}
