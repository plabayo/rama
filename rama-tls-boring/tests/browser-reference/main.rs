//! Browser-driven ECH reference server; launched by ech_reference.py.

#[path = "../support/ech_keys.rs"]
mod fixtures;

use fixtures::{SERVER_ECH_CONFIG, SERVER_ECH_KEY};
use rama_core::error::BoxError;
use rama_utils::octets::kib;

#[tokio::test]
async fn browser_ech_reference() {
    use rama_core::{Service, ServiceInput, extensions::ExtensionsRef, service::service_fn};
    use rama_net::address::Domain;
    use rama_tls::{
        SecureTransport,
        server::{
            GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData, ServerEchAccepted,
            TlsServerConfig,
        },
    };
    use rama_tls_boring::server::{
        BoringServerConfigExt as _, EchServerKey, EchServerKeys, TlsAcceptorService,
    };
    use rama_ua::profile::{
        capture::completeness::ProfileCaptureCompleteness,
        capture::tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };

    let dir = std::path::PathBuf::from(
        std::env::var_os("RAMA_ECH_BROWSER_EVIDENCE").expect("evidence directory"),
    );
    let leaf = LeafCertRequest {
        identities: ["origin.test", "baseline.test", "doh.test", "ech.com"]
            .map(|host| Domain::try_from(host).unwrap().into())
            .to_vec(),
        ..Default::default()
    };
    let auth =
        ServerAuthData::new_generated(GeneratedServerAuthConfig::SelfSignedLeaf(leaf)).unwrap();
    let cert = rama_boring::x509::X509::from_der(&auth.cert_chain[0]).unwrap();
    let private =
        rama_boring::pkey::PKey::private_key_from_der(auth.private_key.secret_der()).unwrap();
    std::fs::write(dir.join("server.pem"), cert.to_pem().unwrap()).unwrap();
    std::fs::write(
        dir.join("server-key.pem"),
        private.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    let keys =
        EchServerKeys::new([EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, true)]).unwrap();
    std::fs::write(dir.join("ech-config.bin"), keys.retry_configs()).unwrap();
    let output = dir.clone();
    let service =
        TlsAcceptorService::new(
            TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn_http_1()
                .with_ech_keys(keys),
            service_fn(
                move |mut stream: rama_tls_boring::TlsStream<ServiceInput<TcpStream>>| -> std::pin::Pin<
                    Box<dyn Future<Output = Result<(), BoxError>> + Send>,
                > {
                    let dir = output.clone();
                    Box::pin(async move {
                        let accepted = stream
                            .extensions()
                            .get_ref::<ServerEchAccepted>()
                            .unwrap()
                            .0;
                        let hello = stream
                            .extensions()
                            .get_ref::<SecureTransport>()
                            .unwrap()
                            .client_hello()
                            .unwrap();
                        let name = if accepted { "inner" } else { "baseline" };
                        let capture = TlsCapture::capture(
                            ProfileCaptureCompleteness::Complete,
                            TlsCaptureTransport::Tcp,
                            hello,
                            TlsCaptureLimits::default(),
                        )?;
                        std::fs::write(
                            dir.join(format!("{name}.json")),
                            serde_json::to_vec_pretty(&capture)?,
                        )?;
                        std::fs::write(
                            dir.join(format!("{name}.canonical")),
                            &capture.canonical(TlsCaptureLimits::default())?.bytes,
                        )?;
                        if let Some(observation) = stream
                            .extensions()
                            .get_ref::<rama_tls::server::EchServerObservation>(
                        ) {
                            let outer = TlsCapture::capture(
                                ProfileCaptureCompleteness::Complete,
                                TlsCaptureTransport::Tcp,
                                &observation.outer,
                                TlsCaptureLimits::default(),
                            )?;
                            std::fs::write(
                                dir.join(format!("{name}-outer.json")),
                                serde_json::to_vec_pretty(&outer)?,
                            )?;
                            std::fs::write(
                                dir.join(format!("{name}-outer.canonical")),
                                &outer.canonical(TlsCaptureLimits::default())?.bytes,
                            )?;
                        }
                        let mut bytes = [0; kib(16)];
                        let n = stream.read(&mut bytes).await?;
                        if n != 0 {
                            let body = format!("ECH accepted: {accepted}");
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            stream.write_all(response.as_bytes()).await?;
                            stream.flush().await?;
                        }
                        Ok::<_, BoxError>(())
                    })
                },
            ),
            true,
        );
    let service = service.boxed();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    std::fs::write(
        dir.join("ready.json"),
        serde_json::to_vec(&serde_json::json!({"port": listener.local_addr().unwrap().port()}))
            .unwrap(),
    )
    .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    while let Ok(Ok((stream, _))) = tokio::time::timeout_at(deadline, listener.accept()).await {
        let service = service.clone();
        tokio::spawn(async move {
            let mut raw = vec![0; kib(64)];
            let hello = loop {
                let n = stream.peek(&mut raw).await.unwrap();
                if n == 0 {
                    return;
                }
                if let Ok(hello) = rama_tls::client::parse_client_hello_handshake(&raw[..n]) {
                    break hello;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            };
            let input = ServiceInput::new(stream);
            input
                .extensions()
                .insert(SecureTransport::with_client_hello(hello));
            if let Err(error) = service.serve(input).await {
                eprintln!("reference handshake failed: {error}");
            }
        });
    }
}
