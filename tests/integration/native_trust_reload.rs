use parking_lot::Mutex;
use rama::{Service, ServiceInput, extensions::ExtensionsRef, io::PrefixedIo};
use rama_crypto::{
    cert::generate_server_auth, native_certs, pem::PemBlock, pki_types::CertificateDer,
};
use rama_net::{
    Protocol,
    address::{Domain, Host, HostWithPort},
    client::{ConnectRequest, ConnectionError, ConnectionErrorKind, EstablishedClientConnection},
};
#[cfg(not(target_os = "android"))]
use rama_tls::client::PlatformTrustPolicy;
use rama_tls::{
    client::{
        ChannelReloadTrigger, ClientHandshake, NativeTrustPolicy, NativeTrustStoreChanges,
        NegotiatedTlsParameters, TlsClientConfig, TlsServerCertPinSet, TlsServerCertPins,
        TlsServerTrust, parse_client_hello_handshake,
    },
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData,
        TlsServerConfig,
    },
};
use rama_tls_boring::{
    client::{TlsClientSessionCache, TlsConnector as BoringConnector},
    core::{ssl::SslAcceptor, tokio::accept},
    server::TlsAcceptorData,
};
use rama_tls_rustls::client::TlsConnector as RustlsConnector;
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    sync::oneshot,
};

const CHILD: &str = "RAMA_NATIVE_TRUST_RELOAD_TEST_DIR";

#[test]
fn native_roots_cut_over_for_new_handshakes() {
    isolated_case("native_roots_cut_over_for_new_handshakes", |dir| {
        run(dir, |trigger| {
            NativeTrustPolicy::new().with_reload_trigger(trigger).into()
        })
    });
}

#[cfg(not(any(target_vendor = "apple", windows, target_os = "android")))]
#[test]
fn platform_fallback_cuts_over_for_new_handshakes() {
    isolated_case("platform_fallback_cuts_over_for_new_handshakes", |dir| {
        run(dir, |trigger| {
            PlatformTrustPolicy::new()
                .with_reload_trigger(trigger)
                .into()
        })
    });
}

#[cfg(any(target_vendor = "apple", windows))]
#[test]
fn platform_reload_replaces_only_environment_extra_anchors() {
    isolated_case(
        "platform_reload_replaces_only_environment_extra_anchors",
        run_platform_extras,
    );
}

fn isolated_case<F>(name: &str, run: impl FnOnce(PathBuf) -> F)
where
    F: std::future::Future<Output = ()>,
{
    // The snapshot loader reads process environment and initializes global caches.
    // An isolated test process lets the two backends share the test fixture.
    if let Some(dir) = std::env::var_os(CHILD) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(15), run(PathBuf::from(dir)))
                .await
                .expect("TLS test timed out");
        });
        return;
    }

    let dir = std::env::temp_dir().join(format!("rama-{name}-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    fs::create_dir(dir.join("roots")).unwrap();
    fs::create_dir(dir.join("extras")).unwrap();
    let case = format!("native_trust_reload::{name}");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &case, "--nocapture"])
        .env(CHILD, &dir)
        .env("SSL_CERT_FILE", dir.join("bundle.pem"))
        .env("SSL_CERT_EXTRA_FILE", dir.join("extra.pem"))
        .env("SSL_CERT_DIR", dir.join("roots"))
        .env("SSL_CERT_EXTRA_DIR", dir.join("extras"))
        .spawn()
        .unwrap();
    // Keep a wall-clock deadline outside the runtime under test. Its own
    // timeout cannot fire if a regression blocks its only worker.
    let start = Instant::now();
    let succeeded = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.success();
        }
        if start.elapsed() >= Duration::from_secs(20) {
            _ = child.kill();
            _ = child.wait().unwrap();
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    fs::remove_dir_all(dir).unwrap();
    assert!(succeeded, "{name} subprocess failed or timed out");
}

async fn run(dir: PathBuf, trust: impl FnOnce(ChannelReloadTrigger) -> TlsServerTrust) {
    let bundle = dir.join("bundle.pem");
    let extra = dir.join("extra.pem");
    let (a, anchor_a) = certified_peer();
    let (b, anchor_b) = certified_peer();
    write_bundle(&bundle, &anchor_a);
    fs::write(&extra, b"").unwrap();

    let static_native = native_certs::shared_native_trust_anchors();
    let static_extras = native_certs::shared_extra_trust_anchors();

    let use_b = Arc::new(AtomicBool::new(false));
    let dial = Dial {
        a,
        b,
        use_b: use_b.clone(),
        pause: Arc::default(),
    };
    let (reload, trigger) = ChannelReloadTrigger::new();
    let policy = trust(trigger);
    let boring = Arc::new(
        BoringConnector::secure(dial.clone())
            .with_base_config(TlsClientConfig::new().with_server_trust(policy.clone()))
            .with_session_store(Arc::new(TlsClientSessionCache::default())),
    );
    // Pins for another name select the pin-aware verifiers without rejecting this peer.
    let pinned = TlsClientConfig::new()
        .with_server_trust(policy.clone())
        .with_server_cert_pins(TlsServerCertPins::new(
            TlsServerCertPinSet::new(anchor_b.clone())
                .with_server_name(Domain::from_static("pinned.test")),
        ));
    let pinned_boring = BoringConnector::secure(dial.clone()).with_base_config(pinned.clone());
    let pinned_rustls = RustlsConnector::secure(dial.clone()).with_base_config(pinned);
    let rustls = Arc::new(
        RustlsConnector::secure(dial.clone())
            .with_base_config(TlsClientConfig::new().with_server_trust(policy)),
    );
    let boring_snapshot = BoringConnector::secure(dial.clone());
    let rustls_snapshot = RustlsConnector::secure(dial.clone());
    let auto_rustls = RustlsConnector::secure(dial.clone()).with_base_config(
        TlsClientConfig::new().with_server_trust(
            NativeTrustPolicy::new()
                .with_reload_trigger(NativeTrustStoreChanges::new(Duration::from_millis(20))),
        ),
    );
    let strict_rustls = RustlsConnector::secure(dial.clone()).with_base_config(
        TlsClientConfig::new()
            .with_server_trust(NativeTrustPolicy::new().with_max_age(Duration::ZERO)),
    );

    let mut existing = rustls.serve(request()).await.unwrap().conn;
    read_server_byte(&mut existing).await;
    read_server_byte(&mut strict_rustls.serve(request()).await.unwrap().conn).await;
    read_server_byte(&mut auto_rustls.serve(request()).await.unwrap().conn).await;
    read_server_byte(&mut boring_snapshot.serve(request()).await.unwrap().conn).await;
    read_server_byte(&mut rustls_snapshot.serve(request()).await.unwrap().conn).await;
    read_server_byte(&mut pinned_boring.serve(request()).await.unwrap().conn).await;
    read_server_byte(&mut pinned_rustls.serve(request()).await.unwrap().conn).await;

    let mut first = boring.serve(request()).await.unwrap().conn;
    read_server_byte(&mut first).await;
    assert!(!resumed(&first));
    let mut repeat = boring.serve(request()).await.unwrap().conn;
    read_server_byte(&mut repeat).await;
    assert!(resumed(&repeat));

    reload.request_reload().unwrap();
    let mut unchanged = boring.serve(request()).await.unwrap().conn;
    read_server_byte(&mut unchanged).await;
    assert!(resumed(&unchanged));

    // Failed refreshes retain the last valid snapshot, except for a handshake
    // that requires a fresh read.
    fs::write(&bundle, b"not a certificate bundle").unwrap();
    reload.request_reload().unwrap();
    read_server_byte(&mut rustls.serve(request()).await.unwrap().conn).await;
    drop(strict_rustls.serve(request()).await.unwrap_err());

    // Hold one full handshake from each backend after the peer has seen
    // ClientHello but before it returns the certificate chain.
    let (rustls_hello, rustls_resume) = dial.pause_next_handshake();
    let rustls_pending = tokio::spawn({
        let rustls = rustls.clone();
        async move {
            let request = request();
            request.extensions().insert(ClientHandshake::Full);
            rustls.serve(request).await
        }
    });
    rustls_hello.await.unwrap();

    let (boring_hello, boring_resume) = dial.pause_next_handshake();
    let boring_pending = tokio::spawn({
        let boring = boring.clone();
        async move {
            let request = request();
            request.extensions().insert(ClientHandshake::Full);
            boring.serve(request).await
        }
    });
    boring_hello.await.unwrap();

    // Successfully reading an empty store distrusts the old certificate.
    fs::write(&bundle, b"").unwrap();
    assert!(Arc::ptr_eq(
        &static_native,
        &native_certs::shared_native_trust_anchors()
    ));
    assert!(Arc::ptr_eq(
        &static_extras,
        &native_certs::shared_extra_trust_anchors()
    ));
    reload.request_reload().unwrap();
    drop(rustls.serve(request()).await.unwrap_err());
    drop(boring.serve(request()).await.unwrap_err()); // A's tickets cannot bypass distrust
    // Both backends reject at the handshake, not while building their configuration.
    let boring_error = pinned_boring.serve(request()).await.unwrap_err();
    let rustls_error = pinned_rustls.serve(request()).await.unwrap_err();
    assert_ne!(rustls_error.kind(), ConnectionErrorKind::InvalidInput);
    assert_eq!(rustls_error.kind(), boring_error.kind());
    rustls_resume.send(()).unwrap();
    boring_resume.send(()).unwrap();
    let mut held_rustls = rustls_pending.await.unwrap().unwrap().conn;
    read_server_byte(&mut held_rustls).await;
    assert!(!resumed(&held_rustls));
    let mut pinned_boring = boring_pending.await.unwrap().unwrap().conn;
    read_server_byte(&mut pinned_boring).await;
    assert!(!resumed(&pinned_boring));
    read_server_byte(&mut rustls_snapshot.serve(request()).await.unwrap().conn).await;
    read_server_byte(&mut boring_snapshot.serve(request()).await.unwrap().conn).await;

    existing.write_all(b"x").await.unwrap();
    assert_eq!(existing.read_u8().await.unwrap(), b'x');

    write_bundle(&dir.join("extra-replacement.pem"), &anchor_b);
    fs::rename(dir.join("extra-replacement.pem"), &extra).unwrap();
    reload.request_reload().unwrap();
    use_b.store(true, Ordering::Relaxed);
    read_server_byte(&mut rustls.serve(request()).await.unwrap().conn).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(mut updated) = auto_rustls.serve(request()).await {
                read_server_byte(&mut updated.conn).await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the file watcher should pick up the replacement CA");
    let mut replacement = boring.serve(request()).await.unwrap().conn;
    read_server_byte(&mut replacement).await;
    assert!(!resumed(&replacement));
    drop(rustls_snapshot.serve(request()).await.unwrap_err());
    drop(boring_snapshot.serve(request()).await.unwrap_err());
}

#[cfg(any(target_vendor = "apple", windows))]
async fn run_platform_extras(dir: PathBuf) {
    let (a, anchor_a) = certified_peer();
    let (b, anchor_b) = certified_peer();
    let use_b = Arc::new(AtomicBool::new(false));
    let dial = Dial {
        a,
        b,
        use_b: use_b.clone(),
        pause: Arc::default(),
    };

    // Both replacement paths contain A. An OS verifier must ignore both.
    write_bundle(&dir.join("bundle.pem"), &anchor_a);
    write_bundle(&dir.join("roots/a.pem"), &anchor_a);
    let extra_file = dir.join("extra.pem");
    fs::write(&extra_file, b"").unwrap();

    let (reload, trigger) = ChannelReloadTrigger::new();
    let policy: TlsServerTrust = PlatformTrustPolicy::new()
        .with_reload_trigger(trigger)
        .into();
    let explicit_a = RustlsConnector::secure(dial.clone()).with_base_config(
        TlsClientConfig::new().with_server_trust(
            policy
                .clone()
                .try_with_additional_anchors([anchor_a.clone()])
                .unwrap(),
        ),
    );
    let strict = RustlsConnector::secure(dial.clone()).with_base_config(
        TlsClientConfig::new()
            .with_server_trust(PlatformTrustPolicy::new().with_max_age(Duration::ZERO)),
    );
    let config = TlsClientConfig::new().with_server_trust(policy);
    let boring = BoringConnector::secure(dial.clone())
        .with_base_config(config.clone())
        .with_session_store(Arc::new(TlsClientSessionCache::default()));
    let rustls = RustlsConnector::secure(dial).with_base_config(config);
    drop(rustls.serve(request()).await.unwrap_err());
    drop(boring.serve(request()).await.unwrap_err());
    read_server_byte(&mut explicit_a.serve(request()).await.unwrap().conn).await;

    write_bundle(&extra_file, &anchor_a);
    reload.request_reload().unwrap();
    let mut existing = rustls.serve(request()).await.unwrap().conn;
    read_server_byte(&mut existing).await;
    read_server_byte(&mut boring.serve(request()).await.unwrap().conn).await;
    let mut repeat = boring.serve(request()).await.unwrap().conn;
    read_server_byte(&mut repeat).await;
    assert!(resumed(&repeat));

    // A trigger event can report a system trust change that the extra roots do not show.
    reload.request_reload().unwrap();
    let mut after_event = boring.serve(request()).await.unwrap().conn;
    read_server_byte(&mut after_event).await;
    assert!(!resumed(&after_event));
    read_server_byte(&mut strict.serve(request()).await.unwrap().conn).await;

    // A malformed extra file keeps the last good verifier until its age limit.
    fs::write(&extra_file, b"broken certificate bundle").unwrap();
    reload.request_reload().unwrap();
    read_server_byte(&mut rustls.serve(request()).await.unwrap().conn).await;
    drop(strict.serve(request()).await.unwrap_err());

    // Move trust from the extra file to the extra directory. The old CA
    // remains in SSL_CERT_DIR, and the replacement bundle is now unreadable.
    fs::remove_file(dir.join("bundle.pem")).unwrap();
    fs::write(&extra_file, b"").unwrap();
    write_bundle(&dir.join("extras/b.pem"), &anchor_b);
    reload.request_reload().unwrap();
    drop(boring.serve(request()).await.unwrap_err());
    drop(rustls.serve(request()).await.unwrap_err());
    read_server_byte(&mut explicit_a.serve(request()).await.unwrap().conn).await;

    existing.write_all(b"x").await.unwrap();
    assert_eq!(existing.read_u8().await.unwrap(), b'x');
    use_b.store(true, Ordering::Relaxed);
    read_server_byte(&mut rustls.serve(request()).await.unwrap().conn).await;
    let mut replacement = boring.serve(request()).await.unwrap().conn;
    read_server_byte(&mut replacement).await;
    assert!(!resumed(&replacement));
}

#[cfg(unix)]
#[test]
fn trust_file_reload_leaves_the_async_runtime_free() {
    isolated_case(
        "trust_file_reload_leaves_the_async_runtime_free",
        |dir| async move {
            let bundle = dir.join("bundle.pem");
            let extra = dir.join("extra.pem");
            let (peer, anchor) = certified_peer();
            let pem = PemBlock::new("CERTIFICATE", &anchor).to_pem();
            fs::write(&bundle, &pem).unwrap();
            fs::write(&extra, b"").unwrap();

            let dial = Dial {
                a: peer.clone(),
                b: peer,
                use_b: Arc::default(),
                pause: Arc::default(),
            };
            let (rustls_reload, trigger) = ChannelReloadTrigger::new();
            let rustls = RustlsConnector::secure(dial.clone()).with_base_config(
                TlsClientConfig::new()
                    .with_server_trust(NativeTrustPolicy::new().with_reload_trigger(trigger)),
            );
            let (boring_reload, trigger) = ChannelReloadTrigger::new();
            let boring = BoringConnector::secure(dial).with_base_config(
                TlsClientConfig::new()
                    .with_server_trust(NativeTrustPolicy::new().with_reload_trigger(trigger)),
            );

            read_server_byte(&mut rustls.serve(request()).await.unwrap().conn).await;
            read_server_byte(&mut boring.serve(request()).await.unwrap().conn).await;
            fs::remove_file(&bundle).unwrap();
            assert!(
                Command::new("mkfifo")
                    .arg(&bundle)
                    .status()
                    .unwrap()
                    .success()
            );

            rustls_reload.request_reload().unwrap();
            assert_async_progress_during_trust_read(&bundle, &pem, rustls.serve(request())).await;
            boring_reload.request_reload().unwrap();
            assert_async_progress_during_trust_read(&bundle, &pem, boring.serve(request())).await;
        },
    );
}

#[cfg(unix)]
async fn assert_async_progress_during_trust_read<T>(
    bundle: &Path,
    pem: &str,
    handshake: impl std::future::Future<
        Output = Result<EstablishedClientConnection<T, ConnectRequest>, ConnectionError>,
    >,
) where
    T: AsyncRead + Unpin,
{
    use std::io::Write as _;

    let (opened, read_started) = oneshot::channel();
    let (runtime_progressed, runtime_response) = std::sync::mpsc::sync_channel(1);
    let bundle = bundle.to_owned();
    let pem = pem.to_owned();

    let writer = std::thread::spawn(move || {
        // Opening the FIFO for writes only succeeds once the trust loader is
        // reading. Leave it blocked until a second runtime task responds.
        let mut pipe = fs::OpenOptions::new().write(true).open(bundle).unwrap();
        opened.send(()).unwrap();
        let made_progress = runtime_response
            .recv_timeout(Duration::from_secs(5))
            .is_ok();
        // Close the pipe even on regression so the test fails instead of
        // leaving the synchronous reader blocked indefinitely.
        pipe.write_all(pem.as_bytes()).unwrap();
        made_progress
    });
    let other_task = tokio::spawn(async move {
        read_started.await.unwrap();
        // A disconnected receiver means the writer already timed out, which
        // the assertion below reports.
        _ = runtime_progressed.send(());
    });

    read_server_byte(&mut handshake.await.unwrap().conn).await;
    other_task.await.unwrap();
    assert!(
        writer.join().unwrap(),
        "the Tokio runtime stalled during the trust file read",
    );
}

fn request() -> ConnectRequest {
    ConnectRequest::new(HostWithPort::new(Host::from_static("reload.test"), 443))
        .with_application_protocol(Protocol::HTTPS)
}

fn resumed(conn: &impl ExtensionsRef) -> bool {
    conn.extensions()
        .get_ref::<NegotiatedTlsParameters>()
        .and_then(|params| params.resumed)
        .unwrap()
}

async fn read_server_byte(io: &mut (impl AsyncRead + Unpin)) {
    assert_eq!(io.read_u8().await.unwrap(), b't');
}

fn write_bundle(path: &Path, anchor: &CertificateDer<'_>) {
    fs::write(path, PemBlock::new("CERTIFICATE", anchor).to_pem()).unwrap();
}

fn certified_peer() -> (SslAcceptor, CertificateDer<'static>) {
    let (cert_chain, private_key) = generate_server_auth(GeneratedServerAuthConfig::GeneratedCa {
        ca: Default::default(),
        leaf: LeafCertRequest {
            config: Default::default(),
            identities: [CertificateIdentity::Dns(Domain::from_static("reload.test"))].into(),
        },
    })
    .unwrap();
    let root = cert_chain.last().unwrap().clone();
    let config = TlsServerConfig::new().with_single_cert(ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    });
    let acceptor = TlsAcceptorData::try_from(&config)
        .unwrap()
        .into_static_acceptor_builder()
        .unwrap()
        .build();
    (acceptor, root)
}

#[derive(Clone)]
struct Dial {
    a: SslAcceptor,
    b: SslAcceptor,
    use_b: Arc<AtomicBool>,
    pause: Arc<Mutex<Option<PauseHandshake>>>,
}

struct PauseHandshake {
    hello: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

impl Dial {
    fn pause_next_handshake(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (arrived, hello) = oneshot::channel();
        let (resume, continue_handshake) = oneshot::channel();
        let previous = self.pause.lock().replace(PauseHandshake {
            hello: arrived,
            resume: continue_handshake,
        });
        assert!(previous.is_none());
        (hello, resume)
    }
}

impl Service<ConnectRequest> for Dial {
    type Output = EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let acceptor = if self.use_b.load(Ordering::Relaxed) {
            self.b.clone()
        } else {
            self.a.clone()
        };
        let pause = self.pause.lock().take();
        tokio::spawn(async move {
            let mut prefix = Vec::new();
            if let Some(pause) = pause {
                let mut header = [0; 5];
                server.read_exact(&mut header).await.unwrap();
                prefix.extend(header);
                prefix.resize(
                    5 + usize::from(u16::from_be_bytes([header[3], header[4]])),
                    0,
                );
                server.read_exact(&mut prefix[5..]).await.unwrap();
                parse_client_hello_handshake(&prefix).unwrap();
                pause.hello.send(()).unwrap();
                pause.resume.await.unwrap();
            }
            let server = PrefixedIo::new(Cursor::new(prefix), ServiceInput::new(server));
            if let Ok(mut stream) = accept(&acceptor, server).await {
                // Reading the marker also lets the client store any TLS 1.3 tickets.
                if stream.write_all(b"t").await.is_ok()
                    && let Ok(echo) = stream.read_u8().await
                {
                    drop(stream.write_u8(echo).await);
                }
            }
        });
        Ok(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    }
}
