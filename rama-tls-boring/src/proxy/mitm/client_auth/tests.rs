use super::*;
use crate::{
    client::{TlsConnectorData, tls_connect},
    proxy::{
        TlsMitmEgressServerAuth, TlsMitmRelay, TlsMitmRelayErrorKind,
        cert_issuer::StaticBoringMitmCertIssuer,
    },
};
use rama_boring::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod, SslVerifyMode, SslVersion},
    x509::{
        X509Name,
        extension::{BasicConstraints, SubjectAlternativeName},
        store::{X509Store, X509StoreBuilder},
    },
};
use rama_core::{ServiceInput, extensions::ExtensionsRef, io::BridgeIo};
use rama_tls::{
    KeyLogIntent,
    client::{NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig},
};
use rama_utils::collections::NonEmptyVec;
use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Relay = TlsMitmRelay<StaticBoringMitmCertIssuer>;
const VERSIONS: [SslVersion; 2] = [SslVersion::TLS1_2, SslVersion::TLS1_3];

struct Identity {
    cert: X509,
    key: PKey<Private>,
}
impl Identity {
    fn new(name: &str, issuer: Option<&Self>) -> Self {
        let key = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let mut subject = X509Name::builder().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&subject).unwrap();
        cert.set_issuer_name(issuer.map_or(&*subject, |i| i.cert.subject_name()))
            .unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        let mut constraints = BasicConstraints::new();
        constraints.critical();
        if issuer.is_none() {
            constraints.ca();
        }
        cert.append_extension(&constraints.build().unwrap())
            .unwrap();
        cert.append_extension(
            &SubjectAlternativeName::new()
                .dns("localhost")
                .build(&cert.x509v3_context(issuer.map(|i| &*i.cert), None))
                .unwrap(),
        )
        .unwrap();
        cert.sign(issuer.map_or(&key, |i| &i.key), MessageDigest::sha256())
            .unwrap();
        Self {
            cert: cert.build(),
            key,
        }
    }
    fn credential(&self) -> SslCredential {
        crate::client::ConnectorConfigClientAuth {
            cert_chain: vec![self.cert.clone()],
            private_key: self.key.clone(),
        }
        .try_into()
        .unwrap()
    }
}
struct Material {
    ca: Identity,
    server: Identity,
    guest: Identity,
    mapped: Identity,
    other_ca: Identity,
    stranger: Identity,
}
fn material() -> &'static Material {
    static MATERIAL: OnceLock<Material> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let ca = Identity::new("CA", None);
        let other_ca = Identity::new("other CA", None);
        Material {
            server: Identity::new("server", Some(&ca)),
            guest: Identity::new("guest", Some(&ca)),
            mapped: Identity::new("mapped", Some(&ca)),
            stranger: Identity::new("stranger", Some(&other_ca)),
            ca,
            other_ca,
        }
    })
}
fn store(cert: &X509) -> X509Store {
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(cert.clone()).unwrap();
    store.build()
}
fn relay() -> Relay {
    Relay::new(StaticBoringMitmCertIssuer::new(
        NonEmptyVec::new(material().server.cert.clone()),
        material().server.key.clone(),
    ))
    .with_keylog_intent(KeyLogIntent::Disabled)
    .with_egress_server_auth(
        TlsMitmEgressServerAuth::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([rama_crypto::pki_types::CertificateDer::from(
                material().ca.cert.to_der().unwrap(),
            )])
            .unwrap(),
    )
}
fn connector(version: SslVersion) -> TlsConnectorData {
    let mut data = TlsConnectorData::try_from(
        &TlsClientConfig::new()
            .with_server_name(Host::from_static("localhost"))
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([rama_crypto::pki_types::CertificateDer::from(
                material().ca.cert.to_der().unwrap(),
            )])
            .unwrap()
            .with_keylog(KeyLogIntent::Disabled),
    )
    .unwrap();
    data.config.set_min_proto_version(Some(version)).unwrap();
    data.config.set_max_proto_version(Some(version)).unwrap();
    data
}

struct Outcome {
    upstream: Result<Option<Vec<u8>>, String>,
    relay:
        Result<Option<Vec<rama_crypto::pki_types::CertificateDer<'static>>>, TlsMitmRelayErrorKind>,
    client: Result<(), String>,
}
async fn run(
    relay: &Relay,
    version: SslVersion,
    upstream_mode: SslVerifyMode,
    guest: Option<SslCredential>,
    flow_policy: Option<TlsMitmClientAuthPolicy>,
    data: Option<TlsConnectorData>,
) -> Outcome {
    run_with_options(
        relay,
        version,
        upstream_mode,
        guest,
        flow_policy,
        data,
        RunOptions::default(),
    )
    .await
}

#[derive(Default)]
struct RunOptions {
    guest_data: Option<TlsConnectorData>,
    external_timeout: Option<Duration>,
    disconnect_upstream: Option<Arc<tokio::sync::Notify>>,
}

fn upstream_acceptor(version: SslVersion, upstream_mode: SslVerifyMode) -> SslAcceptor {
    let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    server.set_min_proto_version(Some(version)).unwrap();
    server.set_max_proto_version(Some(version)).unwrap();
    server.set_certificate(&material().server.cert).unwrap();
    server.set_private_key(&material().server.key).unwrap();
    server.set_cert_store(store(&material().ca.cert));
    server.add_client_ca(&material().ca.cert).unwrap();
    server.set_verify(upstream_mode);
    server.set_alpn_select_callback(|_, _| Ok(b"http/1.1"));
    server.build()
}

async fn run_with_options(
    relay: &Relay,
    version: SslVersion,
    upstream_mode: SslVerifyMode,
    guest: Option<SslCredential>,
    flow_policy: Option<TlsMitmClientAuthPolicy>,
    data: Option<TlsConnectorData>,
    options: RunOptions,
) -> Outcome {
    let server = upstream_acceptor(version, upstream_mode);
    // Tiny buffers force partial writes and transport Pending throughout both legs.
    let (client, ingress) = tokio::io::duplex(64);
    let (egress, upstream) = tokio::io::duplex(64);
    let ingress = ServiceInput::new(ingress);
    if let Some(policy) = flow_policy {
        ingress.extensions().insert(policy);
    }
    let input = BridgeIo(ingress, ServiceInput::new(egress));
    let mut guest_data = options.guest_data.unwrap_or_else(|| connector(version));
    if let Some(guest) = guest {
        guest_data.config.add_credential(&guest).unwrap();
    }
    let upstream = async {
        let accept = rama_boring_tokio::accept(&server, upstream);
        let mut stream = if let Some(disconnect) = options.disconnect_upstream {
            tokio::select! {
                _ = disconnect.notified() => return Err("upstream disconnected during selection".into()),
                result = accept => result.map_err(|e| e.to_string())?,
            }
        } else {
            accept.await.map_err(|e| e.to_string())?
        };
        let cert = stream.ssl().peer_certificate().map(|c| c.to_der().unwrap());
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(&byte).await.map_err(|e| e.to_string())?;
        Ok(cert)
    };
    let bridge = async {
        let handshake = relay.handshake(input, Some(data.unwrap_or_else(|| connector(version))));
        let handshake = async { handshake.await.map_err(|e| e.kind()) };
        let BridgeIo(mut ingress, mut egress) = if let Some(deadline) = options.external_timeout {
            // Exercise caller-owned cancellation with the relay deadline disabled.
            tokio::time::timeout(deadline, handshake)
                .await
                .map_err(|_error| TlsMitmRelayErrorKind::Timeout)??
        } else {
            handshake.await?
        };
        let chain = ingress
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .unwrap()
            .peer_certificate_chain
            .clone();
        let mut byte = [0];
        if ingress.read_exact(&mut byte).await.is_ok()
            && egress.write_all(&byte).await.is_ok()
            && egress.read_exact(&mut byte).await.is_ok()
        {
            drop(ingress.write_all(&byte).await);
        }
        Ok(chain)
    };
    let client = async {
        let mut stream = tls_connect(ServiceInput::new(client), Some(guest_data))
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(b"x").await.map_err(|e| e.to_string())?;
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| e.to_string())?;
        if byte != *b"x" {
            return Err("bad response".into());
        }
        Ok(())
    };
    let (upstream, relay, client) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(Box::pin(upstream), Box::pin(bridge), Box::pin(client))
    })
    .await
    .expect("relay test timed out");
    Outcome {
        upstream,
        relay,
        client,
    }
}
fn required() -> SslVerifyMode {
    SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
}

#[tokio::test]
async fn default_denies_certificate_requests_but_allows_plain_tls() {
    for version in VERSIONS {
        for mode in [SslVerifyMode::NONE, SslVerifyMode::PEER, required()] {
            let result = run(&relay(), version, mode, None, None, None).await;
            assert_eq!(result.client.is_ok(), mode == SslVerifyMode::NONE);
            assert_eq!(result.relay.is_ok(), mode == SslVerifyMode::NONE);
        }
    }
}

#[tokio::test]
async fn fixed_identity_replaces_inherited_credentials_and_reports_no_ingress_identity() {
    for version in VERSIONS {
        let relay = relay().with_client_auth(TlsMitmClientAuthPolicy::fixed(
            material().mapped.credential(),
        ));
        let mut data = connector(version);
        data.config
            .add_credential(&material().guest.credential())
            .unwrap();
        let result = run(&relay, version, required(), None, None, Some(data)).await;
        assert!(result.client.is_ok(), "{:?}", result.client);
        assert_eq!(
            result.upstream.unwrap(),
            Some(material().mapped.cert.to_der().unwrap())
        );
        assert!(result.relay.unwrap().is_none());
    }
}

fn mapped_policy(calls: Arc<AtomicUsize>, fallback: bool) -> TlsMitmClientAuthPolicy {
    TlsMitmClientAuthPolicy::new(service_fn(move |input: TlsMitmClientAuthInput| {
        let calls = calls.clone();
        async move {
            if let Some(request) = &input.request
                && (request.signature_algorithms.is_empty()
                    || request.certificate_authorities.is_empty())
            {
                return Err(BoxError::from("missing CertificateRequest metadata"));
            }
            tokio::task::yield_now().await;
            let requested = input.request.is_some();
            Ok::<_, BoxError>(
                TlsMitmClientAuthPlan::new(service_fn(move |identity: TlsMitmClientIdentity| {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, SeqCst);
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        let matches = identity.leaf().map(|c| c.to_der().unwrap())
                            == Some(material().guest.cert.to_der().unwrap());
                        if !matches && !fallback {
                            return Err(BoxError::from("unmapped ingress identity"));
                        }
                        Ok(requested.then(|| {
                            if matches {
                                material().mapped.credential()
                            } else {
                                material().guest.credential()
                            }
                        }))
                    }
                }))
                .with_ingress_trust(store(&material().ca.cert)),
            )
        }
    }))
}

#[tokio::test]
async fn mapping_requires_a_trusted_matching_ingress_identity() {
    for version in VERSIONS {
        for (guest, expected, resolver_calls) in [
            (Some(material().guest.credential()), true, 1),
            (Some(material().mapped.credential()), false, 1),
            (Some(material().stranger.credential()), false, 0),
            (None, false, 0),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let guest_was_untrusted = guest.is_some() && resolver_calls == 0;
            let result = run(
                &relay().with_client_auth(mapped_policy(calls.clone(), false)),
                version,
                required(),
                guest,
                None,
                None,
            )
            .await;
            assert_eq!(result.client.is_ok(), expected, "{:?}", result.client);
            assert_eq!(calls.load(SeqCst), resolver_calls);
            if guest_was_untrusted {
                assert_eq!(
                    result.relay.as_ref().unwrap_err(),
                    &TlsMitmRelayErrorKind::ClientAuth
                );
            }
            if expected {
                assert_eq!(
                    result.upstream.unwrap(),
                    Some(material().mapped.cert.to_der().unwrap())
                );
                let chain = result.relay.unwrap().unwrap();
                assert_eq!(chain[0].as_ref(), material().guest.cert.to_der().unwrap());
            }
        }
    }
}

#[tokio::test]
async fn fallback_and_ingress_admission_without_upstream_request() {
    for version in VERSIONS {
        let calls = Arc::new(AtomicUsize::new(0));
        let relay = relay().with_client_auth(mapped_policy(calls.clone(), true));
        let result = run(
            &relay,
            version,
            required(),
            Some(material().mapped.credential()),
            None,
            None,
        )
        .await;
        result.client.unwrap();
        assert_eq!(
            result.upstream.unwrap(),
            Some(material().guest.cert.to_der().unwrap())
        );
        let result = run(
            &relay,
            version,
            SslVerifyMode::NONE,
            Some(material().guest.credential()),
            None,
            None,
        )
        .await;
        result.client.unwrap();
        assert!(result.upstream.unwrap().is_none());
        let result = run(&relay, version, SslVerifyMode::NONE, None, None, None).await;
        result.client.unwrap_err();
        assert_eq!(calls.load(SeqCst), 2);
    }
}

#[tokio::test]
async fn explicit_anonymous_response_clears_credentials_and_respects_upstream_requirement() {
    for version in VERSIONS {
        for mode in [SslVerifyMode::PEER, required()] {
            let policy =
                TlsMitmClientAuthPolicy::new(service_fn(|_: TlsMitmClientAuthInput| async {
                    Ok::<_, Infallible>(TlsMitmClientAuthPlan::fixed(None))
                }));
            let mut data = connector(version);
            data.config
                .add_credential(&material().guest.credential())
                .unwrap();
            let result = run(
                &relay().with_client_auth(policy),
                version,
                mode,
                None,
                None,
                Some(data),
            )
            .await;
            assert_eq!(result.client.is_ok(), mode == SslVerifyMode::PEER);
            if mode == SslVerifyMode::PEER {
                assert!(result.upstream.unwrap().is_none());
            }
        }
    }
}

#[tokio::test]
async fn unused_egress_credential_is_a_policy_error() {
    let policy = TlsMitmClientAuthPolicy::new(service_fn(|_: TlsMitmClientAuthInput| async {
        Ok::<_, Infallible>(TlsMitmClientAuthPlan::fixed(Some(
            material().mapped.credential(),
        )))
    }));
    let result = run(
        &relay().with_client_auth(policy),
        SslVersion::TLS1_3,
        SslVerifyMode::NONE,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(result.relay.unwrap_err(), TlsMitmRelayErrorKind::ClientAuth);
    result.client.unwrap_err();
}

struct WrongSigner;
impl rama_boring::ssl::PrivateKeyMethod for WrongSigner {
    fn sign(
        &self,
        _: &mut SslRef,
        input: &[u8],
        _: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<usize, rama_boring::ssl::PrivateKeyMethodError> {
        let mut signer =
            rama_boring::sign::Signer::new(MessageDigest::sha256(), &material().mapped.key)
                .map_err(|_error| rama_boring::ssl::PrivateKeyMethodError::FAILURE)?;
        signer
            .update(input)
            .map_err(|_error| rama_boring::ssl::PrivateKeyMethodError::FAILURE)?;
        signer
            .sign(output)
            .map_err(|_error| rama_boring::ssl::PrivateKeyMethodError::FAILURE)
    }
    fn decrypt(
        &self,
        _: &mut SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, rama_boring::ssl::PrivateKeyMethodError> {
        Err(rama_boring::ssl::PrivateKeyMethodError::FAILURE)
    }
    fn complete(
        &self,
        _: &mut SslRef,
        _: &mut [u8],
    ) -> Result<usize, rama_boring::ssl::PrivateKeyMethodError> {
        Err(rama_boring::ssl::PrivateKeyMethodError::FAILURE)
    }
}

#[tokio::test]
async fn custom_verification_does_not_release_credentials_before_proof_of_possession() {
    for version in VERSIONS {
        let verified = Arc::new(AtomicUsize::new(0));
        let resolved = Arc::new(AtomicUsize::new(0));
        let (verify, resolve) = (verified.clone(), resolved.clone());
        let policy = TlsMitmClientAuthPolicy::new(service_fn(move |_: TlsMitmClientAuthInput| {
            let (verify, resolve) = (verify.clone(), resolve.clone());
            async move {
                Ok::<_, Infallible>(
                    TlsMitmClientAuthPlan::new(service_fn(move |_: TlsMitmClientIdentity| {
                        resolve.fetch_add(1, SeqCst);
                        async { Ok::<_, Infallible>(Some(material().mapped.credential())) }
                    }))
                    .with_ingress(move |ssl| {
                        ssl.set_async_custom_verify_callback(required(), move |_| {
                            let verify = verify.clone();
                            Ok(Box::pin(async move {
                                tokio::task::yield_now().await;
                                Ok(Box::new(move |_: &mut SslRef| {
                                    verify.fetch_add(1, SeqCst);
                                    Ok(())
                                })
                                    as rama_boring::ssl::BoxCustomVerifyFinish)
                            }))
                        });
                        Ok(())
                    }),
                )
            }
        }));
        let mut forged = SslCredential::builder().unwrap();
        forged
            .set_certificate_chain([&material().guest.cert])
            .unwrap();
        forged.set_private_key_method(WrongSigner).unwrap();
        let result = run(
            &relay().with_client_auth(policy),
            version,
            required(),
            Some(forged.build()),
            None,
            None,
        )
        .await;
        result.client.unwrap_err();
        result.relay.unwrap_err();
        assert_eq!(verified.load(SeqCst), 1);
        assert_eq!(resolved.load(SeqCst), 0);
    }
}

#[tokio::test]
async fn upstream_verification_and_pins_run_before_policy_selection() {
    use crate::client::BoringClientConfigExt as _;
    use rama_tls::client::{TlsServerCertPin, TlsServerCertPins};
    for version in VERSIONS {
        for pin_mismatch in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let policy =
                TlsMitmClientAuthPolicy::new(service_fn(move |_: TlsMitmClientAuthInput| {
                    count.fetch_add(1, SeqCst);
                    async {
                        Ok::<_, Infallible>(TlsMitmClientAuthPlan::fixed(Some(
                            material().mapped.credential(),
                        )))
                    }
                }));
            let mut config = TlsClientConfig::new()
                .with_server_name(Host::from_static("localhost"))
                .with_server_verify(ServerVerifyMode::Auto)
                .with_server_verify_cert_store(Arc::new(store(if pin_mismatch {
                    &material().ca.cert
                } else {
                    &material().other_ca.cert
                })));
            if pin_mismatch {
                config.set_server_cert_pins(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
                    [0; 32],
                )));
            }
            let mut data = TlsConnectorData::try_from(&config).unwrap();
            data.config.set_min_proto_version(Some(version)).unwrap();
            data.config.set_max_proto_version(Some(version)).unwrap();
            let result = run(
                &relay().with_client_auth(policy),
                version,
                required(),
                None,
                None,
                Some(data),
            )
            .await;
            result.client.unwrap_err();
            result.relay.unwrap_err();
            assert_eq!(calls.load(SeqCst), 0);
        }
    }
}

struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.fetch_add(1, SeqCst);
    }
}

#[tokio::test]
async fn deadline_cancels_policy_futures_and_closes_both_transports() {
    for (resolve_stage, external) in [(false, false), (true, false), (false, true), (true, true)] {
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (start, drop) = (started.clone(), dropped.clone());
        let policy = TlsMitmClientAuthPolicy::new(service_fn(move |_: TlsMitmClientAuthInput| {
            let (start, drop) = (start.clone(), drop.clone());
            async move {
                if !resolve_stage {
                    let _probe = DropProbe(drop.clone());
                    start.fetch_add(1, SeqCst);
                    std::future::pending::<()>().await;
                }
                Ok::<_, Infallible>(TlsMitmClientAuthPlan::new(service_fn(
                    move |_: TlsMitmClientIdentity| {
                        let (start, drop) = (start.clone(), drop.clone());
                        async move {
                            let _probe = DropProbe(drop);
                            start.fetch_add(1, SeqCst);
                            std::future::pending::<Result<Option<SslCredential>, Infallible>>()
                                .await
                        }
                    },
                )))
            }
        }));
        let relay = relay().with_client_auth(policy);
        let relay = if external {
            relay.without_handshake_timeout()
        } else {
            relay.with_handshake_timeout(Duration::from_millis(100))
        };
        let result = run_with_options(
            &relay,
            SslVersion::TLS1_3,
            required(),
            None,
            None,
            None,
            RunOptions {
                external_timeout: external.then_some(Duration::from_millis(100)),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(result.relay.unwrap_err(), TlsMitmRelayErrorKind::Timeout);
        result.client.unwrap_err();
        result.upstream.unwrap_err();
        assert_eq!(started.load(SeqCst), 1);
        assert_eq!(dropped.load(SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_overrides_and_cached_acceptors_do_not_cross_authentication_between_connections() {
    let relay = Arc::new(relay().with_client_auth(TlsMitmClientAuthPolicy::fixed(
        material().guest.credential(),
    )));
    let mut jobs = tokio::task::JoinSet::new();
    for id in 0..24 {
        let relay = relay.clone();
        jobs.spawn(async move {
            let override_policy = (id % 2 == 0)
                .then(|| TlsMitmClientAuthPolicy::fixed(material().mapped.credential()));
            let version = VERSIONS[(id / 2) % 2];
            let result = run(&relay, version, required(), None, override_policy, None).await;
            result.client.unwrap();
            let expected = if id % 2 == 0 {
                &material().mapped.cert
            } else {
                &material().guest.cert
            };
            assert_eq!(result.upstream.unwrap(), Some(expected.to_der().unwrap()));
        });
    }
    while let Some(result) = jobs.join_next().await {
        result.unwrap();
    }
    // A different per-flow trust policy must not be remembered by the cached acceptor.
    let calls = Arc::new(AtomicUsize::new(0));
    let result = run(
        &relay,
        SslVersion::TLS1_3,
        required(),
        None,
        Some(mapped_policy(calls.clone(), false)),
        None,
    )
    .await;
    result.client.unwrap_err();
    assert_eq!(calls.load(SeqCst), 0);
    let result = run(&relay, SslVersion::TLS1_3, required(), None, None, None).await;
    result.client.unwrap();
}

#[test]
fn ordinary_client_auth_conversion_rejects_empty_or_mismatched_credentials() {
    let auth = crate::client::ConnectorConfigClientAuth {
        cert_chain: vec![],
        private_key: material().guest.key.clone(),
    };
    assert!(
        SslCredential::try_from(auth).is_err(),
        "invalid certificate/key pair must fail"
    );
    let auth = crate::client::ConnectorConfigClientAuth {
        cert_chain: vec![material().guest.cert.clone()],
        private_key: material().mapped.key.clone(),
    };
    assert!(
        SslCredential::try_from(auth).is_err(),
        "invalid certificate/key pair must fail"
    );
}

#[tokio::test]
async fn optional_ingress_can_mirror_or_fall_back_without_a_certificate() {
    for version in VERSIONS {
        for present in [false, true] {
            let policy =
                TlsMitmClientAuthPolicy::new(service_fn(|_: TlsMitmClientAuthInput| async {
                    Ok::<_, Infallible>(
                        TlsMitmClientAuthPlan::new(service_fn(
                            |identity: TlsMitmClientIdentity| async move {
                                Ok::<_, Infallible>(Some(if identity.leaf().is_some() {
                                    material().guest.credential()
                                } else {
                                    material().mapped.credential()
                                }))
                            },
                        ))
                        .with_ingress_trust(store(&material().ca.cert))
                        .with_ingress(|ssl| {
                            ssl.set_verify(SslVerifyMode::PEER);
                            Ok(())
                        }),
                    )
                }));
            let result = run(
                &relay().with_client_auth(policy),
                version,
                required(),
                present.then(|| material().guest.credential()),
                None,
                None,
            )
            .await;
            result.client.unwrap();
            let expected = if present {
                &material().guest.cert
            } else {
                &material().mapped.cert
            };
            assert_eq!(result.upstream.unwrap(), Some(expected.to_der().unwrap()));
        }
    }
}

#[tokio::test]
async fn stage_one_errors_never_configure_ingress_or_run_the_resolver() {
    for version in VERSIONS {
        let called = Arc::new(AtomicUsize::new(0));
        let count = called.clone();
        let policy =
            TlsMitmClientAuthPolicy::new(service_fn(move |input: TlsMitmClientAuthInput| {
                count.fetch_add(1, SeqCst);
                assert!(input.request.is_some());
                assert_eq!(input.server_name, Some(Host::from_static("localhost")));
                assert_eq!(
                    input.server_certificate.to_der().unwrap(),
                    material().server.cert.to_der().unwrap()
                );
                async { Err::<TlsMitmClientAuthPlan, _>(BoxError::from("no suitable credential")) }
            }));
        let result = run(
            &relay().with_client_auth(policy),
            version,
            required(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(result.relay.unwrap_err(), TlsMitmRelayErrorKind::ClientAuth);
        result.client.unwrap_err();
        result.upstream.unwrap_err();
        assert_eq!(called.load(SeqCst), 1);
    }
}

struct DelayedSigner {
    fail: bool,
    calls: Arc<AtomicUsize>,
}
impl rama_boring::ssl::AsyncPrivateKeyMethod for DelayedSigner {
    fn sign(
        &self,
        _: &mut SslRef,
        input: &[u8],
        algorithm: SslSignatureAlgorithm,
        _: &mut [u8],
    ) -> Result<
        rama_boring::ssl::BoxPrivateKeyMethodFuture,
        rama_boring::ssl::AsyncPrivateKeyMethodError,
    > {
        assert_eq!(algorithm, SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256);
        self.calls.fetch_add(1, SeqCst);
        let input = input.to_vec();
        let fail = self.fail;
        Ok(Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(3)).await;
            if fail {
                return Err(rama_boring::ssl::AsyncPrivateKeyMethodError);
            }
            let mut signer =
                rama_boring::sign::Signer::new(MessageDigest::sha256(), &material().mapped.key)
                    .unwrap();
            signer.update(&input).unwrap();
            let signature = signer.sign_to_vec().unwrap();
            Ok(Box::new(move |_: &mut SslRef, output: &mut [u8]| {
                output[..signature.len()].copy_from_slice(&signature);
                Ok(signature.len())
            })
                as rama_boring::ssl::BoxPrivateKeyMethodFinish)
        }))
    }
    fn decrypt(
        &self,
        _: &mut SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<
        rama_boring::ssl::BoxPrivateKeyMethodFuture,
        rama_boring::ssl::AsyncPrivateKeyMethodError,
    > {
        Err(rama_boring::ssl::AsyncPrivateKeyMethodError)
    }
}

#[tokio::test]
async fn delayed_egress_private_key_operations_complete_or_fail_without_hanging() {
    for version in VERSIONS {
        for fail in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut credential = SslCredential::builder().unwrap();
            credential
                .set_certificate_chain([&material().mapped.cert])
                .unwrap();
            credential
                .set_async_private_key_method(DelayedSigner {
                    fail,
                    calls: calls.clone(),
                })
                .unwrap();
            let result = run(
                &relay().with_client_auth(TlsMitmClientAuthPolicy::fixed(credential.build())),
                version,
                required(),
                None,
                None,
                None,
            )
            .await;
            assert_eq!(result.client.is_ok(), !fail);
            assert_eq!(result.upstream.is_ok(), !fail);
            assert_eq!(calls.load(SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn explicit_egress_sessions_are_rejected_and_ingress_issues_no_auth_session() {
    use crate::client::TlsConnectorContextBuilder;
    use rama_boring::ssl::SslSessionCacheMode;
    for version in VERSIONS {
        let saved = Arc::new(parking_lot::Mutex::new(None));
        let session = saved.clone();
        let config = TlsClientConfig::new().with_server_name(Host::from_static("localhost"));
        let mut builder = TlsConnectorContextBuilder::try_from(&config).unwrap();
        builder.config.set_cert_store(store(&material().ca.cert));
        builder.config.set_min_proto_version(Some(version)).unwrap();
        builder.config.set_max_proto_version(Some(version)).unwrap();
        builder
            .config
            .set_session_cache_mode(SslSessionCacheMode::CLIENT);
        builder.config.set_new_session_callback(move |_, ticket| {
            *session.lock() = Some(ticket);
        });
        let context = builder.build();
        let acceptor = upstream_acceptor(version, SslVerifyMode::NONE);
        let (client, server) = tokio::io::duplex(64);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let mut s = rama_boring_tokio::accept(&acceptor, server).await.unwrap();
                    s.write_all(b"x").await.unwrap();
                },
                async {
                    let mut c = tls_connect(
                        ServiceInput::new(client),
                        Some(context.configure().unwrap()),
                    )
                    .await
                    .unwrap();
                    c.read_exact(&mut [0]).await.unwrap();
                }
            );
        })
        .await
        .unwrap();
        let session = saved
            .lock()
            .take()
            .expect("positive control must issue a session");
        for policy in [
            None,
            Some(TlsMitmClientAuthPolicy::fixed(
                material().mapped.credential(),
            )),
        ] {
            let mut data = context.configure().unwrap();
            // Same client context and server identity as the original session.
            unsafe {
                data.config.set_session(&session).unwrap();
            }
            assert!(data.config.session().is_some());
            let result = run(
                &relay().maybe_with_client_auth(policy),
                version,
                required(),
                None,
                None,
                Some(data),
            )
            .await;
            assert_eq!(result.relay.unwrap_err(), TlsMitmRelayErrorKind::Config);
            result.client.unwrap_err();
            result.upstream.unwrap_err();
        }
        let relay = relay().with_client_auth(TlsMitmClientAuthPolicy::fixed(
            material().mapped.credential(),
        ));
        for _ in 0..2 {
            let result = run_with_options(
                &relay,
                version,
                required(),
                None,
                None,
                None,
                RunOptions {
                    guest_data: Some(context.configure().unwrap()),
                    ..Default::default()
                },
            )
            .await;
            assert!(result.client.is_ok(), "{:?}", result.client);
            assert!(
                saved.lock().is_none(),
                "auth-enabled ingress must not issue resumable sessions"
            );
        }
    }
}

#[tokio::test]
async fn peeked_client_hello_service_preserves_policy_context_and_negotiated_alpn() {
    use crate::{TlsStream, proxy::TlsMitmRelayService};
    use rama_core::io::PrefixedIo;
    use rama_net::tls::ApplicationProtocol;
    use rama_tls::{
        SecureTransport,
        server::{InputWithClientHello, peek_client_hello_from_input},
    };
    for version in VERSIONS {
        let policy =
            TlsMitmClientAuthPolicy::new(service_fn(|input: TlsMitmClientAuthInput| async move {
                assert!(
                    input
                        .extensions
                        .get_ref::<SecureTransport>()
                        .unwrap()
                        .client_hello()
                        .is_some()
                );
                assert!(
                    input
                        .extensions
                        .get_ref::<TlsMitmClientAuthPolicy>()
                        .is_some()
                );
                assert!(input.request.is_some());
                Ok::<_, Infallible>(TlsMitmClientAuthPlan::fixed(Some(
                    material().mapped.credential(),
                )))
            }));
        let (client, ingress) = tokio::io::duplex(64);
        let (egress, upstream) = tokio::io::duplex(64);
        let ingress = ServiceInput::new(ingress);
        ingress.extensions().insert(policy);
        let bridge = async {
            let (input, hello) = peek_client_hello_from_input(
                BridgeIo(ingress, ServiceInput::new(egress)),
                Some(Duration::from_secs(3)),
            )
            .await
            .unwrap();
            let inner = service_fn(
                |BridgeIo(mut ingress, mut egress): BridgeIo<
                    TlsStream<
                        PrefixedIo<
                            rama_core::io::HeapReader,
                            ServiceInput<tokio::io::DuplexStream>,
                        >,
                    >,
                    TlsStream<ServiceInput<tokio::io::DuplexStream>>,
                >| async move {
                    for stream in [ingress.extensions(), egress.extensions()] {
                        assert_eq!(
                            stream
                                .get_ref::<NegotiatedTlsParameters>()
                                .unwrap()
                                .application_layer_protocol,
                            Some(ApplicationProtocol::HTTP_11)
                        );
                    }
                    let mut byte = [0];
                    ingress.read_exact(&mut byte).await?;
                    egress.write_all(&byte).await?;
                    egress.read_exact(&mut byte).await?;
                    ingress.write_all(&byte).await?;
                    Ok::<_, BoxError>(())
                },
            );
            TlsMitmRelayService::new(relay(), inner)
                .serve(InputWithClientHello {
                    input,
                    client_hello: hello.unwrap(),
                })
                .await
                .unwrap();
        };
        let server = async {
            let acceptor = upstream_acceptor(version, required());
            let mut stream = rama_boring_tokio::accept(&acceptor, upstream)
                .await
                .unwrap();
            assert_eq!(
                stream.ssl().peer_certificate().unwrap().to_der().unwrap(),
                material().mapped.cert.to_der().unwrap()
            );
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            stream.write_all(&byte).await.unwrap();
        };
        let guest = async {
            let config = TlsClientConfig::new()
                .with_server_name(Host::from_static("localhost"))
                .with_alpn_http_1();
            let mut data = TlsConnectorData::try_from(&config).unwrap();
            data.config
                .set_verify_cert_store(store(&material().ca.cert))
                .unwrap();
            data.config.set_min_proto_version(Some(version)).unwrap();
            data.config.set_max_proto_version(Some(version)).unwrap();
            let mut stream = tls_connect(ServiceInput::new(client), Some(data))
                .await
                .unwrap();
            stream.write_all(b"x").await.unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            assert_eq!(&byte, b"x");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(Box::pin(bridge), Box::pin(server), Box::pin(guest));
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn upstream_disconnect_during_selection_closes_the_ingress() {
    for version in VERSIONS {
        let disconnect = Arc::new(tokio::sync::Notify::new());
        let notify = disconnect.clone();
        let policy = TlsMitmClientAuthPolicy::new(service_fn(move |_: TlsMitmClientAuthInput| {
            let notify = notify.clone();
            async move {
                notify.notify_one();
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok::<_, Infallible>(TlsMitmClientAuthPlan::fixed(Some(
                    material().mapped.credential(),
                )))
            }
        }));
        let result = run_with_options(
            &relay().with_client_auth(policy),
            version,
            required(),
            None,
            None,
            None,
            RunOptions {
                disconnect_upstream: Some(disconnect),
                ..Default::default()
            },
        )
        .await;
        result.relay.unwrap_err();
        result.client.unwrap_err();
        assert!(
            result
                .upstream
                .unwrap_err()
                .contains("disconnected during selection")
        );
    }
}
