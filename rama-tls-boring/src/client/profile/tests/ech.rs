//! Chrome 157.0.8103.78 on macOS, captured 2026-11-15 with
//! `rama-fp/browser_automation/ech_reference.py`: fresh profiles, loopback DoH,
//! scoped SPKI trust and direct HTTP/1.1 TLS. Inner and outer are a matched
//! accepted-ECH pair; baseline is a separate connection without advertised ECH.
//! Fixtures retain canonical capture-safe shapes, not cryptographic secrets.

use rama_core::{Layer as _, Service, ServiceInput, service::service_fn};
#[cfg(feature = "http")]
use rama_net::{
    address::Domain,
    client::{ConnectionError, EstablishedClientConnection},
    tls::ServerName,
};
use rama_net::{client::ConnectorTarget, tls::TargetEchConfig};
#[cfg(feature = "http")]
use rama_tls::{
    ExtensionId,
    client::{EchRequirement, NegotiatedTlsParameters},
    server::{
        GeneratedServerAuthConfig, ServerAuthData, StoreOuterClientHelloLayer,
        TlsClientHelloPrefixedIo,
    },
};
use rama_tls::{
    client::TlsEchAccepted,
    server::{ServerClientHellos, TlsServerConfig},
};
use rama_ua::profile::format::canonical::{CanonicalValue, ValueId};
#[cfg(feature = "http")]
use rama_ua::profile::{
    capture::joint::CapturedSlot,
    model::identity::ConnectionContext,
    model::identity::FlowKey,
    selection::{
        DrawKey, ProfileSeed,
        capabilities::CapabilitySet,
        database::UserAgentDatabase,
        variants::{EmulationContext, ProfileSelector, SelectionRequest, VariantPins},
    },
};
use rama_utils::octets::kib;
#[cfg(feature = "http")]
use tokio::io::{DuplexStream, duplex};

use super::*;
#[cfg(feature = "http")]
use super::{
    connection::established_in,
    fixture::{connection_database, selected_connections},
};
use crate::server::{
    BoringServerConfigExt as _, EchServerKey, EchServerKeys, TlsAcceptorService,
    ech::tests::{SERVER_ECH_CONFIG, SERVER_ECH_KEY},
};
#[cfg(feature = "http")]
use crate::{TlsStream, client::TlsConnectorLayer};

/// HPKE AEAD identifier of ChaCha20-Poly1305.
const CHACHA20_POLY1305: u16 = 3;

fn reference(bytes: &'static [u8]) -> TlsCapture {
    TlsCapture::from_canonical(
        &CanonicalValue {
            id: ValueId(rama_boring::sha::sha256(bytes)),
            bytes: bytes.into(),
        },
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn direct_chrome_outer_reproduces_inner_through_real_ech() {
    let captured = reference(include_bytes!("fixtures/chrome-157-ech-inner.bin"));
    let outer = reference(include_bytes!("fixtures/chrome-157-ech-outer.bin"));
    assert_eq!(
        captured.clone().with_grease_placeholders().unwrap(),
        outer
            .ech_inner_from_outer()
            .unwrap()
            .with_grease_placeholders()
            .unwrap()
    );
    replay_pair(captured, outer).await;
}

#[tokio::test]
async fn correlated_ech_orders_follow_native_construction_across_permutations() {
    let mut outer = reference(include_bytes!("fixtures/chrome-157-ech-outer.bin"));
    let end = outer.extensions.len() - 1;
    for offset in [1, 3, 7] {
        // Keep the observed GREASE ends and vary the ordinary extension order.
        outer.extensions[1..end].rotate_left(offset);
        replay_pair(outer.ech_inner_from_outer().unwrap(), outer.clone()).await;
    }
}

/// A profile whose `token_present` context holds only a matched pair, its outer shown by
/// ordinary GREASE offers in another context, and the selection drawn there without ECH.
#[cfg(feature = "http")]
fn grease_fallback_profile() -> (EmulationContext, ConnectionSelection, ConnectionContext) {
    let baseline = reference(include_bytes!("fixtures/chrome-157-ech-baseline.bin"));
    let inner = reference(include_bytes!("fixtures/chrome-157-ech-inner.bin"));
    let outer = reference(include_bytes!("fixtures/chrome-157-ech-outer.bin"));
    // This browser draws its GREASE ECH payload from the lengths real ECH uses; a
    // second GREASE observation shows the length of the captured outer.
    let ech = |capture: &TlsCapture| {
        capture
            .extensions
            .iter()
            .find(|extension| matches!(extension.value, TlsCapturedExtensionValue::EchOuter { .. }))
            .unwrap()
            .value
            .clone()
    };
    let mut other_grease = baseline.clone();
    for extension in &mut other_grease.extensions {
        if matches!(extension.value, TlsCapturedExtensionValue::EchOuter { .. }) {
            extension.value = ech(&outer);
        }
    }
    assert_ne!(ech(&baseline), ech(&outer));
    let slot = |kind, capture: &TlsCapture| CapturedSlot {
        kind,
        value: capture.canonical(TlsCaptureLimits::default()).unwrap(),
    };
    let paired_only = ConnectionContext {
        token_present: Some(true),
        ..ConnectionContext::default()
    };
    let (context, selection) = selected_connections(
        "grease-fallback",
        true,
        vec![
            (
                ConnectionContext::default(),
                vec![slot(CapturedSlotKind::TcpTls, &baseline)],
            ),
            (
                ConnectionContext::default(),
                vec![slot(CapturedSlotKind::TcpTls, &other_grease)],
            ),
            (
                paired_only.clone(),
                vec![
                    slot(CapturedSlotKind::TcpTls, &inner),
                    slot(CapturedSlotKind::TlsOuter, &outer),
                ],
            ),
        ],
        &paired_only,
    );
    (context, selection, paired_only)
}

#[cfg(feature = "http")]
#[tokio::test]
async fn paired_only_context_offers_its_outer_with_grease_ech_to_a_target_without_ech() {
    let (context, selection, paired_only) = grease_fallback_profile();
    assert!(!selection.ech_ready);
    assert!(selection.prepare_components().unwrap().tls_outer.is_some());
    // The server observes the drawn outer, its ECH extension sent as GREASE.
    let extensions = Box::pin(established_in((&context, &selection), paired_only)).await;
    assert_eq!(
        extensions.get_ref::<TlsEchAccepted>(),
        Some(&TlsEchAccepted(false))
    );
}

#[cfg(feature = "http")]
#[tokio::test]
async fn derived_profiles_in_paired_only_and_mixed_databases_connect_without_ech() {
    let outer = capture();
    let mut inner = outer.clone();
    for extension in &mut inner.extensions {
        if matches!(extension.value, TlsCapturedExtensionValue::EchOuter { .. }) {
            extension.value = TlsCapturedExtensionValue::EchInner;
        }
    }
    let slot = |kind, tls: &TlsCapture| CapturedSlot {
        kind,
        value: tls.canonical(TlsCaptureLimits::default()).unwrap(),
    };
    let pair_database = connection_database(
        "paired",
        vec![(
            ConnectionContext::default(),
            vec![
                slot(CapturedSlotKind::TcpTls, &inner),
                slot(CapturedSlotKind::TlsOuter, &outer),
            ],
        )],
    );
    let ordinary_database = connection_database(
        "ordinary",
        vec![(
            ConnectionContext::default(),
            vec![slot(CapturedSlotKind::TcpTls, &outer)],
        )],
    );
    let mixed: UserAgentDatabase = pair_database
        .iter()
        .chain(ordinary_database.iter())
        .cloned()
        .collect();
    for database in [&pair_database, &mixed] {
        for profile in database.iter() {
            let seed = ProfileSeed([4; 32]);
            let key = DrawKey([6; 32]);
            let selected = Arc::new(
                database
                    .select(
                        &SelectionRequest {
                            client: ProfileSelector {
                                client: Some(profile.key.client.clone()),
                                ..ProfileSelector::default()
                            },
                            required: CapabilitySet {
                                h2: true,
                                tls_tcp: true,
                                ..CapabilitySet::default()
                            },
                            flow: FlowKey::Http {
                                version: Version::HTTP_2,
                                method: "GET".parse().unwrap(),
                                initiator: None,
                                fetch: None,
                                connection: ConnectionContext::default(),
                            },
                            pins: VariantPins::default(),
                        },
                        seed,
                        key,
                    )
                    .unwrap(),
            );
            let selection = selected
                .connection(&ConnectionContext::default(), seed, key)
                .unwrap();
            assert!(!selection.ech_ready);
            let context = selected.emulation_context(seed, key, DrawKey([7; 32]));
            let extensions = Box::pin(established_in(
                (&context, &selection),
                ConnectionContext::default(),
            ))
            .await;
            assert_eq!(
                extensions.get_ref::<TlsEchAccepted>(),
                Some(&TlsEchAccepted(false))
            );
        }
    }
}

#[cfg(feature = "http")]
#[derive(Debug, Clone, Copy)]
enum Placement {
    Tls,
    TransportUnderTls,
}

#[cfg(feature = "http")]
type TestTlsStream = TlsStream<TlsClientHelloPrefixedIo<ServiceInput<DuplexStream>>>;

#[cfg(feature = "http")]
async fn observe_handshake(
    stream: TestTlsStream,
) -> Result<(Option<bool>, bool, Option<ServerName>, bool), BoxError> {
    let hellos = ServerClientHellos::from_extensions(stream.extensions());
    let outer_ech = hellos.wire().is_some_and(|hello| {
        hello
            .extensions()
            .iter()
            .any(|extension| extension.id() == ExtensionId::ENCRYPTED_CLIENT_HELLO)
    });
    Ok((
        hellos.ech_accepted(),
        hellos.ech_inner().is_some(),
        stream
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .unwrap()
            .server_name
            .clone(),
        outer_ech,
    ))
}

#[cfg(feature = "http")]
async fn ech_changed_by_transport(ready: bool, placement: Placement, required: bool) {
    let (context, _, paired_only) = grease_fallback_profile();
    let keys =
        EchServerKeys::new([EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, true)]).unwrap();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::generated_ca_for(
        Domain::from_static("prepared.test"),
    ))
    .unwrap();
    let policy = TlsClientConfig::new()
        .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
        .unwrap();
    let server = Arc::new(
        StoreOuterClientHelloLayer::new().into_layer(TlsAcceptorService::new(
            TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn_http_auto()
                .with_ech_keys(keys.clone()),
            service_fn(observe_handshake),
            true,
        )),
    );
    let peer = Arc::new(Mutex::new(None));
    let transport = service_fn({
        let peer = peer.clone();
        move |input: ConnectRequest| {
            let peer = peer.clone();
            let server = server.clone();
            let configs = keys.retry_configs().to_vec();
            async move {
                if ready {
                    input.extensions().insert(TargetEchConfig::new(
                        "other.example:443".parse().unwrap(),
                        configs,
                    ));
                } else {
                    input
                        .extensions()
                        .insert(TargetEchConfig::new(input.authority.clone(), configs));
                }
                let (client, remote) = duplex(kib(64));
                *peer.lock() = Some(tokio::spawn(async move {
                    server.serve(ServiceInput::new(remote)).await
                }));
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(client),
                })
            }
        }
    });
    let compiler = ConnectionProfileCompiler::new(policy.clone());
    let request = input();
    request.extensions().insert(paired_only);
    if required {
        request.extensions().insert(EchRequirement::Required);
    }
    if ready {
        let keys = EchServerKeys::new([EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, true)])
            .unwrap();
        request.extensions().insert(TargetEchConfig::new(
            request.authority.clone(),
            keys.retry_configs().to_vec(),
        ));
    }
    context.publish(request.extensions());
    let accepted = match placement {
        Placement::Tls => {
            let connected = ProfileEmulateHttpConnectModifier::new(
                TlsConnectorLayer::secure()
                    .with_base_config(policy)
                    .into_layer(transport),
            )
            .with_connection_compiler(compiler)
            .serve(request)
            .await
            .unwrap();
            assert_eq!(
                connected
                    .conn
                    .extensions()
                    .get_ref::<ConnectionSelection>()
                    .unwrap()
                    .ech_ready,
                !ready
            );
            connected
                .conn
                .extensions()
                .get_ref::<TlsEchAccepted>()
                .copied()
        }
        Placement::TransportUnderTls => {
            let connected = TlsConnectorLayer::secure()
                .with_base_config(policy)
                .into_layer(
                    ProfileEmulateHttpConnectModifier::new(transport)
                        .with_connection_compiler(compiler),
                )
                .serve(request)
                .await
                .unwrap();
            assert_eq!(
                connected
                    .conn
                    .extensions()
                    .get_ref::<ConnectionSelection>()
                    .unwrap()
                    .ech_ready,
                !ready
            );
            connected
                .conn
                .extensions()
                .get_ref::<TlsEchAccepted>()
                .copied()
        }
    };
    assert_eq!(accepted, Some(TlsEchAccepted(!ready)));
    let task = peer.lock().take().unwrap();
    let (accepted, inner, name, outer_ech) = task.await.unwrap().unwrap();
    assert_eq!(accepted, Some(!ready));
    assert_eq!(inner, !ready);
    assert!(outer_ech);
    assert_eq!(
        name.unwrap().as_domain(),
        Some(&Domain::from_static("prepared.test"))
    );
}

#[cfg(feature = "http")]
#[tokio::test]
async fn late_ech_discovery_reprepares_the_drawn_tcp_offer_in_both_directions() {
    for placement in [Placement::Tls, Placement::TransportUnderTls] {
        for ready in [false, true] {
            ech_changed_by_transport(ready, placement, false).await;
        }
    }
}

#[cfg(feature = "http")]
#[tokio::test]
async fn required_ech_discovered_by_transport_reprepares_the_drawn_tcp_offer() {
    for placement in [Placement::Tls, Placement::TransportUnderTls] {
        ech_changed_by_transport(false, placement, true).await;
    }
}

async fn replay_pair(captured: TlsCapture, outer: TlsCapture) {
    let (config, report) = compile_tcp(&outer, None).unwrap();
    assert!(report.is_exact(), "{report:?}");
    let keys =
        EchServerKeys::new([EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, true)]).unwrap();
    let auth = rama_tls::server::ServerAuthData::new_generated(
        rama_tls::server::GeneratedServerAuthConfig::default(),
    )
    .unwrap();
    let config = config
        .with_server_name(Domain::from_static("localhost"))
        .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
        .unwrap();
    config
        .as_extensions()
        .insert(ConnectorTarget("localhost:443".parse().unwrap()));
    config.as_extensions().insert(TargetEchConfig::new(
        "localhost:443".parse().unwrap(),
        keys.retry_configs().to_vec(),
    ));
    let service = TlsAcceptorService::new(
        TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn_http_auto()
            .with_ech_keys(keys),
        service_fn(
            |stream: crate::TlsStream<
                rama_tls::server::TlsClientHelloPrefixedIo<ServiceInput<tokio::io::DuplexStream>>,
            >| async move {
                let hellos = ServerClientHellos::from_extensions(stream.extensions());
                assert_eq!(hellos.ech_accepted(), Some(true));
                let hello = hellos.effective().unwrap();
                let outer = hellos.wire().unwrap();
                Ok::<_, BoxError>((
                    TlsCapture::capture(
                        ProfileCaptureCompleteness::Complete,
                        TlsCaptureTransport::Tcp,
                        hello,
                        TlsCaptureLimits::default(),
                    )?,
                    TlsCapture::capture(
                        ProfileCaptureCompleteness::Complete,
                        TlsCaptureTransport::Tcp,
                        outer,
                        TlsCaptureLimits::default(),
                    )?,
                ))
            },
        ),
        true,
    );
    let service = rama_tls::server::StoreOuterClientHelloLayer::new().into_layer(service);
    let mut data = TlsConnectorData::try_from(&config).unwrap();
    data.configure_target_ech(config.as_extensions(), &"localhost:443".parse().unwrap())
        .unwrap();
    let (client, server) = tokio::io::duplex(kib(64));
    let (client, server) = tokio::join!(
        crate::client::tls_connect(ServiceInput::new(client), Some(data)),
        service.serve(ServiceInput::new(server)),
    );
    assert_eq!(
        client.unwrap().extensions().get_ref::<TlsEchAccepted>(),
        Some(&TlsEchAccepted(true))
    );
    let (observed, observed_outer) = server.unwrap();
    assert_eq!(
        observed.clone().with_grease_placeholders().unwrap(),
        observed_outer
            .ech_inner_from_outer()
            .unwrap()
            .with_grease_placeholders()
            .unwrap()
    );
    assert_eq!(
        captured.with_grease_placeholders().unwrap(),
        observed.with_grease_placeholders().unwrap()
    );
    assert_eq!(
        outer_structure(native_outer(outer)),
        outer_structure(observed_outer)
    );
}

/// The outer the native stack sends for `capture` on this machine.
fn native_outer(mut capture: TlsCapture) -> TlsCapture {
    // SAFETY: `EVP_has_aes_hardware` takes no arguments and only reads the CPU
    // capabilities the library detected.
    let has_aes_hardware = unsafe { rama_boring_sys::EVP_has_aes_hardware() } != 0;
    if !has_aes_hardware {
        // Real ECH then seals with ChaCha20-Poly1305 whenever the config offers it,
        // whichever AEAD the capture carries.
        for extension in &mut capture.extensions {
            if let TlsCapturedExtensionValue::EchOuter { aead, .. } = &mut extension.value {
                *aead = CHACHA20_POLY1305;
            }
        }
    }
    capture
}

fn outer_structure(mut capture: TlsCapture) -> TlsCapture {
    // ECH ciphertext sizes depend on the destination and fresh key material.
    // As with the profile structure key, compare their presence, not their size.
    for extension in &mut capture.extensions {
        if let TlsCapturedExtensionValue::EchOuter { enc, payload, .. } = &mut extension.value {
            *enc = 0;
            *payload = 0;
        }
    }
    capture.with_grease_placeholders().unwrap()
}
