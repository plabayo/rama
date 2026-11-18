//! Chrome 157.0.8103.78 on macOS, captured 2026-11-15 with
//! `rama-fp/browser_automation/ech_reference.py`: fresh profiles, loopback DoH,
//! scoped SPKI trust and direct HTTP/1.1 TLS. Inner and outer are a matched
//! accepted-ECH pair; baseline is a separate connection without advertised ECH.
//! Fixtures retain canonical capture-safe shapes, not cryptographic secrets.

use super::*;
use crate::server::ech::tests::{SERVER_ECH_CONFIG, SERVER_ECH_KEY};
use crate::server::{BoringServerConfigExt as _, EchServerKey, EchServerKeys, TlsAcceptorService};
use rama_core::{Layer as _, Service, ServiceInput, service::service_fn};
use rama_net::{client::ConnectorTarget, tls::TargetEchConfig};
use rama_tls::{SecureTransport, client::TlsEchAccepted, server::TlsServerConfig};
use rama_ua::profile::format::canonical::{CanonicalValue, ValueId};
use rama_utils::octets::kib;

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
        .with_server_name(Host::from_static("localhost"))
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
                assert!(
                    stream
                        .extensions()
                        .get_ref::<rama_tls::server::ServerEchAccepted>()
                        .unwrap()
                        .0
                );
                let hello = stream
                    .extensions()
                    .get_ref::<SecureTransport>()
                    .unwrap()
                    .client_hello()
                    .unwrap();
                let outer = &stream
                    .extensions()
                    .get_ref::<rama_tls::server::EchServerObservation>()
                    .unwrap()
                    .outer;
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
