//! Captured native TLS shape checks, with real ephemeral keys and current policy.

use rama_tls::client::ClientHello;
use rama_tls_boring::client::BoringClientConfigExt as _;
use rama_ua::profile::capture::{
    completeness::ProfileCaptureCompleteness,
    tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport},
};

use super::*;

fn reference(policy: &TlsClientConfig, version: Version) -> TlsCapture {
    let client = BoringTlsProvider
        .client_config(policy, TlsOptions::default())
        .unwrap();
    first_capture(client.crypto, version)
}

fn first_capture(client: Arc<dyn crypto::ClientConfig>, version: Version) -> TlsCapture {
    let mut session = client
        .start_session(version, "localhost", &params(Side::Client))
        .unwrap();
    let mut bytes = Vec::new();
    while let Some(event) = session.poll_handshake().unwrap() {
        let HandshakeEvent::Data(_, data) = event else {
            panic!("unexpected first-flight keys");
        };
        bytes.extend_from_slice(&data);
    }
    let ClientHelloHandshakePrefix::Complete(hello) = parse_client_hello_message_prefix(&bytes)
    else {
        panic!("native ClientHello incomplete");
    };
    capture(&hello)
}

fn capture(hello: &ClientHello) -> TlsCapture {
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Quic,
        hello,
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

fn policy() -> (TlsClientConfig, TlsServerConfig) {
    let (mut client, server) = configs();
    // The test controls only optional layout choices; authentication stays real.
    client.set_client_hello_padding(rama_crypto::dep::boring::ssl::Padding::Off);
    client.set_grease(false);
    client.set_permute_extensions(false);
    (client, server)
}

#[test]
fn captured_quic_tls_preparation_authenticates_with_fresh_native_sessions() {
    for version in [Version::V1, Version::V2] {
        let (policy, server) = policy();
        let source = reference(&policy, version);
        let prepared = crate::tls::profile::boring::prepare(
            &policy,
            rama_net::address::Host::try_from("localhost").unwrap(),
            source.clone(),
        )
        .unwrap()
        .crypto;
        let server = BoringTlsProvider
            .server_config(&server, TlsOptions::default())
            .unwrap()
            .crypto
            .into_fixed();
        for _ in 0..2 {
            let mut c = prepared
                .clone()
                .start_session(version, "localhost", &params(Side::Client))
                .unwrap();
            let mut s = server
                .clone()
                .start_session(version, &params(Side::Server))
                .unwrap();
            check_session(&mut *c, &mut *s, false);
        }
    }
}

#[test]
fn captured_tls_shape_is_checked_against_actual_native_output() {
    let (policy, _) = policy();
    let source = reference(&policy, Version::V1);
    policy
        .as_extensions()
        .insert(HandshakeInitializer(Arc::new(|ssl| {
            ssl.set_alpn_protos(b"\x05other")?;
            Ok(())
        })));
    let prepared = crate::tls::profile::boring::prepare(
        &policy,
        rama_net::address::Host::try_from("localhost").unwrap(),
        source,
    )
    .unwrap()
    .crypto;
    assert!(
        prepared
            .start_session(Version::V1, "localhost", &params(Side::Client))
            .is_err()
    );
}

#[test]
fn captured_parameter_length_cannot_replace_current_connection_parameters() {
    let (policy, _) = policy();
    let source = reference(&policy, Version::V1);
    let prepared = crate::tls::profile::boring::prepare(
        &policy,
        rama_net::address::Host::try_from("localhost").unwrap(),
        source,
    )
    .unwrap()
    .crypto;
    let mut actual = params(Side::Client);
    actual.initial_src_cid = Some(ConnectionId::new(&[1, 2]));
    assert!(
        prepared
            .start_session(Version::V1, "localhost", &actual)
            .is_err()
    );
}

#[test]
fn captured_wire_choices_cannot_override_explicit_cipher_policy() {
    let (mut policy, _) = policy();
    let source = reference(&policy, Version::V1);
    policy.set_cipher_suites(vec![rama_tls::CipherSuite::TLS13_AES_128_GCM_SHA256]);
    crate::tls::profile::boring::prepare(
        &policy,
        rama_net::address::Host::try_from("localhost").unwrap(),
        source,
    )
    .unwrap_err();
}

#[test]
fn a_real_resumed_capture_requires_current_ticket_support() {
    let (policy, server) = policy();
    let client = BoringTlsProvider
        .client_config(&policy, TlsOptions::default())
        .unwrap()
        .crypto;
    let server = BoringTlsProvider
        .server_config(&server, TlsOptions::default())
        .unwrap()
        .crypto
        .into_fixed();
    let mut c = client
        .clone()
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();
    let mut s = server
        .start_session(Version::V1, &params(Side::Server))
        .unwrap();
    check_session(&mut *c, &mut *s, false);
    let resumed = first_capture(client, Version::V1);
    assert!(
        resumed
            .extensions
            .iter()
            .any(|extension| extension.id == u16::from(ExtensionId::PRE_SHARED_KEY))
    );
    crate::tls::profile::boring::prepare(
        &policy,
        rama_net::address::Host::try_from("localhost").unwrap(),
        resumed,
    )
    .unwrap_err();
}
