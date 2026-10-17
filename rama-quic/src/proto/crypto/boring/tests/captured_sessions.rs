//! Captured native TLS shape checks, with real ephemeral keys and current policy.

use super::{capture_fixture::*, *};
use crate::tls::profile::boring;
use rama_net::address::Host;
use rama_tls::CipherSuite;
use rama_tls_boring::client::BoringClientConfigExt as _;

#[test]
fn captured_quic_tls_preparation_authenticates_with_fresh_native_sessions() {
    for version in [Version::V1, Version::V2] {
        let (policy, server) = policy();
        let source = reference(&policy, version);
        let prepared = boring::prepare(
            &policy,
            TlsOptions::default(),
            Host::try_from("localhost").unwrap(),
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
    let prepared = boring::prepare(
        &policy,
        TlsOptions::default(),
        Host::try_from("localhost").unwrap(),
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
    let prepared = boring::prepare(
        &policy,
        TlsOptions::default(),
        Host::try_from("localhost").unwrap(),
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
    policy.set_cipher_suites(vec![CipherSuite::TLS13_AES_128_GCM_SHA256]);
    boring::prepare(
        &policy,
        TlsOptions::default(),
        Host::try_from("localhost").unwrap(),
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
    assert!(
        boring::prepare(
            &policy,
            TlsOptions::default(),
            Host::try_from("localhost").unwrap(),
            resumed,
        )
        .unwrap()
        .crypto
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .is_err()
    );
}
