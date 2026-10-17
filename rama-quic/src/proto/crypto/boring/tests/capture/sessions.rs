//! Captured native TLS shape checks, with real ephemeral keys and current policy.

use super::{fixture::*, *};
use crate::profile::replay::parameters::ParameterExpectation;

use rama_net::address::Host;
use rama_quic_proto::{
    capture::{CaptureLimits, transport_parameters_from_hello},
    profile::ParameterId,
};
use rama_tls::CipherSuite;
use rama_tls_boring::client::BoringClientConfigExt as _;
use rama_ua::profile::capture::{
    completeness::ProfileCaptureCompleteness,
    order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
};

#[test]
fn captured_quic_tls_preparation_authenticates_with_fresh_native_sessions() {
    for version in [Version::V1, Version::V2] {
        let (policy, server) = policy();
        let source = reference(&policy, version);
        let prepared = prepare_tls(
            &policy,
            TlsOptions::default(),
            Host::try_from("localhost").unwrap(),
            source.clone(),
            None,
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
    let prepared = prepare_tls(
        &policy,
        TlsOptions::default(),
        Host::try_from("localhost").unwrap(),
        source,
        None,
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
    let prepared = prepare_tls(
        &policy,
        TlsOptions::default(),
        Host::try_from("localhost").unwrap(),
        source,
        None,
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
    prepare_tls(
        &policy,
        TlsOptions::default(),
        Host::try_from("localhost").unwrap(),
        source,
        None,
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
        prepare_tls(
            &policy,
            TlsOptions::default(),
            Host::try_from("localhost").unwrap(),
            resumed,
            None
        )
        .unwrap()
        .crypto
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .is_err()
    );
}

fn checked_parameters(
    parameters: &TransportParameters,
    version: Version,
) -> Arc<dyn crypto::ClientConfig> {
    let (policy, _) = policy();
    let client = BoringTlsProvider
        .client_config(&policy, TlsOptions::default())
        .unwrap();
    let hello = first_hello(client.crypto, version, parameters);
    let raw = transport_parameters_from_hello(&hello, &CaptureLimits::default()).unwrap();
    let expected = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicParameter,
        raw.iter().map(|field| (field.id.0, field.value.as_slice())),
        OrderCaptureLimits::default(),
    )
    .unwrap();
    prepare_tls(
        &policy,
        TlsOptions::default(),
        Host::try_from("localhost").unwrap(),
        capture(&hello),
        Some(ParameterExpectation::try_from(expected).unwrap()),
    )
    .unwrap()
    .crypto
}

#[test]
fn captured_parameter_literals_are_checked_even_when_the_body_length_matches() {
    for version in [Version::V1, Version::V2] {
        let mut current = params(Side::Client);
        current
            .extra
            .push((ParameterId::GOOGLE_CONNECTION_OPTIONS.0, vec![1, 2, 3, 4]));
        let prepared = checked_parameters(&current, version);
        prepared
            .clone()
            .start_session(version, "localhost", &current)
            .unwrap();
        current.extra[0].1[0] = 5;
        let Err(error) = prepared.start_session(version, "localhost", &current) else {
            panic!("same-sized parameter substitution must fail before output");
        };
        assert!(
            format!("{error:?}").contains("native QUIC parameters differ"),
            "{error:?}"
        );
    }
}

#[test]
fn captured_parameter_binding_lengths_are_checked_independently_of_the_body_length() {
    for version in [Version::V1, Version::V2] {
        let mut current = params(Side::Client);
        current
            .extra
            .push((ParameterId::DEBUGGING_SNI.0, vec![1, 2]));
        let prepared = checked_parameters(&current, version);
        prepared
            .clone()
            .start_session(version, "localhost", &current)
            .unwrap();
        current.initial_src_cid = Some(ConnectionId::new(&[7, 8]));
        current.extra[0].1.truncate(1);
        let Err(error) = prepared.start_session(version, "localhost", &current) else {
            panic!("binding lengths cannot trade bytes while preserving the aggregate length");
        };
        assert!(
            format!("{error:?}").contains("native QUIC parameters differ"),
            "{error:?}"
        );
    }
}
