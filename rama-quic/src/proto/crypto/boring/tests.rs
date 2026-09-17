use super::*;
use crate::proto::crypto::{
    self, ClientConfig as _, HandshakeEvent, ServerConfig as _, Session, config::TlsOptions,
};
use rama_core::bytes::BytesMut;
use rama_quic_proto::{ConnectionId, Side, Version, transport_parameters::TransportParameters};
use rama_tls::{
    client::{TlsClientConfig, TlsServerCertPins},
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertConfig, LeafCertRequest,
        SelfSignedCaConfig, ServerAuthData, TlsServerConfig,
    },
};
use std::sync::Arc;

fn configs() -> (TlsClientConfig, TlsServerConfig) {
    configs_for([rama_net::address::Domain::from_static("localhost")])
}

/// The same pair, with a leaf certificate naming every host the test connects to. Server
/// identity is verified as usual, so a test that needs several names has to ask for them.
fn configs_for(
    hosts: impl IntoIterator<Item = rama_net::address::Domain>,
) -> (TlsClientConfig, TlsServerConfig) {
    configs_from(generated_auth(hosts))
}

/// A CA and a leaf signed by it, naming `hosts`. Kept separate so a test can hold on to the
/// chain it expects the peer to report.
fn generated_auth(hosts: impl IntoIterator<Item = rama_net::address::Domain>) -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::GeneratedCa {
        ca: SelfSignedCaConfig::default(),
        leaf: LeafCertRequest {
            config: LeafCertConfig::default(),
            identities: hosts.into_iter().map(CertificateIdentity::Dns).collect(),
        },
    })
    .unwrap()
}

fn configs_from(auth: ServerAuthData) -> (TlsClientConfig, TlsServerConfig) {
    let alpn = || {
        [rama_net::tls::ApplicationProtocol::from(
            b"rama-boring-test".as_slice(),
        )]
        .into_iter()
        .collect()
    };
    let client = TlsClientConfig::new()
        .with_alpn(alpn())
        .with_server_cert_pins(TlsServerCertPins::new(auth.cert_chain[0].clone()))
        .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
        .unwrap();
    (
        client,
        TlsServerConfig::new()
            .with_alpn(alpn())
            .with_server_auth(auth),
    )
}

fn params(side: Side) -> TransportParameters {
    TransportParameters {
        initial_src_cid: Some(ConnectionId::new(&[if side.is_client() { 1 } else { 2 }])),
        ..TransportParameters::default()
    }
}

fn transfer(
    from: &mut dyn Session,
    to: &mut dyn Session,
) -> Result<bool, rama_quic_proto::TransportError> {
    let mut progress = false;
    while let Some(event) = from.poll_handshake()? {
        progress = true;
        if let HandshakeEvent::Data(level, bytes) = event {
            for fragment in bytes.chunks(17) {
                to.read_handshake(level, fragment)?;
            }
        }
    }
    Ok(progress)
}

fn handshake(
    client: &mut dyn Session,
    server: &mut dyn Session,
) -> Result<(), rama_quic_proto::TransportError> {
    for _ in 0..32 {
        let progress = transfer(client, server)? | transfer(server, client)?;
        if !progress {
            assert!(!client.is_handshaking());
            assert!(!server.is_handshaking());
            return Ok(());
        }
    }
    panic!("TLS handshake did not settle");
}

fn check_session(client: &mut dyn Session, server: &mut dyn Session, resumed: bool) {
    handshake(client, server).unwrap();
    for session in [&*client, &*server] {
        assert_eq!(
            session.negotiated_alpn(),
            Some(b"rama-boring-test".as_slice())
        );
        assert_eq!(session.handshake_summary().unwrap().resumed, Some(resumed));
    }
    assert!(client.peer_certificates().is_some());
    let mut a = [0; 32];
    let mut b = [0; 32];
    client
        .export_keying_material(&mut a, b"rama\0\xff", b"context")
        .unwrap();
    server
        .export_keying_material(&mut b, b"rama\0\xff", b"context")
        .unwrap();
    assert_eq!(a, b);
    // Both sides agreeing proves nothing on its own: an exporter that wrote nothing would
    // leave both buffers untouched and agree just as well.
    assert_ne!(
        a, [0; 32],
        "the exporter must write the material it derives"
    );
    let mut other = [0; 32];
    client
        .export_keying_material(&mut other, b"rama\0\xff", b"other context")
        .unwrap();
    assert_ne!(
        a, other,
        "a different context must derive different material"
    );
    for number in 1..=3 {
        let client_keys = client.next_1rtt_keys().unwrap().unwrap();
        let server_keys = server.next_1rtt_keys().unwrap().unwrap();
        let mut packet = b"headbody".to_vec();
        packet.resize(24, 0);
        client_keys.local.encrypt(number, &mut packet, 4).unwrap();
        let mut payload = BytesMut::from(&packet[4..]);
        server_keys
            .remote
            .decrypt(number, &packet[..4], &mut payload)
            .unwrap();
        assert_eq!(&payload[..], b"body");
        packet[4..8].copy_from_slice(b"body");
        server_keys.local.encrypt(number, &mut packet, 4).unwrap();
        let mut payload = BytesMut::from(&packet[4..]);
        client_keys
            .remote
            .decrypt(number, &packet[..4], &mut payload)
            .unwrap();
        assert_eq!(&payload[..], b"body");
    }
}

#[test]
fn full_resumed_and_early_handshakes() {
    let (client, server) = configs();
    let options = TlsOptions::default().with_early_data(true);
    let client: Arc<dyn crypto::ClientConfig> =
        Arc::new(QuicClientConfig::from_rama(&client, options).unwrap());
    let server: Arc<dyn crypto::ServerConfig> =
        Arc::new(QuicServerConfig::from_rama(&server, options).unwrap());
    for resumed in [false, true] {
        let mut c = client
            .clone()
            .start_session(Version::V1, "localhost", &params(Side::Client))
            .unwrap();
        let mut s = server
            .clone()
            .start_session(Version::V1, &params(Side::Server))
            .unwrap();
        assert_eq!(c.early_crypto().is_some(), resumed);
        check_session(&mut *c, &mut *s, resumed);
        assert_eq!(c.early_data_accepted(), Some(resumed));
    }
}

#[test]
fn changed_transport_settings_reject_early_data_without_losing_resumption() {
    let (client, server) = configs();
    let options = TlsOptions::default().with_early_data(true);
    let client = Arc::new(QuicClientConfig::from_rama(&client, options).unwrap());
    let server = Arc::new(QuicServerConfig::from_rama(&server, options).unwrap());
    let mut server_params = params(Side::Server);
    server_params.initial_max_data = rama_quic_proto::VarInt::from_u32(1024);
    for resumed in [false, true] {
        if resumed {
            server_params.initial_max_data = rama_quic_proto::VarInt::from_u32(512);
        }
        let mut c = client
            .clone()
            .start_session(Version::V1, "localhost", &params(Side::Client))
            .unwrap();
        let mut s = server
            .clone()
            .start_session(Version::V1, &server_params)
            .unwrap();
        assert_eq!(c.early_crypto().is_some(), resumed);
        if resumed {
            assert_eq!(
                c.transport_parameters().unwrap().unwrap().initial_max_data,
                rama_quic_proto::VarInt::from_u32(1024)
            );
        }
        check_session(&mut *c, &mut *s, resumed);
        assert_eq!(c.early_data_accepted(), Some(false));
        assert_eq!(
            c.transport_parameters().unwrap().unwrap().initial_max_data,
            server_params.initial_max_data
        );
    }
}

#[test]
fn ticket_cache_belongs_to_the_client_configuration() {
    let (client_tls, server_tls) = configs();
    let options = TlsOptions::default().with_early_data(true);
    let client = Arc::new(QuicClientConfig::from_rama(&client_tls, options).unwrap());
    let server = Arc::new(QuicServerConfig::from_rama(&server_tls, options).unwrap());
    let mut c = client
        .clone()
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();
    let mut s = server
        .clone()
        .start_session(Version::V1, &params(Side::Server))
        .unwrap();
    check_session(&mut *c, &mut *s, false);
    let other = Arc::new(QuicClientConfig::from_rama(&client_tls, options).unwrap());
    let mut c = other
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();
    let mut s = server
        .start_session(Version::V1, &params(Side::Server))
        .unwrap();
    assert!(c.early_crypto().is_none());
    check_session(&mut *c, &mut *s, false);
    let c = client
        .start_session(Version::V1, "another.example", &params(Side::Client))
        .unwrap();
    assert!(c.early_crypto().is_none());
    assert!(c.transport_parameters().unwrap().is_none());
}

/// RFC 9369 §5: a ticket resumes only a connection in the version that issued it. The client
/// cache files tickets by version; when a ticket is forced onto another version anyway, the
/// server's per-version context refuses to resume with it.
#[test]
fn a_ticket_from_another_version_does_not_resume() {
    let (client_tls, server_tls) = configs();
    let options = TlsOptions::default().with_early_data(true);
    let client = Arc::new(QuicClientConfig::from_rama(&client_tls, options).unwrap());
    let server = Arc::new(QuicServerConfig::from_rama(&server_tls, options).unwrap());

    let mut c = client
        .clone()
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();
    let mut s = server
        .clone()
        .start_session(Version::V1, &params(Side::Server))
        .unwrap();
    check_session(&mut *c, &mut *s, false);

    // The v1 ticket is not offered to a v2 connection.
    let c = client
        .clone()
        .start_session(Version::V2, "localhost", &params(Side::Client))
        .unwrap();
    assert!(c.early_crypto().is_none());
    drop(c);

    // Forced onto a v2 connection, the server does not resume with it.
    client.relabel_tickets(Version::V2);
    let mut c = client
        .clone()
        .start_session(Version::V2, "localhost", &params(Side::Client))
        .unwrap();
    assert!(
        c.early_crypto().is_some(),
        "the relabelled ticket is offered"
    );
    let mut s = server
        .clone()
        .start_session(Version::V2, &params(Side::Server))
        .unwrap();
    check_session(&mut *c, &mut *s, false);
    assert_eq!(c.early_data_accepted(), Some(false));

    // The v2 connection issued a v2 ticket, which resumes a v2 connection.
    let mut c = client
        .start_session(Version::V2, "localhost", &params(Side::Client))
        .unwrap();
    let mut s = server
        .start_session(Version::V2, &params(Side::Server))
        .unwrap();
    check_session(&mut *c, &mut *s, true);
}

/// BoringSSL hands a client a peer chain that already starts with the leaf, and a server one
/// that does not, so the leaf is added separately and any copy of it in the chain is dropped.
/// The chain reported to the application must therefore be the one the peer actually sent,
/// with no repeated leaf. Only the server's own chain is checked elsewhere, and a server never
/// takes the branch that drops the copy.
#[test]
fn a_peer_chain_is_reported_without_a_repeated_leaf() {
    let auth = generated_auth([rama_net::address::Domain::from_static("localhost")]);
    let expected = auth.cert_chain.clone();
    assert!(
        expected.len() > 1,
        "a single-certificate chain could not show a repeated leaf"
    );
    let (client_tls, server_tls) = configs_from(auth);
    let options = TlsOptions::default();
    let client = Arc::new(QuicClientConfig::from_rama(&client_tls, options).unwrap());
    let server = Arc::new(QuicServerConfig::from_rama(&server_tls, options).unwrap());
    let mut c = client
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();
    let mut s = server
        .start_session(Version::V1, &params(Side::Server))
        .unwrap();
    handshake(&mut *c, &mut *s).unwrap();
    assert_eq!(c.peer_certificates().unwrap(), expected);
}

/// A server learns the name and the application protocol from the ClientHello, and reports
/// them then, so the application can act on them while the handshake is still running. Waiting
/// for the handshake to finish would be too late to be useful.
#[test]
fn a_server_reports_its_handshake_data_before_the_handshake_finishes() {
    let (client_tls, server_tls) = configs();
    let options = TlsOptions::default();
    let client = Arc::new(QuicClientConfig::from_rama(&client_tls, options).unwrap());
    let server = Arc::new(QuicServerConfig::from_rama(&server_tls, options).unwrap());
    let mut c = client
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();
    let mut s = server
        .start_session(Version::V1, &params(Side::Server))
        .unwrap();

    // The client's first flight only, so the handshake cannot have completed.
    let mut reported = false;
    while let Some(event) = c.poll_handshake().unwrap() {
        if let HandshakeEvent::Data(level, bytes) = event {
            reported |= s.read_handshake(level, &bytes).unwrap();
        }
    }
    assert!(
        reported,
        "the ClientHello alone must produce the server's handshake data"
    );
    assert!(
        s.is_handshaking(),
        "the handshake must still be running when that data is reported"
    );
    assert_eq!(s.negotiated_alpn(), Some(b"rama-boring-test".as_slice()));

    // Reported once only; the rest of the handshake adds nothing new to report.
    let mut again = false;
    for _ in 0..32 {
        let progress = transfer(&mut *s, &mut *c).unwrap();
        while let Some(event) = c.poll_handshake().unwrap() {
            if let HandshakeEvent::Data(level, bytes) = event {
                again |= s.read_handshake(level, &bytes).unwrap();
            }
        }
        if !progress && !c.is_handshaking() && !s.is_handshaking() {
            break;
        }
    }
    assert!(!again, "handshake data must be reported exactly once");
}

/// The same contract on a client, which never receives a server name and so rests entirely on
/// the negotiated protocol. It must report once the server has chosen one, while its own
/// handshake is still running.
#[test]
fn a_client_reports_its_handshake_data_before_the_handshake_finishes() {
    let (client_tls, server_tls) = configs();
    let options = TlsOptions::default();
    let client = Arc::new(QuicClientConfig::from_rama(&client_tls, options).unwrap());
    let server = Arc::new(QuicServerConfig::from_rama(&server_tls, options).unwrap());
    let mut c = client
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();
    let mut s = server
        .start_session(Version::V1, &params(Side::Server))
        .unwrap();

    let mut reported_while_handshaking = false;
    let mut reports = 0;
    for _ in 0..32 {
        let mut progress = false;
        while let Some(event) = c.poll_handshake().unwrap() {
            progress = true;
            if let HandshakeEvent::Data(level, bytes) = event {
                for fragment in bytes.chunks(17) {
                    s.read_handshake(level, fragment).unwrap();
                }
            }
        }
        while let Some(event) = s.poll_handshake().unwrap() {
            progress = true;
            if let HandshakeEvent::Data(level, bytes) = event {
                // Fragmented, so the protocol arrives before the handshake can complete.
                for fragment in bytes.chunks(17) {
                    if c.read_handshake(level, fragment).unwrap() {
                        reports += 1;
                        reported_while_handshaking |= c.is_handshaking();
                    }
                }
            }
        }
        if !progress {
            break;
        }
    }
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert_eq!(reports, 1, "handshake data must be reported exactly once");
    assert!(
        reported_while_handshaking,
        "the client must report as soon as the protocol is agreed, not once it has finished"
    );
}

/// QUIC runs on TLS 1.3 only (RFC 9001 §4.2), so a configuration that rules it out is
/// refused on both sides. An empty list leaves the choice to the backend, which this pins to
/// TLS 1.3 itself, and is therefore accepted.
#[test]
fn boring_requires_tls13() {
    use crate::proto::crypto::config::TlsConfigError;
    use rama_tls::{ProtocolVersion, TlsSupportedVersions};

    let (client, server) = configs();
    let options = TlsOptions::default();
    QuicClientConfig::from_rama(&client, options).unwrap();
    QuicServerConfig::from_rama(&server, options).unwrap();

    client.insert(TlsSupportedVersions(vec![ProtocolVersion::TLSv1_2]));
    server.insert(TlsSupportedVersions(vec![ProtocolVersion::TLSv1_2]));
    assert!(matches!(
        QuicClientConfig::from_rama(&client, options),
        Err(TlsConfigError::Tls13Required)
    ));
    assert!(matches!(
        QuicServerConfig::from_rama(&server, options),
        Err(TlsConfigError::Tls13Required)
    ));

    // Naming TLS 1.3, alone or alongside an older version, is what the check looks for.
    for versions in [
        vec![ProtocolVersion::TLSv1_3],
        vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
        vec![],
    ] {
        client.insert(TlsSupportedVersions(versions.clone()));
        server.insert(TlsSupportedVersions(versions));
        QuicClientConfig::from_rama(&client, options).unwrap();
        QuicServerConfig::from_rama(&server, options).unwrap();
    }
}

/// RFC 9001 §5.8: a Retry packet carries an integrity tag over the original destination
/// connection ID and the packet itself. A client that accepted one without checking would let
/// any off-path observer redirect its handshake.
#[test]
fn a_retry_packet_is_accepted_only_with_its_own_integrity_tag() {
    let (client, _) = configs();
    let config = Arc::new(QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap());
    let session = config
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();

    let cid = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let header = b"retry-pseudo-header".as_slice();
    let token = b"opaque-retry-token".as_slice();
    let mut pseudo = header.to_vec();
    pseudo.extend_from_slice(token);
    let mut payload = token.to_vec();
    payload.extend_from_slice(
        &super::packet::retry_tag(&rama_quic_proto::version::V1_WIRE, &cid, &pseudo).unwrap(),
    );
    assert!(session.is_valid_retry(&cid, header, &payload));

    // One flipped bit anywhere in the token or the tag fails authentication.
    for index in 0..payload.len() {
        let mut corrupt = payload.clone();
        corrupt[index] ^= 1;
        assert!(
            !session.is_valid_retry(&cid, header, &corrupt),
            "a Retry corrupted at byte {index} must be refused"
        );
    }
    // So does a tag computed over a different identity or a different header.
    assert!(!session.is_valid_retry(&ConnectionId::new(&[9; 8]), header, &payload));
    assert!(!session.is_valid_retry(&cid, b"other-pseudo-header", &payload));
    // A payload shorter than the tag has nothing to verify.
    for len in 0..16 {
        assert!(
            !session.is_valid_retry(&cid, header, &payload[..len]),
            "a {len}-byte Retry payload must be refused"
        );
    }
}

/// The client ticket cache is bounded. Once it is full the oldest entry makes room for the
/// newest, rather than the cache growing for the life of the configuration. Checking only the
/// most recent host would also pass against a cache that kept a single entry, so this pins a
/// host behind it as well.
#[test]
fn a_full_ticket_cache_evicts_its_oldest_entry() {
    const HANDSHAKES: usize = 80;

    let host = |index: usize| format!("host{index}.example");
    let (client_tls, server_tls) = configs_for(
        (0..HANDSHAKES).map(|index| rama_net::address::Domain::try_from(host(index)).unwrap()),
    );
    let options = TlsOptions::default().with_early_data(true);
    let client = Arc::new(QuicClientConfig::from_rama(&client_tls, options).unwrap());
    let server = Arc::new(QuicServerConfig::from_rama(&server_tls, options).unwrap());

    // More tickets than the cache holds, so its earliest entries are pushed out. Each
    // handshake issues at least one ticket, so the exact count per handshake does not matter.
    for index in 0..HANDSHAKES {
        let mut c = client
            .clone()
            .start_session(Version::V1, &host(index), &params(Side::Client))
            .unwrap();
        let mut s = server
            .clone()
            .start_session(Version::V1, &params(Side::Server))
            .unwrap();
        handshake(&mut *c, &mut *s).unwrap();
    }

    let recent = client
        .clone()
        .start_session(Version::V1, &host(HANDSHAKES - 2), &params(Side::Client))
        .unwrap();
    assert!(
        recent.transport_parameters().unwrap().is_some(),
        "a recent host must still be cached"
    );
    let oldest = client
        .start_session(Version::V1, &host(0), &params(Side::Client))
        .unwrap();
    assert!(
        oldest.transport_parameters().unwrap().is_none(),
        "the oldest host must have been evicted"
    );
}

#[test]
fn boring_requires_explicit_alpn() {
    use crate::proto::crypto::config::{AlpnPolicy, TlsConfigError};
    for (policy, out_of_band) in [
        (AlpnPolicy::Require, false),
        (AlpnPolicy::OutOfBandAgreement, true),
    ] {
        let result = QuicClientConfig::from_rama(
            &TlsClientConfig::new(),
            TlsOptions::default().with_alpn(policy),
        );
        assert!(matches!(
            (result, out_of_band),
            (Err(TlsConfigError::AlpnRequired), false)
                | (Err(TlsConfigError::UnsupportedOutOfBandAgreement), true)
        ));
    }
}

#[test]
fn client_authentication_is_verified_and_retained_on_resumption() {
    use rama_crypto::{
        dep::boring::{
            asn1::Asn1Time,
            bn::BigNum,
            ec::{EcGroup, EcKey},
            hash::MessageDigest,
            nid::Nid,
            pkey::PKey,
            x509::{
                X509, X509NameBuilder,
                extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
            },
        },
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    };
    use rama_tls::{
        TlsBackend,
        client::{ClientAuth, ClientAuthData},
        server::ClientVerifyMode,
    };

    let identity = |name: &str| {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_nid(Nid::COMMONNAME, name).unwrap();
        let subject = subject.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&subject).unwrap();
        cert.set_issuer_name(&subject).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.append_extension(&BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        cert.append_extension(&KeyUsage::new().digital_signature().build().unwrap())
            .unwrap();
        cert.append_extension(&ExtendedKeyUsage::new().client_auth().build().unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        ClientAuthData {
            private_key: PrivatePkcs8KeyDer::from(key.private_key_to_der_pkcs8().unwrap()).into(),
            cert_chain: vec![CertificateDer::from(cert.build().to_der().unwrap())],
        }
    };
    let trusted = identity("trusted client");
    let stranger = identity("untrusted client");
    for (client_backend, server_backend) in [
        (TlsBackend::Boring, TlsBackend::Boring),
        #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
        (TlsBackend::Rustls, TlsBackend::Boring),
        #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
        (TlsBackend::Boring, TlsBackend::Rustls),
    ] {
        let (base_client, server) = configs();
        let server =
            server.with_client_verify(ClientVerifyMode::ClientAuth(trusted.cert_chain.clone()));
        let server = crate::ServerConfig::try_from_rama_tls(
            &server,
            TlsOptions::default().with_backend(server_backend),
        )
        .unwrap()
        .crypto;
        for (identity, accepted) in [
            (Some(trusted.clone()), true),
            (Some(stranger.clone()), false),
            (None, false),
        ] {
            let mut client = base_client.clone();
            if let Some(identity) = identity {
                client = client.with_client_auth(ClientAuth::Single(identity));
            }
            let client = crate::ClientConfig::try_from_rama_tls(
                &client,
                TlsOptions::default().with_backend(client_backend),
            )
            .unwrap()
            .crypto;
            for resumed in [false, true] {
                let mut c = client
                    .clone()
                    .start_session(Version::V1, "localhost", &params(Side::Client))
                    .unwrap();
                let mut s = server
                    .clone()
                    .start_session(Version::V1, &params(Side::Server))
                    .unwrap();
                if accepted {
                    check_session(&mut *c, &mut *s, resumed);
                    assert_eq!(s.peer_certificates().unwrap(), trusted.cert_chain);
                } else {
                    let error = handshake(&mut *c, &mut *s).unwrap_err();
                    assert!(
                        matches!(error.code().tls_alert(), Some(48 | 116)),
                        "unexpected client-auth failure: {error:?}"
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
#[test]
fn both_directions_interoperate_with_rustls() {
    use crate::proto::crypto::rustls;
    for boring_client in [true, false] {
        let (client, server) = configs();
        let options = TlsOptions::default().with_early_data(true);
        let client: Arc<dyn crypto::ClientConfig> = if boring_client {
            Arc::new(QuicClientConfig::from_rama(&client, options).unwrap())
        } else {
            Arc::new(
                rustls::QuicClientConfig::from_rama(
                    &client,
                    rustls::configured_provider(),
                    options,
                )
                .unwrap(),
            )
        };
        let server: Arc<dyn crypto::ServerConfig> = if boring_client {
            Arc::new(
                rustls::QuicServerConfig::from_rama(
                    &server,
                    rustls::configured_provider(),
                    options,
                )
                .unwrap(),
            )
        } else {
            Arc::new(QuicServerConfig::from_rama(&server, options).unwrap())
        };
        for resumed in [false, true] {
            let mut c = client
                .clone()
                .start_session(Version::V1, "localhost", &params(Side::Client))
                .unwrap();
            let mut s = server
                .clone()
                .start_session(Version::V1, &params(Side::Server))
                .unwrap();
            assert_eq!(c.early_crypto().is_some(), resumed);
            check_session(&mut *c, &mut *s, resumed);
            assert_eq!(c.early_data_accepted(), Some(resumed));
        }
    }
}

#[tokio::test]
async fn udp_endpoints_exchange_streams_datagrams_and_early_data() {
    use crate::{ClientConfig, Endpoint, ServerConfig};
    use rama_core::{bytes::Bytes, rt::Executor};
    use rama_quic_proto::VarInt;
    use rama_tls::TlsBackend;
    use std::{net::UdpSocket, time::Duration};

    let pairs = [
        (TlsBackend::Boring, TlsBackend::Boring),
        #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
        (TlsBackend::Boring, TlsBackend::Rustls),
        #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
        (TlsBackend::Rustls, TlsBackend::Boring),
    ];
    for (client_backend, server_backend) in pairs {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (client_tls, server_tls) = configs();
            let options = TlsOptions::default().with_early_data(true);
            let client_config =
                ClientConfig::try_from_rama_tls(&client_tls, options.with_backend(client_backend))
                    .unwrap();
            let server_config =
                ServerConfig::try_from_rama_tls(&server_tls, options.with_backend(server_backend))
                    .unwrap();
            let client = Endpoint::new_client_with_std_socket(
                Executor::new(),
                UdpSocket::bind("127.0.0.1:0").unwrap(),
            )
            .unwrap();
            let server = Endpoint::new_server_with_std_socket(
                Executor::new(),
                server_config,
                UdpSocket::bind("127.0.0.1:0").unwrap(),
            )
            .unwrap();
            for resumed in [false, true] {
                let connecting = client
                    .connect_with(
                        client_config.clone(),
                        server.local_addr().unwrap(),
                        "localhost",
                    )
                    .unwrap();
                let (client_conn, server_conn) = if resumed {
                    let (connection, accepted) = connecting.into_0rtt().unwrap();
                    let mut stream = connection.open_uni().await.unwrap();
                    stream.write_all(b"early request").await.unwrap();
                    stream.finish().unwrap();
                    let peer = server.accept().await.unwrap().await.unwrap();
                    assert!(accepted.await.unwrap());
                    let mut stream = peer.accept_uni().await.unwrap();
                    assert_eq!(stream.read_to_end(32).await.unwrap(), b"early request");
                    (connection, peer)
                } else {
                    let (connection, peer) =
                        tokio::join!(connecting, async { server.accept().await.unwrap().await });
                    (connection.unwrap(), peer.unwrap())
                };
                client_conn.handshake_confirmed().await.unwrap();
                server_conn.handshake_confirmed().await.unwrap();
                for conn in [&client_conn, &server_conn] {
                    assert_eq!(conn.handshake_data().unwrap().resumed, Some(resumed));
                }
                assert!(client_conn.force_key_update());
                assert!(server_conn.force_key_update());
                for (sender, receiver) in
                    [(&client_conn, &server_conn), (&server_conn, &client_conn)]
                {
                    sender
                        .send_datagram(Bytes::from_static(b"datagram"))
                        .unwrap();
                    assert_eq!(&receiver.read_datagram().await.unwrap()[..], b"datagram");
                    let mut send = sender.open_uni().await.unwrap();
                    send.write_all(b"stream after key update").await.unwrap();
                    send.finish().unwrap();
                    let mut recv = receiver.accept_uni().await.unwrap();
                    assert_eq!(
                        recv.read_to_end(64).await.unwrap(),
                        b"stream after key update"
                    );
                }
                client_conn.close(VarInt::from_u32(0), b"done");
                server_conn.closed().await;
            }
            tokio::join!(client.shutdown(), server.shutdown());
        })
        .await
        .unwrap_or_else(|_| {
            panic!("endpoint exchange timed out: {client_backend:?}/{server_backend:?}")
        });
    }
}
