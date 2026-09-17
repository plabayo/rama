//! QUIC version 2 (RFC 9369): the wire constants against the RFC's own vectors, through the
//! provider traits so every TLS backend is held to them, and a v2 handshake end to end.

use rama_core::bytes::BytesMut;
use rama_quic_proto::{ConnectionId, Dir, Side, VarInt, Version, version::LongKind};

use super::*;

/// Non-empty parameters: BoringSSL refuses to start a QUIC session without any.
fn client_params(cid: ConnectionId) -> TransportParameters {
    TransportParameters {
        initial_src_cid: Some(cid),
        ..TransportParameters::default()
    }
}

fn hex(input: &str) -> Vec<u8> {
    rama_utils::hex::decode(input.split_whitespace().collect::<String>())
        .expect("valid hex in an RFC vector")
}

/// RFC 9369 Appendix A.3: the server Initial protected with v2 Initial keys.
const SERVER_INITIAL_HEADER: &str = "d16b3343cf0008f067a5502a4262b50040750001";
const SERVER_INITIAL_PAYLOAD: &str =
    "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
    88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
    0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304";
const SERVER_INITIAL_PROTECTED: &str =
    "dc6b3343cf0008f067a5502a4262b500 4075d92faaf16f05d8a4398c47089698
    baeea26b91eb761d9b89237bbf872630 17915358230035f7fd3945d88965cf17
    f9af6e16886c61bfc703106fbaf3cb4c fa52382dd16a393e42757507698075b2
    c984c707f0a0812d8cd5a6881eaf21ce da98f4bd23f6fe1a3e2c43edd9ce7ca8 4bed8521e2e140";

/// RFC 9369 Appendix A.4: a Retry for the client Initial of A.2.
const RETRY_WITHOUT_TAG: &str = "cf6b3343cf0008f067a5502a4262b574 6f6b656e";
const RETRY_TAG: &str = "c8646ce8bfe33952d955543665dcc7b6";

#[test]
fn rfc9369_server_initial_is_protected_with_v2_salt_and_labels() {
    let cid = ConnectionId::new(&hex("8394c8f03e515708"));
    let header = hex(SERVER_INITIAL_HEADER);
    let payload = hex(SERVER_INITIAL_PAYLOAD);
    let server = server_config()
        .crypto
        .initial_keys(Version::V2, &cid)
        .unwrap();
    let mut packet = header.clone();
    packet.extend_from_slice(&payload);
    packet.resize(packet.len() + server.local.packet.tag_len(), 0);
    server
        .local
        .packet
        .encrypt(1, &mut packet, header.len())
        .unwrap();
    server.local.header.encrypt(header.len() - 2, &mut packet);
    assert_eq!(packet, hex(SERVER_INITIAL_PROTECTED));

    // The client derives the same keys for the same version from a started session.
    let client = client_config()
        .crypto
        .start_session(Version::V2, "localhost", &client_params(cid))
        .unwrap();
    let read = client
        .initial_keys(Version::V2, &cid, Side::Client)
        .unwrap()
        .remote
        .unwrap();
    read.header.decrypt(header.len() - 2, &mut packet);
    assert_eq!(&packet[..header.len()], header);
    let mut decrypted = BytesMut::from(&packet[header.len()..]);
    read.packet.decrypt(1, &header, &mut decrypted).unwrap();
    assert_eq!(decrypted, payload);
}

#[test]
fn v1_initial_keys_do_not_open_a_v2_initial() {
    let cid = ConnectionId::new(&hex("8394c8f03e515708"));
    let header = hex(SERVER_INITIAL_HEADER);
    let mut packet = hex(SERVER_INITIAL_PROTECTED);
    let read = server_config()
        .crypto
        .initial_keys(Version::V1, &cid)
        .unwrap()
        .remote
        .unwrap();
    read.header.decrypt(header.len() - 2, &mut packet);
    let mut decrypted = BytesMut::from(&packet[header.len()..]);
    assert!(read.packet.decrypt(1, &header, &mut decrypted).is_err());
}

#[test]
fn rfc9369_retry_tag_uses_the_v2_key_and_nonce() {
    let cid = ConnectionId::new(&hex("8394c8f03e515708"));
    let packet = hex(RETRY_WITHOUT_TAG);
    let server = server_config();
    assert_eq!(
        server.crypto.retry_tag(Version::V2, &cid, &packet).unwrap()[..],
        hex(RETRY_TAG)[..]
    );
    assert_ne!(
        server.crypto.retry_tag(Version::V1, &cid, &packet).unwrap()[..],
        hex(RETRY_TAG)[..]
    );

    // A client session started in v2 accepts it; one started in v1 does not.
    let mut payload = hex("746f6b656e");
    payload.extend_from_slice(&hex(RETRY_TAG));
    let header = hex("cf6b3343cf0008f067a5502a4262b5");
    for (version, valid) in [(Version::V2, true), (Version::V1, false)] {
        let session = client_config()
            .crypto
            .start_session(version, "localhost", &client_params(cid))
            .unwrap();
        assert_eq!(
            session.is_valid_retry(&cid, &header, &payload),
            valid,
            "{version}"
        );
    }
}

#[test]
fn unknown_versions_are_refused_by_the_provider() {
    let cid = ConnectionId::new(&hex("8394c8f03e515708"));
    let reserved = Version::from_u32(0x0a1a_2a3a);
    assert!(matches!(
        server_config().crypto.initial_keys(reserved, &cid),
        Err(crypto::InitialKeysError::UnsupportedVersion)
    ));
    assert!(matches!(
        client_config()
            .crypto
            .start_session(reserved, "localhost", &client_params(cid))
            .map(drop),
        Err(ConnectError::UnsupportedVersion)
    ));
}

/// A whole connection in version 2: the long headers carry the v2 type bits and version, and
/// data flows both ways.
#[test]
fn v2_handshake_completes_with_v2_long_headers() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut config = client_config();
    config.set_version(Version::V2).unwrap();
    let (client_ch, server_ch) = pair.connect_with(config);

    let wire = Version::V2.wire().unwrap();
    let mut kinds = Vec::new();
    for sent in pair.client_sent.iter().chain(&pair.server_sent) {
        let Some(version) = sent.version else {
            continue;
        };
        assert_eq!(version, Version::V2, "every long header carries v2");
        kinds.push(wire.long_kind(sent.first_byte));
    }
    // Handshake packets ride coalesced behind an Initial, so only Initials lead a datagram.
    assert!(kinds.contains(&LongKind::Initial));
    assert!(!kinds.contains(&LongKind::ZeroRtt) && !kinds.contains(&LongKind::Retry));

    const MSG: &[u8] = b"over version two";
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive();
    assert_eq!(pair.server_streams(server_ch).accept(Dir::Bi), Some(s));
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(true).unwrap();
    assert_eq!(chunks.next(usize::MAX).unwrap().unwrap().bytes[..], MSG[..]);
    let _transmit = chunks.finalize();
}

/// A server that speaks only v1 answers a v2 first flight with Version Negotiation that lists v1.
#[test]
fn a_v1_only_server_negotiates_a_v2_client_down() {
    let _guard = subscribe();
    let mut server_endpoint = EndpointConfig::try_with_rand_key().unwrap();
    server_endpoint.set_supported_versions(vec![Version::V1]);
    let server = Endpoint::new(
        Arc::new(server_endpoint),
        Some(Arc::new(server_config())),
        true,
        None,
    );
    let client = Endpoint::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        None,
        true,
        None,
    );
    let mut pair = Pair::new_from_endpoint(client, server);
    let mut config = client_config();
    config.set_version(Version::V2).unwrap();
    let client_ch = pair.begin_connect(config);
    pair.drive();
    match pair.client_conn_mut(client_ch).poll() {
        Some(Event::ConnectionLost {
            reason: ConnectionError::VersionMismatch { .. },
        }) => {}
        other => panic!("expected a version mismatch, got {other:?}"),
    }
}

// ---- RFC 9368 compatible version negotiation -------------------------------------------------

use rama_quic_proto::version::{ClientVersionPolicy, ServerVersionPolicy, VersionPreference};

fn server_preferring(versions: Vec<Version>) -> ServerConfig {
    let mut config = server_config();
    config.set_versions(
        ServerVersionPolicy::new()
            .try_with_preference(VersionPreference::Prefer(versions))
            .unwrap(),
    );
    config
}

fn pair_with(server: ServerConfig) -> Pair {
    Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        server,
    )
}

fn exchange(pair: &mut Pair, client_ch: ConnectionHandle, server_ch: ConnectionHandle) {
    const MSG: &[u8] = b"after negotiation";
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive();
    assert_eq!(pair.server_streams(server_ch).accept(Dir::Bi), Some(s));
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(true).unwrap();
    assert_eq!(chunks.next(usize::MAX).unwrap().unwrap().bytes[..], MSG[..]);
    let _transmit = chunks.finalize();
}

/// A server that prefers v2 moves a client that offered it, when the client's TLS session can
/// follow (Boring); a client that cannot switch only offers v1 and stays there.
#[test]
fn a_server_preferring_v2_moves_a_client_that_offered_it() {
    let _guard = subscribe();
    let mut pair = pair_with(server_preferring(vec![Version::V2]));
    let config = client_config();
    let switchable = config.versions_policy().needs_switch();
    let (client_ch, server_ch) = pair.connect_with(config);
    let expected = if switchable { Version::V2 } else { Version::V1 };

    assert_eq!(pair.client_conn_mut(client_ch).version(), expected);
    assert_eq!(pair.server_conn_mut(server_ch).version(), expected);
    assert_eq!(
        pair.client_conn_mut(client_ch).original_version(),
        Version::V1
    );
    assert_eq!(
        pair.server_conn_mut(server_ch).original_version(),
        Version::V1
    );

    // The first flight is v1; everything the server sends with a long header is the negotiated
    // version, and a moved client follows it.
    assert_eq!(pair.client_sent[0].version, Some(Version::V1));
    assert!(
        pair.server_sent
            .iter()
            .filter_map(|sent| sent.version)
            .all(|v| v == expected)
    );
    if switchable {
        assert!(
            pair.client_sent
                .iter()
                .filter_map(|sent| sent.version)
                .any(|v| v == Version::V2)
        );
    }
    exchange(&mut pair, client_ch, server_ch);
}

#[test]
fn a_server_keeping_the_clients_choice_stays_in_the_first_flights_version() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect_with(client_config());
    assert_eq!(pair.client_conn_mut(client_ch).version(), Version::V1);
    assert_eq!(pair.server_conn_mut(server_ch).version(), Version::V1);
    assert!(
        pair.server_sent
            .iter()
            .filter_map(|sent| sent.version)
            .all(|v| v == Version::V1)
    );
}

#[test]
fn a_client_offering_only_its_version_is_not_moved() {
    let _guard = subscribe();
    let mut pair = pair_with(server_preferring(vec![Version::V2]));
    let mut config = client_config();
    config
        .set_versions(ClientVersionPolicy::new(Version::V1).unwrap())
        .unwrap();
    let (client_ch, server_ch) = pair.connect_with(config);
    assert_eq!(pair.client_conn_mut(client_ch).version(), Version::V1);
    assert_eq!(pair.server_conn_mut(server_ch).version(), Version::V1);
    exchange(&mut pair, client_ch, server_ch);
}

/// A client that starts in v2 keeps v1 in its compatible list, so a server preferring v1 can
/// move it down.
#[test]
fn a_client_starting_in_v2_can_be_moved_down_to_v1() {
    let _guard = subscribe();
    let mut pair = pair_with(server_preferring(vec![Version::V1]));
    let mut config = client_config();
    config.set_version(Version::V2).unwrap();
    let switchable = config.versions_policy().needs_switch();
    let (client_ch, server_ch) = pair.connect_with(config);
    let expected = if switchable { Version::V1 } else { Version::V2 };
    assert_eq!(pair.client_conn_mut(client_ch).version(), expected);
    assert_eq!(pair.server_conn_mut(server_ch).version(), expected);
    assert_eq!(pair.client_sent[0].version, Some(Version::V2));
    exchange(&mut pair, client_ch, server_ch);
}

#[test]
fn both_sides_record_the_others_version_information() {
    let _guard = subscribe();
    let mut pair = pair_with(server_preferring(vec![Version::V2]));
    let config = client_config();
    let offered = config.versions_policy().compatible().to_vec();
    let (client_ch, server_ch) = pair.connect_with(config);
    let negotiated = pair.client_conn_mut(client_ch).version();

    let from_client = pair
        .server_conn_mut(server_ch)
        .peer_params()
        .version_information
        .clone()
        .expect("the client sends version_information");
    assert_eq!(from_client.chosen(), Version::V1);
    assert!(offered.iter().all(|v| from_client.available().contains(v)));
    assert!(from_client.available().iter().any(|v| v.is_reserved()));

    let from_server = pair
        .client_conn_mut(client_ch)
        .peer_params()
        .version_information
        .clone()
        .expect("the server sends version_information");
    assert_eq!(from_server.chosen(), negotiated);
    assert!(from_server.available().contains(&Version::V1));
    assert!(from_server.available().contains(&Version::V2));
    assert!(from_server.available().iter().any(|v| v.is_reserved()));
}

/// A server told to report nothing as fully deployed still names the version in use.
#[test]
fn a_server_may_report_an_empty_fully_deployed_list() {
    let _guard = subscribe();
    let mut server = server_config();
    server.set_versions(
        ServerVersionPolicy::new()
            .try_with_fully_deployed(vec![])
            .unwrap()
            .with_reserved_version_grease(false),
    );
    let mut pair = pair_with(server);
    let (client_ch, _) = pair.connect_with(client_config());
    let from_server = pair
        .client_conn_mut(client_ch)
        .peer_params()
        .version_information
        .clone()
        .unwrap();
    assert_eq!(from_server.chosen(), Version::V1);
    assert!(from_server.available().is_empty());
}

/// A ticket belongs to the version it was issued in (RFC 9369 §5): after a switch it is a
/// ticket for the negotiated version, the next first flight starts in that version, and a
/// server that would prefer another version leaves a resuming connection where it is, so
/// 0-RTT arrives in the version the ticket was issued in.
#[test]
fn a_resumed_connection_keeps_its_ticket_version_and_its_0rtt() {
    let _guard = subscribe();
    let first = server_preferring(vec![Version::V2]);
    // The same TLS configuration, so its tickets stay valid, with the opposite preference.
    let mut second = first.clone();
    second.set_versions(
        ServerVersionPolicy::new()
            .try_with_preference(VersionPreference::Prefer(vec![Version::V1]))
            .unwrap(),
    );
    let mut pair = pair_with(first);
    pair.server.handle_incoming = Box::new(validate_incoming);
    let config = client_config();
    let switchable = config.versions_policy().needs_switch();

    let client_ch = pair.begin_connect(config.clone());
    pair.drive();
    let server_ch = pair.server.assert_accept();
    let ticket_version = pair.server_conn_mut(server_ch).version();
    assert_eq!(
        ticket_version,
        if switchable { Version::V2 } else { Version::V1 }
    );
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt::from_u32(0), [][..].into());
    pair.drive();

    // The server would now rather have v1, but a resuming client is not moved.
    pair.server
        .endpoint
        .set_server_config(Some(Arc::new(second)));
    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().next().unwrap(),
    );
    pair.client_sent.clear();
    let client_ch = pair.begin_connect(config);
    assert!(
        pair.client_conn_mut(client_ch).has_0rtt(),
        "the ticket resumes"
    );
    assert_eq!(
        pair.client_conn_mut(client_ch).original_version(),
        ticket_version,
        "the first flight follows the ticket's version"
    );
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, s).write(b"early").unwrap();
    pair.drive();
    let server_ch = pair.server.assert_accept();
    pair.drive();

    assert_eq!(pair.client_conn_mut(client_ch).version(), ticket_version);
    assert_eq!(pair.server_conn_mut(server_ch).version(), ticket_version);
    assert!(pair.client_conn_mut(client_ch).accepted_0rtt());
    let zero_rtt: Vec<_> = pair
        .client_sent
        .iter()
        .flat_map(|sent| sent.packets.iter())
        .filter(|packet| packet.long_kind() == Some(LongKind::ZeroRtt))
        .collect();
    assert!(!zero_rtt.is_empty(), "0-RTT was sent");
    assert!(
        zero_rtt
            .iter()
            .all(|packet| packet.version == Some(ticket_version))
    );
    exchange(&mut pair, client_ch, server_ch);
}

// ---- RFC 9369 §5: tickets and tokens belong to one version -----------------------------------

/// A session ticket resumes only a connection in the version that issued it.
#[test]
fn a_ticket_is_not_offered_in_another_version() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let config = client_config();

    let client_ch = pair.begin_connect(config.clone());
    pair.drive();
    pair.server.assert_accept();
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt::from_u32(0), [][..].into());
    pair.drive();

    // The same TLS configuration, starting in v2: nothing to resume with.
    let mut v2 = config.clone();
    v2.set_version(Version::V2).unwrap();
    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().next().unwrap(),
    );
    let client_ch = pair.begin_connect(v2);
    assert!(!pair.client_conn_mut(client_ch).has_0rtt());
    pair.drive();
    pair.server.assert_accept();
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt::from_u32(0), [][..].into());
    pair.drive();

    // Back in v1, the v1 ticket is still there.
    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().next().unwrap(),
    );
    let client_ch = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
}

/// A NEW_TOKEN token validates an address only for a connection in the version that issued it.
#[test]
fn a_new_token_validates_only_the_version_that_issued_it() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let config = client_config();

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(!incoming.remote_address_validated());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch, _) = pair.connect_with(config.clone());
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt::from_u32(0), [][..].into());
    pair.drive();

    // The v1 token is not sent with a v2 first flight, so the address is not validated.
    let mut v2 = config.clone();
    v2.set_version(Version::V2).unwrap();
    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(!incoming.remote_address_validated());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch, _) = pair.connect_with(v2);
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt::from_u32(0), [][..].into());
    pair.drive();

    // In v1 it is, and the server accepts it.
    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch, _) = pair.connect_with(config);
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt::from_u32(0), [][..].into());
    pair.drive();
}
