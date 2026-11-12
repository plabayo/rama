//! Peers that stray from RFC 9000 in ways deployed stacks accept.

use super::{observation::rewrite_initial, *};
use rama_quic_proto::packet::{
    FixedLengthConnectionIdParser, InitialHeader, PacketNumber, PartialDecode,
};

/// A ClientHello spread over several Initials, so later ones still carry handshake data.
fn large_hello_pair() -> (Pair, ConnectionHandle) {
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        ServerConfig::with_crypto(Arc::new(server_crypto_with_alpn(vec![b"h3".to_vec()]))),
    );
    let mut protocols: Vec<_> = (0..24u8).map(|n| vec![b'a' + n; 96]).collect();
    protocols.push(b"h3".to_vec());
    let client = pair.begin_connect(ClientConfig::new(Arc::new(client_crypto_with_alpn(
        protocols,
    ))));
    (pair, client)
}

#[test]
fn a_changed_token_on_a_later_initial_is_refused_only_after_a_retry() {
    for retry in [false, true] {
        let (mut pair, client) = large_hello_pair();
        pair.drive_client();
        if retry {
            pair.server.handle_incoming = Box::new(validate_incoming);
            pair.drive_server();
            pair.drive_client();
        }
        assert!(pair.server.inbound.len() > 1);
        let rest = pair.server.inbound.split_off(1);
        pair.drive_server();
        let server = pair.server.assert_accept();
        let before = pair.server_conn_mut(server).stats().frame_rx.crypto;

        let mut changed = rest.front().unwrap().clone();
        rewrite_initial(&mut changed.packet, false, true);
        pair.server.inbound.push_back(changed);
        pair.drive_server();
        let after = pair.server_conn_mut(server).stats().frame_rx.crypto;
        assert_eq!(after > before, !retry, "retry: {retry}");

        let mut rest = rest;
        if retry {
            // The refused copy left its packet number free for the genuine packet.
            pair.server.inbound.push_back(rest.pop_front().unwrap());
            pair.drive_server();
            let genuine = pair.server_conn_mut(server).stats().frame_rx.crypto;
            assert!(genuine > after);
        }
        pair.server.inbound.extend(rest);
        pair.drive();
        assert!(pair.client_conn_mut(client).handshake_confirmed());
    }
}

/// A server Initial holding one PING that answers `client_initial` from the destination CID the
/// client chose.
fn echoing_server_initial(client_initial: BytesMut) -> BytesMut {
    let version = Version::from_be_bytes(client_initial[1..5].try_into().unwrap());
    let initial_dst_cid = ConnectionId::new(&client_initial[6..6 + usize::from(client_initial[5])]);
    let keys = server_config()
        .crypto
        .initial()
        .initial_keys(version, &initial_dst_cid)
        .unwrap();
    let (decode, _) = PartialDecode::new(
        client_initial,
        &FixedLengthConnectionIdParser::new(8),
        &[version],
        true,
    )
    .unwrap();
    let packet = decode
        .finish_protected(keys.remote.as_ref().unwrap().header.as_ref())
        .unwrap();
    let Header::Initial(client) = packet.header else {
        panic!("expected Initial");
    };
    let keys = keys.local;
    let mut output = Vec::new();
    let partial = Header::Initial(InitialHeader {
        dst_cid: client.src_cid,
        src_cid: client.dst_cid,
        token: Bytes::new(),
        number: PacketNumber::U8(0),
        version: client.version,
    })
    .encode(&mut output);
    output.push(0x01);
    output.resize(1200, 0);
    partial
        .finish(
            &mut output,
            keys.header.as_ref(),
            Some((0, keys.packet.as_ref())),
        )
        .unwrap();
    BytesMut::from(output.as_slice())
}

#[test]
fn a_server_initial_echoing_the_clients_destination_cid_leaves_the_server_cid_open() {
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    let echo = echoing_server_initial(pair.server.inbound.front().unwrap().packet.clone());
    pair.client
        .inbound
        .push_back(Inbound::plain(pair.time, None, echo));
    pair.drive_client();

    pair.drive();
    assert!(pair.client_conn_mut(client).handshake_confirmed());
}
