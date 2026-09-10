//! What a connection in the closing state answers, and how often.
//!
//! RFC 9000 §10.2.1 asks an endpoint in that state to answer received packets progressively less
//! often. These tests drive each side by hand so the peer never learns of the close, and release
//! the peer's packets one at a time, so what earns an answer is exactly what the test says it is.

use std::{collections::VecDeque, mem, net::SocketAddr};

use crate::proto::Duration;

use rama_core::bytes::Bytes;

use super::{
    ApplicationClose, ConnectionError, ConnectionHandle, Event, Ipv6Addr, VarInt, subscribe,
    util::*,
};
use rama_crypto::dep::rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rama_tls_rustls::dep::rustls::AlertDescription;

use crate::proto::{
    DEFAULT_SUPPORTED_VERSIONS, TransportErrorCode,
    packet::{FixedLengthConnectionIdParser, PartialDecode},
    shared::{ConnectionEvent, ConnectionEventInner, DatagramConnectionEvent},
};

/// Take everything waiting for the client, so the test decides when each datagram reaches it.
fn hold_for_the_client(pair: &mut Pair) -> VecDeque<Inbound> {
    mem::take(&mut pair.client.inbound)
}

/// Fill that queue with packets the peer sends while the client is not looking.
fn gather_from_the_peer(
    pair: &mut Pair,
    server_ch: ConnectionHandle,
    count: usize,
) -> VecDeque<Inbound> {
    for _ in 0..count {
        pair.server_conn_mut(server_ch).ping();
        pair.drive_server();
    }
    let held = hold_for_the_client(pair);
    assert_eq!(
        held.len(),
        count,
        "the peer put {count} datagrams on the wire"
    );
    held
}

/// Give the client one held datagram, from `from` when given, and drive it. Answers whether it
/// transmitted anything.
fn release_one(pair: &mut Pair, held: &mut VecDeque<Inbound>, from: Option<SocketAddr>) -> bool {
    let mut datagram = held.pop_front().expect("a datagram was held for this");
    datagram.at = pair.time;
    if let Some(from) = from {
        datagram.from = Some(from);
    }
    pair.client.inbound.push_back(datagram);
    let before = pair.client_sent.len();
    pair.drive_client();
    assert!(
        pair.client.inbound.is_empty(),
        "the datagram was taken, not left waiting"
    );
    pair.client_sent.len() > before
}

/// Read a QUIC variable-length integer, answering its value and its width.
fn varint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(at)?;
    let width = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for step in 1..width {
        value = (value << 8) | u64::from(*bytes.get(at + step)?);
    }
    Some((value, width))
}

/// How many packets a datagram carries, walking the long headers by the length each declares.
/// A short header runs to the end of the datagram, so it is the last one. Every step is bounds
/// checked and a declared length that runs past the datagram is a fault, so a malformed one
/// cannot be counted as another packet.
fn packets_in(datagram: &[u8]) -> usize {
    let mut at = 0usize;
    let mut packets = 0usize;
    while at < datagram.len() {
        packets += 1;
        let first = datagram[at];
        if first & 0x80 == 0 {
            break;
        }
        let kind = (first & 0x30) >> 4;
        // The long header: one byte of flags, four of version, then each identifier with its
        // own length byte.
        let mut cursor = at + 5;
        for _ in 0..2 {
            let len = usize::from(*datagram.get(cursor).expect("an identifier length"));
            cursor = cursor
                .checked_add(1 + len)
                .filter(|next| *next <= datagram.len())
                .expect("an identifier inside the datagram");
        }
        if kind == 0 {
            let (token, width) = varint(datagram, cursor).expect("a token length");
            cursor = cursor
                .checked_add(width)
                .and_then(|next| next.checked_add(usize::try_from(token).ok()?))
                .filter(|next| *next <= datagram.len())
                .expect("a token inside the datagram");
        }
        if kind == 3 {
            // Retry carries no length and nothing may follow it.
            break;
        }
        let (length, width) = varint(datagram, cursor).expect("a payload length");
        at = cursor
            .checked_add(width)
            .and_then(|next| next.checked_add(usize::try_from(length).ok()?))
            .filter(|next| *next <= datagram.len())
            .expect("a payload inside the datagram");
    }
    packets
}

/// An address no connection in these tests is on, in the family the harness uses.
fn elsewhere() -> SocketAddr {
    SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9).into(), 4433)
}

/// Close the client and let its first close go out, then hand back packets the peer had already
/// sent, ready to be released one at a time.
fn closed_with_input_waiting(
    pair: &mut Pair,
    client_ch: ConnectionHandle,
    server_ch: ConnectionHandle,
    count: usize,
) -> VecDeque<Inbound> {
    let held = gather_from_the_peer(pair, server_ch, count);
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        Bytes::from_static(b"done"),
    );
    pair.drive_client();
    held
}

/// The answers fall further and further apart: each one doubles what the next costs.
#[test]
fn a_closed_connection_answers_progressively_less_often() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let mut held = closed_with_input_waiting(&mut pair, client_ch, server_ch, 40);

    let mut answered_at = Vec::new();
    for packet in 1..=40 {
        if release_one(&mut pair, &mut held, None) {
            answered_at.push(packet);
        }
    }
    assert_eq!(answered_at, vec![2, 6, 14, 30]);
}

/// Packets from an address the connection is not on never reach it: the endpoint discards a
/// datagram from an address it does not recognise. That is the outer half of the path rule.
#[test]
fn the_endpoint_discards_input_from_another_path() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let mut held = closed_with_input_waiting(&mut pair, client_ch, server_ch, 4);

    for _ in 0..4 {
        assert!(
            !release_one(&mut pair, &mut held, Some(elsewhere())),
            "nothing from another path is answered"
        );
    }
}

/// The inner half. A client discards a packet from another address before anything else looks
/// at it, so the closing state's own path guard is only reachable on a connection that would
/// otherwise follow a peer's move: a server that allows migration. Closed, it must not answer
/// an address it has not validated, and the packet must not buy eligibility either.
#[test]
fn a_closing_server_does_not_answer_an_address_it_has_not_validated() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    // Packets the client sent, held so the server takes them when this test says so.
    for _ in 0..12 {
        pair.client_conn_mut(client_ch).ping();
        pair.drive_client();
    }
    let mut held = mem::take(&mut pair.server.inbound);
    assert_eq!(held.len(), 12, "the client put 12 datagrams on the wire");

    pair.server.connections.get_mut(&server_ch).unwrap().close(
        pair.time,
        VarInt(42),
        Bytes::from_static(b"done"),
    );
    pair.drive_server();

    for _ in 0..8 {
        let datagram = held.pop_front().expect("a datagram was held for this");
        let before = pair.server_sent.len();
        hand_to_the_server(&mut pair, server_ch, datagram, elsewhere());
        pair.drive_server();
        assert_eq!(
            pair.server_sent.len(),
            before,
            "an address it has not validated is not answered"
        );
    }

    let mut answered_at = Vec::new();
    for packet in 1..=4 {
        let mut datagram = held.pop_front().expect("a datagram was held for this");
        datagram.at = pair.time;
        pair.server.inbound.push_back(datagram);
        let before = pair.server_sent.len();
        pair.drive_server();
        if pair.server_sent.len() > before {
            answered_at.push(packet);
        }
    }
    assert_eq!(
        answered_at,
        vec![2],
        "none of it counted towards the next answer"
    );
}

/// A close waiting to be sent stays waiting: the pass that takes the next packet in also sends
/// it, and the peer reports it.
#[test]
fn a_pending_close_is_sent_on_the_next_pass() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let mut held = gather_from_the_peer(&mut pair, server_ch, 1);

    // Closed, and not yet driven, so the close is still waiting to be encoded.
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        Bytes::from_static(b"done"),
    );

    assert!(
        release_one(&mut pair, &mut held, None),
        "the close that was waiting was sent"
    );
    pair.drive_server();
    match pair.server_conn_mut(server_ch).poll() {
        Some(Event::ConnectionLost {
            reason:
                ConnectionError::ApplicationClosed(ApplicationClose {
                    error_code: VarInt(42),
                    ..
                }),
        }) => {}
        other => panic!("the peer received the close, not {other:?}"),
    }
}

/// Hand a datagram straight to the server's connection, claiming it came from `remote`.
///
/// The endpoint discards a datagram from an address it does not recognise before any connection
/// sees it, so the closing state's own path guard cannot be reached through the endpoint. This
/// reaches it directly, which is the only way to test that guard.
fn hand_to_the_server(
    pair: &mut Pair,
    server_ch: ConnectionHandle,
    datagram: Inbound,
    remote: SocketAddr,
) {
    let (first_decode, remaining) = PartialDecode::new(
        datagram.packet,
        // The harness's endpoints use the default identifier length and grease the fixed bit.
        &FixedLengthConnectionIdParser::new(8),
        DEFAULT_SUPPORTED_VERSIONS,
        true,
    )
    .expect("the peer's datagram decodes");
    let now = pair.time;
    pair.server_conn_mut(server_ch)
        .handle_event(ConnectionEvent(ConnectionEventInner::Datagram(
            DatagramConnectionEvent {
                now,
                remote,
                local: datagram.to,
                ecn: datagram.ecn,
                first_decode,
                remaining,
            },
        )));
}

/// The closing state is finite, and neither input nor further close calls move its deadline.
#[test]
fn the_close_deadline_is_fixed_and_expires() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let mut held = closed_with_input_waiting(&mut pair, client_ch, server_ch, 8);

    let deadline = pair
        .client_conn_mut(client_ch)
        .poll_timeout()
        .expect("a closed connection has a deadline to drain on");

    // Time moves on between them, so a deadline reset to now plus three PTO on each input would
    // show up as a later deadline rather than the same one.
    for _ in 0..4 {
        pair.time += Duration::from_millis(1);
        let now = pair.time;
        pair.client_conn_mut(client_ch).handle_timeout(now);
        release_one(&mut pair, &mut held, None);
        pair.client.connections.get_mut(&client_ch).unwrap().close(
            now,
            VarInt(7),
            Bytes::from_static(b"again"),
        );
        assert_eq!(
            pair.client_conn_mut(client_ch).poll_timeout(),
            Some(deadline),
            "neither input nor another close call moves the deadline"
        );
    }

    // A moment before it, the connection is still closing.
    pair.time = deadline
        .checked_sub(Duration::from_micros(1))
        .expect("the deadline is past the epoch");
    let now = pair.time;
    pair.client_conn_mut(client_ch).handle_timeout(now);
    assert!(
        !pair.client_conn_mut(client_ch).is_drained(),
        "it has not drained yet"
    );

    // At it, the connection drains and says nothing more.
    pair.time = deadline;
    pair.client_conn_mut(client_ch).handle_timeout(deadline);
    assert!(
        pair.client_conn_mut(client_ch).is_drained(),
        "the deadline ended the closing state"
    );
    let before = pair.client_sent.len();
    release_one(&mut pair, &mut held, None);
    assert_eq!(
        pair.client_sent.len(),
        before,
        "and nothing is sent after it"
    );
}

/// Once the peer has closed too, the connection drains and answers nothing more, however much of
/// the peer's earlier traffic is delivered afterwards.
#[test]
fn a_peer_close_ends_the_answers() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let mut held = closed_with_input_waiting(&mut pair, client_ch, server_ch, 8);

    // The peer takes the close and answers with its own, which puts this side into draining.
    pair.drive_server();
    pair.drive_client();
    assert!(
        !pair.client_conn_mut(client_ch).is_drained(),
        "draining, not yet drained"
    );

    let before = pair.client_sent.len();
    for _ in 0..8 {
        release_one(&mut pair, &mut held, None);
    }
    assert_eq!(
        pair.client_sent.len(),
        before,
        "a draining connection answers nothing"
    );
}

/// The same, with the peer's close arriving while a local close is still waiting to be sent.
#[test]
fn a_peer_close_while_a_local_close_waits_ends_the_answers() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let mut held = gather_from_the_peer(&mut pair, server_ch, 8);

    // The peer closes first, and its close is held back.
    pair.server.connections.get_mut(&server_ch).unwrap().close(
        pair.time,
        VarInt(9),
        Bytes::from_static(b"peer"),
    );
    pair.drive_server();
    let mut peer_close = mem::take(&mut pair.client.inbound);
    assert_eq!(peer_close.len(), 1, "the peer's close is on the wire");

    // This side closes too, and does not get to send it before the peer's close arrives.
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        Bytes::from_static(b"done"),
    );
    release_one(&mut pair, &mut peer_close, None);

    let before = pair.client_sent.len();
    for _ in 0..8 {
        release_one(&mut pair, &mut held, None);
    }
    assert_eq!(
        pair.client_sent.len(),
        before,
        "nothing is answered once the peer has closed"
    );
}

/// A close the receive path decides on, rather than one the application asked for, is answered
/// on the very pass that decided it: no further input is needed, and the peer is told why.
#[test]
fn a_protocol_error_close_answers_on_the_pass_that_decided_it() {
    let _guard = subscribe();
    let mut pair = Pair::default();

    // A certificate from an issuer the client does not trust, distinct from the default root so
    // the failure is the anchor and not path building.
    let mut cert = CertificateParams::new(["localhost".into()]).unwrap();
    let mut issuer = DistinguishedName::new();
    issuer.push(DnType::OrganizationName, "Rama's House of Certificates");
    cert.distinguished_name = issuer;
    let cert = cert.self_signed(&KeyPair::generate().unwrap()).unwrap();
    let client_ch = pair.begin_connect(client_config_with_certs(vec![cert.into()]));

    pair.drive_client();
    let mut outcome = None;
    let mut answered_on_that_pass = false;
    for _ in 0..12 {
        pair.drive_server();
        let before = pair.client_sent.len();
        pair.drive_client();
        if let Some(event) = pair.client_conn_mut(client_ch).poll() {
            answered_on_that_pass = pair.client_sent.len() > before;
            outcome = Some(event);
            break;
        }
    }

    match outcome {
        Some(Event::ConnectionLost {
            reason: ConnectionError::TransportError(ref error),
        }) if error.code == TransportErrorCode::crypto(AlertDescription::UnknownCA.into()) => {}
        other => panic!("the client stopped on the certificate check, not {other:?}"),
    }
    assert!(
        answered_on_that_pass,
        "and answered on the pass that decided it, with no further input"
    );

    // The peer receives that close and reports the same reason.
    pair.drive_server();
    let server_ch = pair.server.assert_accept();
    let mut told = None;
    while let Some(event) = pair.server_conn_mut(server_ch).poll() {
        if let Event::ConnectionLost { reason } = event {
            told = Some(reason);
            break;
        }
    }
    match told {
        Some(ConnectionError::ConnectionClosed(ref close))
            if close.error_code
                == TransportErrorCode::crypto(AlertDescription::UnknownCA.into()) => {}
        other => panic!("the peer was told why, not {other:?}"),
    }
}

/// The keys' budget still governs. A closing connection whose 1-RTT keys have reached their
/// confidentiality limit encrypts nothing further with them: it dies on the limit instead.
#[test]
fn an_exhausted_key_budget_stops_the_answers() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let mut held = closed_with_input_waiting(&mut pair, client_ch, server_ch, 8);

    let limit = pair.client_conn_mut(client_ch).confidentiality_limit();
    pair.client_conn_mut(client_ch)
        .set_packets_sent_with_keys(limit);

    let gap = pair.client_conn_mut(client_ch).close_response_gap();
    for _ in 0..8 {
        release_one(&mut pair, &mut held, None);
    }
    assert_eq!(
        pair.client_conn_mut(client_ch).packets_sent_with_keys(),
        limit,
        "no further packet was encrypted with the spent keys"
    );
    assert_eq!(
        pair.client_conn_mut(client_ch).close_response_gap(),
        gap,
        "and no answer was counted for a pass that encoded none"
    );
    assert!(
        pair.client_conn_mut(client_ch).is_drained(),
        "the connection died on the limit rather than answering past it"
    );
}

/// A close made before the handshake is confirmed is coalesced into one datagram, which RFC
/// 9000 §10.2.3 permits, and counts as one answer: the gap doubles once, not once per packet.
#[test]
fn a_coalesced_close_counts_once() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config());

    // One flight each way, so the client holds keys for more than one space and has not been
    // confirmed.
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();

    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        Bytes::from_static(b"done"),
    );
    let spaces = pair.client_conn_mut(client_ch).spaces_with_close_keys();
    assert!(
        spaces > 1,
        "this close has more than one space to go into: {spaces}"
    );
    assert_eq!(
        pair.client_conn_mut(client_ch).close_response_gap(),
        1,
        "nothing has been answered yet"
    );

    let before = pair.client_sent.len();
    pair.drive_client();
    assert!(pair.client_sent.len() > before, "the close went out");

    // What went out, as it sits on the wire: more than one packet in the datagram, the first of
    // them a long header.
    let datagram = pair
        .server
        .inbound
        .back()
        .expect("the close reached the peer's queue");
    assert!(
        datagram.packet[0] & 0x80 != 0,
        "the first packet has a long header"
    );
    assert!(
        packets_in(&datagram.packet) > 1,
        "and the datagram carries more than one packet"
    );

    assert_eq!(
        pair.client_conn_mut(client_ch).close_response_gap(),
        2,
        "one logical answer, however many packets carried it"
    );
}

/// A close a server has not sent yet stays pending when a packet arrives from an address it has
/// not validated. The server allows migration, so the packet is not discarded before the closing
/// state sees it.
#[test]
fn a_pending_server_close_survives_input_from_elsewhere() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    pair.client_conn_mut(client_ch).ping();
    pair.drive_client();
    let mut held = mem::take(&mut pair.server.inbound);
    assert_eq!(held.len(), 1, "the client put a datagram on the wire");

    // Closed, and not yet driven, so the close is still waiting to be encoded.
    pair.server.connections.get_mut(&server_ch).unwrap().close(
        pair.time,
        VarInt(42),
        Bytes::from_static(b"done"),
    );

    let datagram = held.pop_front().expect("a datagram was held for this");
    let before = pair.server_sent.len();
    hand_to_the_server(&mut pair, server_ch, datagram, elsewhere());
    pair.drive_server();
    assert!(
        pair.server_sent.len() > before,
        "the close that was waiting was not cleared by input from elsewhere"
    );

    pair.drive_client();
    match pair.client_conn_mut(client_ch).poll() {
        Some(Event::ConnectionLost {
            reason:
                ConnectionError::ApplicationClosed(ApplicationClose {
                    error_code: VarInt(42),
                    ..
                }),
        }) => {}
        other => panic!("the peer received the close, not {other:?}"),
    }
}
