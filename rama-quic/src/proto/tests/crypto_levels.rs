//! CRYPTO data belongs to the encryption level of the TLS message it carries (RFC 9001 §4.1.3).

use super::*;
use crate::proto::crypto::{DirectionalKeys, HandshakeEvent};
use rama_quic_proto::{
    packet::{FixedLengthConnectionIdParser, LongType, PartialDecode, SpaceId},
    version::WireVersion,
};

const SERVER_CID: [u8; 8] = [0x5e; 8];

/// What a client's first flight tells a server that answers it by hand.
struct ClientFlight {
    version: Version,
    wire_version: WireVersion,
    /// The destination CID the client chose, which keys the Initial packets.
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    hello: Vec<u8>,
}

/// Open one of the client's Initial packets: its header and its frames.
fn open_initial(wire: &BytesMut) -> (InitialHeader, Bytes) {
    let version = Version::from_be_bytes(wire[1..5].try_into().unwrap());
    let dst_cid = ConnectionId::new(&wire[6..6 + usize::from(wire[5])]);
    let keys = server_config()
        .crypto
        .initial()
        .initial_keys(version, &dst_cid)
        .unwrap();
    let keys = keys.remote.as_ref().unwrap();
    let (decode, rest) = PartialDecode::new(
        wire.clone(),
        &FixedLengthConnectionIdParser::new(8),
        &[version],
        true,
    )
    .unwrap();
    assert!(rest.is_none());
    let mut packet = decode.finish_protected(keys.header.as_ref()).unwrap();
    let Header::Initial(header) = packet.header else {
        panic!("expected Initial");
    };
    keys.packet
        .decrypt(
            header.number.expand(0),
            &packet.header_data,
            &mut packet.payload,
        )
        .unwrap();
    (header, packet.payload.freeze())
}

fn client_flight(pair: &Pair) -> ClientFlight {
    let mut hello = Vec::new();
    let mut first = None;
    for inbound in &pair.server.inbound {
        let (header, payload) = open_initial(&inbound.packet);
        for frame in frame::Iter::new(payload).unwrap() {
            if let Frame::Crypto(crypto) = frame.unwrap() {
                let offset = crypto.offset as usize;
                let end = offset + crypto.data.len();
                if hello.len() < end {
                    hello.resize(end, 0);
                }
                hello[offset..end].copy_from_slice(&crypto.data);
            }
        }
        first.get_or_insert((
            Version::from_be_bytes(inbound.packet[1..5].try_into().unwrap()),
            header,
        ));
    }
    let (version, header) = first.expect("the client sent an Initial");
    ClientFlight {
        version,
        wire_version: header.version,
        dst_cid: header.dst_cid,
        src_cid: header.src_cid,
        hello,
    }
}

/// A TLS server's answer to the client's hello, as the bytes of each level.
struct ServerFlight {
    hello: Vec<u8>,
    /// EncryptedExtensions through Finished, one entry per TLS message.
    messages: Vec<Vec<u8>>,
    handshake_keys: DirectionalKeys,
}

fn server_flight(client: &ClientFlight) -> ServerFlight {
    let params = TransportParameters {
        original_dst_cid: Some(client.dst_cid),
        initial_src_cid: Some(ConnectionId::new(&SERVER_CID)),
        ..TransportParameters::default()
    };
    let mut session = server_config()
        .crypto
        .into_fixed()
        .start_session(client.version, &params)
        .unwrap();
    session
        .read_handshake(SpaceId::Initial, &client.hello)
        .unwrap();
    let mut hello = Vec::new();
    let mut handshake = Vec::new();
    let mut handshake_keys = None;
    while let Some(event) = session.poll_handshake().unwrap() {
        match event {
            HandshakeEvent::Data(SpaceId::Initial, bytes) => hello.extend(bytes),
            HandshakeEvent::Data(SpaceId::Handshake, bytes) => handshake.extend(bytes),
            HandshakeEvent::Keys(SpaceId::Handshake, keys) => handshake_keys = Some(keys.local),
            _ => {}
        }
    }
    let mut messages = Vec::new();
    let mut rest = handshake.as_slice();
    while !rest.is_empty() {
        let len = 4 + u32::from_be_bytes([0, rest[1], rest[2], rest[3]]) as usize;
        let (message, tail) = rest.split_at(len);
        messages.push(message.to_vec());
        rest = tail;
    }
    assert!(messages.len() >= 4, "EncryptedExtensions through Finished");
    ServerFlight {
        hello,
        messages,
        handshake_keys: handshake_keys.expect("handshake keys follow the ServerHello"),
    }
}

fn encode_crypto(output: &mut Vec<u8>, frames: &[(usize, &[u8])]) {
    for (offset, data) in frames {
        frame::Crypto {
            offset: *offset as u64,
            data: Bytes::copy_from_slice(data),
        }
        .encode(output);
    }
}

/// A server Initial that carries `frames` as CRYPTO frames in the given order.
fn server_initial(client: &ClientFlight, frames: &[(usize, &[u8])]) -> BytesMut {
    let keys = server_config()
        .crypto
        .initial()
        .initial_keys(client.version, &client.dst_cid)
        .unwrap()
        .local;
    let mut output = Vec::new();
    let partial = Header::Initial(InitialHeader {
        dst_cid: client.src_cid,
        src_cid: ConnectionId::new(&SERVER_CID),
        token: Bytes::new(),
        number: PacketNumber::U8(0),
        version: client.wire_version,
    })
    .encode_with_max_packet_len(&mut output, 4096);
    encode_crypto(&mut output, frames);
    let size = output.len().max(1200 - keys.packet.tag_len());
    output.resize(size + keys.packet.tag_len(), 0);
    partial
        .finish(
            &mut output,
            keys.header.as_ref(),
            Some((0, keys.packet.as_ref())),
        )
        .unwrap();
    BytesMut::from(output.as_slice())
}

/// A server Handshake packet that carries `frames` as CRYPTO frames in the given order.
fn server_handshake(
    client: &ClientFlight,
    keys: &DirectionalKeys,
    frames: &[(usize, &[u8])],
) -> BytesMut {
    let mut output = Vec::new();
    let partial = Header::Long {
        ty: LongType::Handshake,
        dst_cid: client.src_cid,
        src_cid: ConnectionId::new(&SERVER_CID),
        number: PacketNumber::U8(0),
        version: client.wire_version,
    }
    .encode_with_max_packet_len(&mut output, 4096);
    encode_crypto(&mut output, frames);
    output.resize(output.len() + keys.packet.tag_len(), 0);
    partial
        .finish(
            &mut output,
            keys.header.as_ref(),
            Some((0, keys.packet.as_ref())),
        )
        .unwrap();
    BytesMut::from(output.as_slice())
}

/// A client that sent its first flight, and that flight.
fn connecting_client() -> (Pair, ConnectionHandle, ClientFlight) {
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    let flight = client_flight(&pair);
    (pair, client, flight)
}

/// Hand the client `datagrams` from the server and return why it gave up.
fn client_refusal(
    mut pair: Pair,
    client: ConnectionHandle,
    datagrams: impl IntoIterator<Item = BytesMut>,
) -> TransportError {
    for datagram in datagrams {
        pair.client
            .inbound
            .push_back(Inbound::plain(pair.time, None, datagram));
    }
    pair.drive_client();
    let connection = pair.client_conn_mut(client);
    while let Some(event) = connection.poll() {
        if let Event::ConnectionLost {
            reason: ConnectionError::TransportError(error),
        } = event
        {
            return error;
        }
    }
    panic!("the client kept the connection");
}

/// The server flight laid out as one CRYPTO stream: each message with its offset.
fn laid_out(flight: &ServerFlight) -> Vec<(usize, &[u8])> {
    let mut offset = 0;
    std::iter::once(flight.hello.as_slice())
        .chain(flight.messages.iter().map(Vec::as_slice))
        .map(|message| {
            let at = offset;
            offset += message.len();
            (at, message)
        })
        .collect()
}

#[test]
fn a_client_refuses_handshake_messages_in_the_initial_packet_of_the_server_hello() {
    let (pair, client, hello) = connecting_client();
    let flight = server_flight(&hello);
    let initial = server_initial(&hello, &laid_out(&flight));

    let error = client_refusal(pair, client, [initial]);
    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
    assert_eq!(error.reason(), "new data at unexpected encryption level");
}

#[test]
fn a_client_refuses_initial_data_buffered_past_the_server_hello() {
    for following in [1, 4] {
        let (pair, client, hello) = connecting_client();
        let flight = server_flight(&hello);
        // The ServerHello arrives last, so the reassembled stream hands over everything at once.
        let mut frames = laid_out(&flight);
        frames.truncate(1 + following);
        frames.reverse();
        let initial = server_initial(&hello, &frames);

        let error = client_refusal(pair, client, [initial]);
        assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
        assert_eq!(
            error.reason(),
            "handshake data past an encryption level change"
        );
    }
}

#[test]
fn a_client_refuses_initial_data_held_behind_a_gap_past_the_server_hello() {
    let (pair, client, hello) = connecting_client();
    let flight = server_flight(&hello);
    // One byte is missing after the ServerHello, so the rest is never handed to TLS.
    let held = (flight.hello.len() + 1, flight.messages[0].as_slice());
    let initial = server_initial(&hello, &[held, (0, &flight.hello)]);

    let error = client_refusal(pair, client, [initial]);
    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
    assert_eq!(
        error.reason(),
        "handshake data past an encryption level change"
    );
}

#[test]
fn a_client_refuses_the_server_flight_in_one_initial_crypto_frame() {
    let (pair, client, hello) = connecting_client();
    let flight = server_flight(&hello);
    let mut joined = flight.hello.clone();
    joined.extend(flight.messages.iter().flatten());
    let initial = server_initial(&hello, &[(0, &joined)]);

    // One frame is one read for the TLS stack, which refuses what follows its key change.
    let _error = client_refusal(pair, client, [initial]);
}

#[test]
fn a_client_refuses_handshake_level_data_past_the_server_finished() {
    let (pair, client, hello) = connecting_client();
    let flight = server_flight(&hello);
    let initial = server_initial(&hello, &[(0, &flight.hello)]);
    let mut frames = laid_out(&flight);
    frames.remove(0);
    for frame in &mut frames {
        frame.0 -= flight.hello.len();
    }
    // The start of a NewSessionTicket, which belongs to the 1-RTT level.
    let end = frames.last().map(|(at, data)| at + data.len()).unwrap();
    frames.push((end, &[4, 0, 0, 16]));
    let handshake = server_handshake(&hello, &flight.handshake_keys, &frames);

    let error = client_refusal(pair, client, [initial, handshake]);
    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
    assert_eq!(error.reason(), "new data at unexpected encryption level");
}

#[test]
fn a_server_refuses_initial_data_past_the_client_hello() {
    for trailing_first in [false, true] {
        let (mut pair, _client, hello) = connecting_client();
        let last = pair.server.inbound.back_mut().unwrap();
        let (header, payload) = open_initial(&last.packet);
        let keys = server_config()
            .crypto
            .initial()
            .initial_keys(hello.version, &hello.dst_cid)
            .unwrap();
        let keys = keys.remote.as_ref().unwrap();
        let number = header.number.expand(0);
        let mut output = Vec::new();
        let partial = Header::Initial(header).encode_with_max_packet_len(&mut output, 4096);
        // The start of a Finished message, which belongs to the Handshake level.
        let trailing = [(hello.hello.len(), [20, 0, 0, 32].as_slice())];
        if trailing_first {
            encode_crypto(&mut output, &trailing);
            output.extend_from_slice(&payload);
        } else {
            output.extend_from_slice(&payload);
            encode_crypto(&mut output, &trailing);
        }
        output.resize(output.len() + keys.packet.tag_len(), 0);
        partial
            .finish(
                &mut output,
                keys.header.as_ref(),
                Some((number, keys.packet.as_ref())),
            )
            .unwrap();
        last.packet = BytesMut::from(output.as_slice());

        pair.drive_server();
        match pair.server.assert_accept_error() {
            ConnectionError::TransportError(error) => {
                assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
                assert_eq!(
                    error.reason(),
                    if trailing_first {
                        "handshake data past an encryption level change"
                    } else {
                        "new data at unexpected encryption level"
                    },
                    "trailing first: {trailing_first}"
                );
            }
            other => panic!("the server refused for another reason: {other:?}"),
        }
    }
}
