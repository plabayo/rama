//! Exercise token state through authenticated peer packets and subsequent client Initials.

#![expect(
    clippy::unwrap_used,
    reason = "invalid fixed harness setup must fail the fuzz run"
)]

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, LazyLock},
};

use rama_core::bytes::{Bytes, BytesMut};
use rama_quic_proto::{
    ConnectionId, Side, VarInt, Version,
    frame::NewToken,
    packet::{
        FixedLengthConnectionIdParser, Header, InitialHeader, PacketNumber, PartialDecode, SpaceId,
    },
    version::ClientVersionPolicy,
};
use rama_tls::{
    client::TlsClientConfig,
    server::{LeafCertRequest, ServerAuthData, TlsServerConfig},
};

use super::Connection;
use crate::{
    ClientConfig, ServerConfig,
    proto::{
        ConnectionHandle, DEFAULT_SUPPORTED_VERSIONS, DatagramEvent, Duration, Endpoint,
        EndpointConfig, Instant, SendPermit,
    },
    tls::TlsOptions,
};

static IDENTITY: LazyLock<ServerAuthData> =
    LazyLock::new(|| ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap());

struct Peer {
    endpoint: Endpoint,
    connection: Option<(ConnectionHandle, Connection)>,
    outgoing: VecDeque<Vec<u8>>,
    address: SocketAddr,
}

impl Peer {
    fn new(config: Arc<EndpointConfig>, server: Option<Arc<ServerConfig>>, port: u16) -> Self {
        Self {
            endpoint: Endpoint::new(config, server, false, Some([port as u8; 32])),
            connection: None,
            outgoing: VecDeque::new(),
            address: ([127, 0, 0, 1], port).into(),
        }
    }

    fn receive(&mut self, now: Instant, remote: SocketAddr, packet: &[u8]) {
        let mut response = Vec::new();
        match self.endpoint.handle(
            now,
            remote,
            Some(self.address),
            None,
            BytesMut::from(packet),
            &mut response,
        ) {
            Some(DatagramEvent::NewConnection(incoming)) => {
                if self.connection.is_some() {
                    self.endpoint.ignore(incoming);
                } else {
                    match self.endpoint.accept(incoming, now, &mut response, None) {
                        Ok(connection) => self.connection = Some(connection),
                        Err(error) => {
                            if let Some(transmit) = error.response {
                                self.outgoing.push_back(response[..transmit.size].to_vec());
                            }
                        }
                    }
                }
            }
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                if let Some((current, connection)) = &mut self.connection {
                    assert_eq!(handle, *current);
                    connection.handle_event(event);
                }
            }
            Some(DatagramEvent::Response(transmit)) => {
                self.outgoing.push_back(response[..transmit.size].to_vec());
            }
            None => {}
        }
    }

    fn routes(&mut self) {
        if let Some((handle, connection)) = &mut self.connection {
            while let Some(event) = connection.poll_endpoint_events() {
                if let Some(reply) = self.endpoint.handle_event(*handle, event) {
                    connection.handle_event(reply);
                }
            }
        }
    }

    fn transmit(&mut self, now: Instant) {
        self.routes();
        let Some((_, connection)) = &mut self.connection else {
            return;
        };
        if connection.poll_timeout().is_some_and(|at| at <= now) {
            connection.handle_timeout(now);
        }
        let mut packet = Vec::new();
        let transmit = connection.poll_transmit(now, 1, &mut packet);
        self.routes();
        let Some(transmit) = transmit else {
            return;
        };
        let connection = &mut self.connection.as_mut().unwrap().1;
        if let Some(sequence) = transmit.cid_used {
            assert!(matches!(
                connection.may_send_cid(sequence, transmit.destination),
                SendPermit::Sendable
            ));
            connection.cid_sent(sequence, transmit.destination);
        }
        assert_eq!(transmit.size, packet.len());
        self.outgoing.push_back(packet);
    }
}

struct Pair {
    client: Peer,
    server: Peer,
    now: Instant,
    destination: ConnectionId,
    source: ConnectionId,
    version: Version,
    server_config: Arc<ServerConfig>,
}

impl Pair {
    fn new(
        client_config: ClientConfig,
        server_config: Arc<ServerConfig>,
        version: Version,
    ) -> Self {
        let mut endpoint_config = EndpointConfig::try_with_rand_key().unwrap();
        endpoint_config.max_udp_payload_size(65_527).unwrap();
        let endpoint_config = Arc::new(endpoint_config);
        let mut client = Peer::new(endpoint_config.clone(), None, 4434);
        let server = Peer::new(endpoint_config, Some(server_config.clone()), 4433);
        let now = Instant::now();
        client.connection = Some(
            client
                .endpoint
                .connect(now, client_config, server.address, "localhost")
                .unwrap(),
        );
        client.transmit(now);
        let (source, destination) = client
            .outgoing
            .front()
            .map(|packet| {
                let (decoded, _) = PartialDecode::new(
                    packet.as_slice().into(),
                    &FixedLengthConnectionIdParser::new(0),
                    DEFAULT_SUPPORTED_VERSIONS,
                    // A token from a server that greases the QUIC bit lets this client grease
                    // its first flight too (RFC 9287 §3.1).
                    true,
                )
                .unwrap();
                let header = decoded.initial_header().unwrap();
                (header.src_cid, header.dst_cid)
            })
            .unwrap_or((ConnectionId::new(&[]), ConnectionId::new(&[])));
        Self {
            client,
            server,
            now,
            source,
            destination,
            version,
            server_config,
        }
    }

    fn drive(&mut self) {
        for _ in 0..64 {
            self.client.transmit(self.now);
            while let Some(packet) = self.client.outgoing.pop_front() {
                self.server.receive(self.now, self.client.address, &packet);
            }
            self.server.transmit(self.now);
            while let Some(packet) = self.server.outgoing.pop_front() {
                self.client.receive(self.now, self.server.address, &packet);
            }
            self.now += Duration::from_millis(1);
        }
    }

    fn retry(&mut self, flags: u8, token: &[u8]) {
        let mut packet = Vec::new();
        Header::Retry {
            src_cid: if flags & 8 != 0 {
                self.destination
            } else {
                ConnectionId::new(&[0xa5; 20])
            },
            dst_cid: self.source,
            version: self.version.to_wire().unwrap(),
        }
        .encode(&mut packet);
        packet.extend_from_slice(token);
        let mut tag = self
            .server_config
            .crypto
            .initial()
            .retry_tag(self.version, &self.destination, &packet)
            .unwrap();
        if flags & 16 != 0 {
            tag[0] ^= 1;
        }
        packet.extend_from_slice(&tag);
        self.client.receive(self.now, self.server.address, &packet);
    }

    fn initial(&mut self, payload: &[u8]) {
        let connection = &self.client.connection.as_ref().unwrap().1;
        let keys = connection
            .crypto
            .initial_keys(self.version, &connection.initial_dst_cid, Side::Server)
            .unwrap();
        let mut packet = Vec::new();
        let number = connection.spaces[SpaceId::Initial].rx_packet + 1;
        let header = Header::Initial(InitialHeader {
            dst_cid: self.source,
            src_cid: ConnectionId::new(&[0xa5; 20]),
            token: Bytes::new(),
            number: PacketNumber::U32(number as u32),
            version: self.version.to_wire().unwrap(),
        })
        .encode(&mut packet);
        packet.extend_from_slice(&payload[..payload.len().min(8192)]);
        packet.resize((packet.len() + keys.local.packet.tag_len()).max(1200), 0);
        header
            .finish(
                &mut packet,
                &*keys.local.header,
                Some((number, &*keys.local.packet)),
            )
            .unwrap();
        self.client.receive(self.now, self.server.address, &packet);
    }

    fn new_token(&mut self, token: &[u8], flags: u8) {
        let connection = &self.client.connection.as_ref().unwrap().1;
        let Some(keys) = connection.spaces[SpaceId::Data].crypto.as_ref() else {
            return;
        };
        let Some(remote) = &keys.remote else {
            return;
        };
        let Some((_, server)) = &self.server.connection else {
            return;
        };
        let number = connection.spaces[SpaceId::Data].rx_packet + 1;
        let mut packet = Vec::new();
        let header = Header::Short {
            spin: false,
            key_phase: connection.key_phase,
            dst_cid: server.rem_cids.active(),
            number: PacketNumber::U32(number as u32),
        }
        .encode(&mut packet);
        NewToken {
            token: Bytes::copy_from_slice(token),
        }
        .encode(&mut packet);
        packet.resize(
            packet
                .len()
                .max(header.header_len + remote.header.sample_size())
                + remote.packet.tag_len(),
            0,
        );
        header
            .finish(
                &mut packet,
                &*remote.header,
                Some((number, &*remote.packet)),
            )
            .unwrap();
        if flags & 16 != 0 {
            *packet.last_mut().unwrap() ^= 1;
        }
        self.client.receive(self.now, self.server.address, &packet);
    }
}

/// Input: version byte, then at most 16 `(opcode, u16 length, fill byte)` operations.
/// Opcodes cover Retry, Initial, handshake, NEW_TOKEN, close, timeout, reconnect and raw input.
#[cfg_attr(
    not(fuzzing),
    expect(
        unreachable_pub,
        reason = "also compiled for the harness regression tests"
    )
)]
pub fn token_sequence(input: &[u8]) {
    let _coverage = run(input);
}

fn run(input: &[u8]) -> [u64; 4] {
    let mut coverage = [0; 4];
    let Some((&version, input)) = input.split_first() else {
        return coverage;
    };
    let version = if version & 1 == 0 {
        Version::V1
    } else {
        Version::V2
    };
    let tls = TlsClientConfig::new()
        .with_alpn([b"rama-token-fuzz".as_slice().into()].into_iter().collect())
        .try_with_server_trust_anchors([IDENTITY.cert_chain.last().unwrap().clone()])
        .unwrap();
    let mut client_config = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
    client_config
        .set_versions(ClientVersionPolicy::new(version).unwrap())
        .unwrap();
    let tls = TlsServerConfig::new()
        .with_alpn([b"rama-token-fuzz".as_slice().into()].into_iter().collect())
        .with_server_auth(IDENTITY.clone());
    let server_config =
        Arc::new(ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap());
    let mut pair = Pair::new(client_config.clone(), server_config.clone(), version);
    for operation in input.as_chunks::<4>().0.iter().take(16) {
        let flags = operation[0];
        let payload = vec![
            operation[3];
            usize::from(u16::from_le_bytes([operation[1], operation[2]])).min(65_000)
        ];
        let pings_before = pair
            .client
            .connection
            .as_ref()
            .unwrap()
            .1
            .stats()
            .frame_rx
            .ping;
        let tokens_before = pair
            .client
            .connection
            .as_ref()
            .unwrap()
            .1
            .stats()
            .frame_rx
            .new_token;
        let cid_before = pair.client.connection.as_ref().unwrap().1.rem_handshake_cid;
        match flags & 7 {
            0 => pair.retry(flags, &payload),
            1 => pair.initial(&payload),
            2 => pair.drive(),
            3 => pair.new_token(&payload, flags),
            4 => pair.client.connection.as_mut().unwrap().1.close(
                pair.now,
                VarInt::from_u32(0),
                payload.into(),
            ),
            5 => {
                pair.now += Duration::from_secs(1);
                pair.client
                    .connection
                    .as_mut()
                    .unwrap()
                    .1
                    .handle_timeout(pair.now);
            }
            6 => {
                pair = Pair::new(client_config.clone(), server_config.clone(), version);
                if let Some(packet) = pair.client.outgoing.front() {
                    let (packet, _) = PartialDecode::new(
                        packet.as_slice().into(),
                        &FixedLengthConnectionIdParser::new(0),
                        DEFAULT_SUPPORTED_VERSIONS,
                        true,
                    )
                    .unwrap();
                    coverage[2] +=
                        u64::from(!packet.initial_header().unwrap().token_pos.is_empty());
                }
            }
            _ => pair.client.receive(pair.now, pair.server.address, &payload),
        }
        let connection = &pair.client.connection.as_ref().unwrap().1;
        if flags & 7 == 0 && connection.rem_handshake_cid != cid_before {
            coverage[0] += 1;
        }
        if flags & 7 == 1 {
            coverage[3] += connection.stats().frame_rx.ping - pings_before;
        }
        if flags & 7 == 3 {
            coverage[1] += connection.stats().frame_rx.new_token - tokens_before;
        }
        pair.client.transmit(pair.now);
        pair.now += Duration::from_millis(1);
    }
    coverage
}

#[cfg(test)]
mod tests {
    use super::{run, token_sequence};

    #[test]
    fn mixed_sequences_remain_bounded() {
        let mut state = 42u64;
        for _ in 0..256 {
            let mut input = [0u8; 65];
            for byte in &mut input {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (state >> 32) as u8;
            }
            token_sequence(&input);
        }
    }

    #[test]
    fn authenticated_sequences_reach_token_storage_and_initial_construction() {
        for version in [0, 1] {
            assert_eq!(run(&[version, 1, 1, 0, 1])[3], 1);
            let retry = run(&[version, 0, 8, 0, 7]);
            assert_eq!(retry[0], 1);
            for token_len in [1u16, 64, 1119] {
                let [lo, hi] = token_len.to_le_bytes();
                let result = run(&[version, 2, 0, 0, 0, 3, lo, hi, 7, 6, 0, 0, 0]);
                assert_eq!(result[1], 1);
                assert_eq!(result[2], 1);
            }
            for flags in [8, 16] {
                assert_eq!(run(&[version, flags, 8, 0, 7])[0], 0);
            }
            assert_eq!(run(&[version, 2, 0, 0, 0, 19, 8, 0, 7])[1], 0);
        }
    }

    /// A server that greases the QUIC bit and issues a token lets the client's next first flight
    /// grease it as well; the harness reads that flight like any other.
    #[test]
    fn a_greased_first_flight_after_a_stored_token_is_read() {
        token_sequence(&[
            45, 2, 35, 0, 0, 3, 96, 4, 0, 2, 35, 0, 0, 3, 96, 4, 7, 6, 0, 2, 35,
        ]);
    }
}
