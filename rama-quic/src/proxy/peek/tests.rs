use std::{num::NonZeroUsize, time::Duration};

use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    io::BridgeIo,
    service::service_fn,
};
use rama_net::{
    address::{HostWithPort, SocketAddress},
    client::ConnectorTarget,
    stream::Socket as _,
};
use rama_quic_proto::capture::{CaptureLimits, KeyProvider};
use rama_udp::{
    DatagramMetadata, DatagramSenderExt as _, PrefixedDatagramSocket, SendDatagram,
    UdpPacketSocket, proxy::DatagramToProxyBridge, test_utils::MemoryDatagramSocket,
};
use rama_utils::{hex::decode, octets::kib};
use tokio::time::{advance, timeout};

use super::*;

#[cfg(feature = "boring")]
fn keys() -> impl KeyProvider + Clone {
    crate::tls::BoringTlsProvider
}

#[cfg(not(feature = "boring"))]
fn keys() -> impl KeyProvider + Clone {
    crate::tls::RustlsTlsProvider::new(crate::proto::crypto::rustls::configured_provider())
}

/// The two Initial datagrams of one captured Chrome flight; the ClientHello spans both.
fn chrome_initials() -> [Vec<u8>; 2] {
    [
        include_str!("../../profile/fixtures/chrome-153-initial-1.hex"),
        include_str!("../../profile/fixtures/chrome-153-initial-2.hex"),
    ]
    .map(|hex| decode::<Vec<u8>>(hex.split_whitespace().collect::<String>()).unwrap())
}

fn association() -> (MemoryDatagramSocket, MemoryDatagramSocket) {
    MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(24000),
        SocketAddress::local_ipv4(24001),
        NonZeroUsize::new(8).unwrap(),
    )
}

fn deliver(ingress: &MemoryDatagramSocket, client: &MemoryDatagramSocket, bytes: &[u8]) {
    let mut metadata = DatagramMetadata::empty();
    metadata.peer = client.local_addr().unwrap();
    metadata.local = ingress.local_addr().unwrap();
    ingress.inject_received(bytes.to_vec(), metadata).unwrap();
}

async fn drain(socket: &mut PrefixedDatagramSocket<MemoryDatagramSocket>) -> Vec<Vec<u8>> {
    let mut buffer = vec![0; kib(64)];
    let mut received = Vec::new();
    while !socket.retained().is_empty() {
        let metadata = socket.recv(&mut buffer).await.unwrap();
        received.push(buffer[..metadata.len].to_vec());
    }
    received
}

#[tokio::test(start_paused = true)]
async fn a_complete_client_hello_reaches_the_inner_service_with_the_flight_replayed() {
    timeout(Duration::from_secs(20), async {
        let (mut client, ingress) = association();
        let initials = chrome_initials();
        for bytes in &initials {
            deliver(&ingress, &client, bytes);
        }
        let peek = PeekQuicClientHelloService::new(
            keys(),
            service_fn(
                async |InputWithQuicClientHello { mut input, peeked }: InputWithQuicClientHello<
                    PrefixedDatagramSocket<MemoryDatagramSocket>,
                >| {
                    let sni = peeked
                        .client_hello
                        .ext_server_name()
                        .map(|name| name.to_string());
                    Ok::<_, BoxError>((sni, drain(&mut input).await))
                },
            ),
        )
        .with_fallback(service_fn(async |_: PrefixedDatagramSocket<_>| {
            Err::<_, BoxError>(BoxError::from_static_str("unexpected fallback"))
        }));
        let (sni, replayed) = peek.serve(ingress).await.unwrap();
        assert!(sni.is_some());
        assert_eq!(replayed, initials);
        // Peeking never answers the client: the association closes without a datagram.
        let mut buffer = [0; 16];
        assert!(matches!(
            client.recv(&mut buffer).await,
            Err(rama_udp::DatagramError::Closed)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn non_quic_input_goes_to_the_fallback_intact() {
    timeout(Duration::from_secs(20), async {
        let (client, ingress) = association();
        let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00".to_vec();
        deliver(&ingress, &client, &dns_query);
        let peek = PeekQuicClientHelloService::new(
            keys(),
            service_fn(async |_: InputWithQuicClientHello<_>| Ok::<_, BoxError>(Vec::new())),
        )
        .with_fallback(service_fn(
            async |mut input: PrefixedDatagramSocket<MemoryDatagramSocket>| {
                Ok::<_, BoxError>(drain(&mut input).await)
            },
        ));
        assert_eq!(peek.serve(ingress).await.unwrap(), vec![dns_query]);
    })
    .await
    .unwrap();
}

/// The datagrams of a flight ending in `class`, and the limits that end it there.
fn flight_ending_in(class: QuicPeekRejection) -> (Vec<Vec<u8>>, CaptureLimits) {
    let [first, second] = chrome_initials();
    let limits = CaptureLimits::default();
    match class {
        QuicPeekRejection::NotQuic => (
            vec![b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00".to_vec()],
            limits,
        ),
        QuicPeekRejection::UnsupportedVersion => {
            let mut unknown = first;
            unknown[1..5].copy_from_slice(&0x1a2a_3a4a_u32.to_be_bytes());
            (vec![unknown], limits)
        }
        QuicPeekRejection::Malformed => {
            let mut forged = first;
            *forged.last_mut().unwrap() ^= 1;
            (vec![forged], limits)
        }
        QuicPeekRejection::Budget => (
            vec![first, second],
            CaptureLimits {
                datagrams: 1,
                ..limits
            },
        ),
        QuicPeekRejection::Deadline => (vec![first], limits),
    }
}

#[tokio::test(start_paused = true)]
async fn each_rejection_reaches_the_fallback_only_when_its_class_is_admitted() {
    timeout(Duration::from_secs(20), async {
        let classes = [
            QuicPeekRejection::NotQuic,
            QuicPeekRejection::UnsupportedVersion,
            QuicPeekRejection::Malformed,
            QuicPeekRejection::Budget,
            QuicPeekRejection::Deadline,
        ];
        let only = |class| QuicPeekFallbackPolicy {
            not_quic: class == QuicPeekRejection::NotQuic,
            unsupported_version: class == QuicPeekRejection::UnsupportedVersion,
            malformed: class == QuicPeekRejection::Malformed,
            budget: class == QuicPeekRejection::Budget,
            deadline: class == QuicPeekRejection::Deadline,
        };
        for class in classes {
            for (policy, admitted) in [
                (QuicPeekFallbackPolicy::default(), true),
                (
                    QuicPeekFallbackPolicy::NOT_QUIC,
                    class == QuicPeekRejection::NotQuic,
                ),
                (only(class), true),
            ] {
                let (client, ingress) = association();
                let (flight, limits) = flight_ending_in(class);
                for bytes in &flight {
                    deliver(&ingress, &client, bytes);
                }
                let peek = PeekQuicClientHelloService::new(
                    keys(),
                    service_fn(async |_: InputWithQuicClientHello<_>| {
                        Err::<_, BoxError>(BoxError::from_static_str("unexpected ClientHello"))
                    }),
                )
                .with_limits(limits)
                .with_peek_timeout(Duration::from_millis(100))
                .with_fallback_policy(policy)
                .with_fallback(service_fn(
                    async |mut input: PrefixedDatagramSocket<MemoryDatagramSocket>| {
                        let reason = input.extensions().get_ref::<QuicPeekRejection>().copied();
                        let failure = input
                            .extensions()
                            .get_ref::<ClientHelloPeekStatus>()
                            .unwrap()
                            .failure;
                        Ok::<_, BoxError>((reason, failure, drain(&mut input).await))
                    },
                ));
                let result = peek.serve(ingress).await;
                if admitted {
                    let expected = match class {
                        QuicPeekRejection::NotQuic => None,
                        QuicPeekRejection::UnsupportedVersion | QuicPeekRejection::Malformed => {
                            Some(PeekStopReason::Rejected)
                        }
                        QuicPeekRejection::Budget => Some(PeekStopReason::MaxPeekSizeReached),
                        QuicPeekRejection::Deadline => Some(PeekStopReason::Timeout),
                    };
                    assert_eq!(result.unwrap(), (Some(class), expected, flight), "{class}");
                } else {
                    let error = result.unwrap_err();
                    assert_eq!(
                        error.downcast_ref::<QuicPeekRejectedError>(),
                        Some(&QuicPeekRejectedError(class)),
                        "{class}: {error}"
                    );
                }
                drop(client);
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_default_fallback_rejects() {
    timeout(Duration::from_secs(20), async {
        let (client, ingress) = association();
        deliver(&ingress, &client, b"not quic");
        let peek = PeekQuicClientHelloService::new(
            keys(),
            service_fn(async |_: InputWithQuicClientHello<_>| Ok::<_, BoxError>(())),
        );
        let error = peek.serve(ingress).await.unwrap_err();
        assert!(
            error.to_string().contains("no complete QUIC ClientHello"),
            "{error}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_deadline_is_fixed_when_the_association_is_handed_over() {
    timeout(Duration::from_secs(20), async {
        let (client, ingress) = association();
        let ingress_address = ingress.local_addr().unwrap();
        let [first, second] = chrome_initials();
        deliver(&ingress, &client, &first);
        let peek = PeekQuicClientHelloService::new(
            keys(),
            service_fn(async |_: InputWithQuicClientHello<_>| Ok::<_, BoxError>(())),
        )
        .with_peek_timeout(Duration::from_millis(100))
        .with_peek_policy(PeekPolicy::FAIL_CLOSED);
        let serving = peek.serve(ingress);
        // A late first poll, and the rest of the flight after the deadline, find it expired.
        advance(Duration::from_millis(150)).await;
        client
            .create_sender()
            .send(SendDatagram::new(ingress_address, &second))
            .await
            .unwrap();
        let error = serving.await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<QuicPeekRejectedError>(),
            Some(&QuicPeekRejectedError(QuicPeekRejection::Deadline))
        );
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_bridge_peeks_ingress_and_keeps_the_prepared_egress() {
    timeout(Duration::from_secs(20), async {
        let (client, ingress) = association();
        let (egress, _origin) = association();
        let egress_local = egress.local_addr().unwrap();
        for bytes in &chrome_initials() {
            deliver(&ingress, &client, bytes);
        }
        let peek = PeekQuicClientHelloService::new(
            keys(),
            service_fn(
                async |InputWithQuicClientHello {
                           input: BridgeIo(_ingress, egress),
                           ..
                       }: InputWithQuicClientHello<
                    BridgeIo<PrefixedDatagramSocket<MemoryDatagramSocket>, MemoryDatagramSocket>,
                >| { Ok::<_, BoxError>(egress.local_addr().unwrap()) },
            ),
        )
        .with_fallback(service_fn(
            async |_: BridgeIo<PrefixedDatagramSocket<_>, _>| {
                Err::<_, BoxError>(BoxError::from_static_str("unexpected fallback"))
            },
        ));
        assert_eq!(
            peek.serve(BridgeIo(ingress, egress)).await.unwrap(),
            egress_local
        );
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_cut_datagram_ends_the_peek_and_is_replayed_as_received() {
    timeout(Duration::from_secs(20), async {
        let (client, ingress) = association();
        let [first, second] = chrome_initials();
        let mut metadata = DatagramMetadata::empty();
        metadata.peer = client.local_addr().unwrap();
        metadata.local = ingress.local_addr().unwrap();
        metadata.truncated = true;
        metadata.original_len = first.len() + 100;
        ingress.inject_received(first.clone(), metadata).unwrap();
        // Whatever follows, a flight with a cut datagram is never inspected to completion.
        deliver(&ingress, &client, &second);
        let peek = PeekQuicClientHelloService::new(
            keys(),
            service_fn(async |_: InputWithQuicClientHello<_>| Ok::<_, BoxError>(None)),
        )
        .with_fallback_policy(QuicPeekFallbackPolicy {
            malformed: true,
            ..QuicPeekFallbackPolicy::NOT_QUIC
        })
        .with_fallback(service_fn(
            async |mut input: PrefixedDatagramSocket<MemoryDatagramSocket>| {
                let mut buffer = vec![0; kib(64)];
                let metadata = input.recv(&mut buffer).await.unwrap();
                Ok::<_, BoxError>(Some((buffer[..metadata.len].to_vec(), metadata.truncated)))
            },
        ));
        assert_eq!(peek.serve(ingress).await.unwrap(), Some((first, true)));
        drop(client);
    })
    .await
    .unwrap();
}

fn deliver_gro(
    ingress: &MemoryDatagramSocket,
    client: &MemoryDatagramSocket,
    bytes: Vec<u8>,
    segment_size: usize,
) {
    let mut metadata = DatagramMetadata::empty();
    metadata.peer = client.local_addr().unwrap();
    metadata.local = ingress.local_addr().unwrap();
    metadata.segment_size = NonZeroUsize::new(segment_size);
    ingress.inject_received(bytes, metadata).unwrap();
}

/// What a fallback or inner service is replayed: each receive with its segment size.
async fn replayed(
    socket: &mut PrefixedDatagramSocket<MemoryDatagramSocket>,
) -> Vec<(Vec<u8>, Option<NonZeroUsize>)> {
    let mut buffer = vec![0; kib(64)];
    let mut received = Vec::new();
    while !socket.retained().is_empty() {
        let metadata = socket.recv(&mut buffer).await.unwrap();
        received.push((buffer[..metadata.len].to_vec(), metadata.segment_size));
    }
    received
}

#[tokio::test(start_paused = true)]
async fn a_gro_receive_is_inspected_and_charged_per_segment() {
    timeout(Duration::from_secs(20), async {
        let [first, second] = chrome_initials();
        // Equal segments, and a first segment padded past its packets, the last one shorter.
        let padded = first.len() + 70;
        let mut padded_flight = first.clone();
        padded_flight.resize(padded, 0);
        padded_flight.extend_from_slice(&second);
        let cases = [
            ([first.as_slice(), &second].concat(), first.len(), 2),
            (padded_flight, padded, 2),
        ];
        for (flight, segment_size, segments) in cases {
            for datagrams in [segments, segments - 1] {
                let (client, ingress) = association();
                deliver_gro(&ingress, &client, flight.clone(), segment_size);
                let peek = PeekQuicClientHelloService::new(
                    keys(),
                    service_fn(
                        async |InputWithQuicClientHello { mut input, .. }: InputWithQuicClientHello<
                            PrefixedDatagramSocket<MemoryDatagramSocket>,
                        >| { Ok::<_, BoxError>((true, replayed(&mut input).await)) },
                    ),
                )
                .with_limits(CaptureLimits {
                    datagrams,
                    ..CaptureLimits::default()
                })
                .with_fallback_policy(QuicPeekFallbackPolicy::ALL)
                .with_fallback(service_fn(
                    async |mut input: PrefixedDatagramSocket<MemoryDatagramSocket>| {
                        assert_eq!(
                            input.extensions().get_ref::<QuicPeekRejection>(),
                            Some(&QuicPeekRejection::Budget)
                        );
                        Ok::<_, BoxError>((false, replayed(&mut input).await))
                    },
                ));
                let (found, replay) = peek.serve(ingress).await.unwrap();
                assert_eq!(found, datagrams == segments, "{datagrams} datagram budget");
                assert_eq!(
                    replay,
                    vec![(flight.clone(), NonZeroUsize::new(segment_size))]
                );
                drop(client);
            }
        }
    })
    .await
    .unwrap();
}

/// Peeking first and bridging after, a transparent proxy creates an egress only for what it
/// routes on, to the association's original destination, with the peeked ClientHello in hand.
#[tokio::test(start_paused = true)]
async fn a_peeked_association_is_bridged_with_its_client_hello() {
    timeout(Duration::from_secs(20), async {
        let (client, ingress) = association();
        let destination = ingress.local_addr().unwrap();
        ingress
            .extensions()
            .insert(ConnectorTarget(HostWithPort::from(destination)));
        let initials = chrome_initials();
        for bytes in &initials {
            deliver(&ingress, &client, bytes);
        }
        let peek = PeekQuicClientHelloService::new(
            keys(),
            DatagramToProxyBridge::extension_connector_target(service_fn(
                async |InputWithQuicClientHello {
                           input: BridgeIo(mut ingress, egress),
                           peeked,
                       }: InputWithQuicClientHello<
                    BridgeIo<PrefixedDatagramSocket<MemoryDatagramSocket>, UdpPacketSocket>,
                >| {
                    Ok::<_, BoxError>((
                        peeked.client_hello.ext_server_name().is_some(),
                        egress.peer_addr().unwrap(),
                        drain(&mut ingress).await,
                    ))
                },
            )),
        )
        .with_fallback(service_fn(async |_: PrefixedDatagramSocket<_>| {
            Err::<_, BoxError>(BoxError::from_static_str("unexpected fallback"))
        }));
        let (named, egress_peer, replayed) = peek.serve(ingress).await.unwrap();
        assert!(named);
        assert_eq!(egress_peer, destination);
        assert_eq!(replayed, initials);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn shared_policies_control_quic_failures_and_timeouts_independently() {
    for malformed in [MalformedTlsPolicy::Fallback, MalformedTlsPolicy::Reject] {
        for timeout_policy in [PeekPolicy::FAIL_OPEN, PeekPolicy::FAIL_CLOSED] {
            for class in [
                QuicPeekRejection::NotQuic,
                QuicPeekRejection::UnsupportedVersion,
                QuicPeekRejection::Malformed,
                QuicPeekRejection::Budget,
                QuicPeekRejection::Deadline,
            ] {
                let (client, ingress) = association();
                let (flight, limits) = flight_ending_in(class);
                for packet in &flight {
                    deliver(&ingress, &client, packet);
                }
                let service = PeekQuicClientHelloService::new(
                    keys(),
                    service_fn(async |_: InputWithQuicClientHello<_>| {
                        Err::<Vec<Vec<u8>>, _>(BoxError::from_static_str(
                            "unexpected complete hello",
                        ))
                    }),
                )
                .with_limits(limits)
                .with_peek_timeout(Duration::from_millis(100))
                .with_malformed_tls_policy(malformed)
                .with_peek_policy(timeout_policy)
                .with_fallback(service_fn(
                    async |mut input: PrefixedDatagramSocket<MemoryDatagramSocket>| {
                        Ok::<_, BoxError>(drain(&mut input).await)
                    },
                ));
                // Both adapters and the explicit policy survive fallback replacement and cloning.
                let extensions = ingress.extensions().clone();
                let result = service.clone().serve(ingress).await;
                let allowed = match class {
                    QuicPeekRejection::NotQuic => true,
                    QuicPeekRejection::Deadline => timeout_policy == PeekPolicy::FAIL_OPEN,
                    _ => malformed == MalformedTlsPolicy::Fallback,
                };
                if allowed {
                    assert_eq!(result.unwrap(), flight);
                    assert!(extensions.get_ref::<ClientHelloPeekStatus>().is_some());
                } else {
                    assert!(extensions.get_ref::<ClientHelloPeekStatus>().is_none());
                    assert_eq!(
                        result.unwrap_err().downcast_ref::<QuicPeekRejectedError>(),
                        Some(&QuicPeekRejectedError(class))
                    );
                }
                drop(client);
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn shared_status_shadows_stale_failure_on_quic_and_non_quic_bridges() {
    for flight in [chrome_initials().to_vec(), vec![b"not quic".to_vec()]] {
        let (client, ingress) = association();
        let (egress, _peer) = association();
        let address = egress.local_addr().unwrap();
        ingress.extensions().insert(ClientHelloPeekStatus {
            failure: Some(PeekStopReason::Timeout),
        });
        let extensions = ingress.extensions().clone();
        for packet in &flight {
            deliver(&ingress, &client, packet);
        }
        type Input = BridgeIo<PrefixedDatagramSocket<MemoryDatagramSocket>, MemoryDatagramSocket>;
        let service = PeekQuicClientHelloService::new(
            keys(),
            service_fn(async |input: InputWithQuicClientHello<Input>| {
                assert!(
                    input
                        .extensions()
                        .get_ref::<ClientHelloPeekStatus>()
                        .unwrap()
                        .failure
                        .is_none()
                );
                Ok::<_, BoxError>(input.input.1.local_addr().unwrap())
            }),
        )
        .with_fallback(service_fn(async |input: Input| {
            assert!(
                input
                    .extensions()
                    .get_ref::<ClientHelloPeekStatus>()
                    .unwrap()
                    .failure
                    .is_none()
            );
            Ok::<_, BoxError>(input.1.local_addr().unwrap())
        }));
        assert_eq!(
            service.serve(BridgeIo(ingress, egress)).await.unwrap(),
            address
        );
        assert!(
            extensions
                .get_ref::<ClientHelloPeekStatus>()
                .unwrap()
                .failure
                .is_none()
        );
    }
}

/// Encrypt a large hello across Initial packets to exercise the real CRYPTO assembler.
fn large_initial_flight() -> Vec<Vec<u8>> {
    use rama_quic_proto::{
        ConnectionId, Side, Version,
        coding::BufMutExt as _,
        packet::{Header, InitialHeader, PacketNumber},
    };
    let mut body = vec![3, 3]; // TLS legacy_version 0x0303.
    body.extend_from_slice(&[0; 32]); // Random.
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]); // No session ID, TLS_AES_128_GCM_SHA256, null compression.
    let padding = kib(60);
    body.extend_from_slice(&u16::try_from(padding + 18).unwrap().to_be_bytes());
    body.extend_from_slice(&[0, 21]); // TLS padding extension.
    body.extend_from_slice(&u16::try_from(padding).unwrap().to_be_bytes());
    body.resize(body.len() + padding, 0);
    // QUIC transport parameters extension (57), with initial_source_connection_id
    // (parameter 15) matching the packet header's eight-byte source CID.
    body.extend_from_slice(&[0, 57, 0, 10, 15, 8]);
    body.extend_from_slice(&[8; 8]);
    let mut hello = vec![1]; // TLS HandshakeType client_hello.
    hello.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    let cid = ConnectionId::try_from_bytes(&[7; 8]).unwrap();
    let scid = ConnectionId::try_from_bytes(&[8; 8]).unwrap();
    let provider = keys();
    let protection = provider
        .initial_keys(Version::V1, &cid, Side::Server)
        .unwrap();
    hello
        .chunks(1000)
        .enumerate()
        .map(|(index, fragment)| {
            let mut packet = Vec::new();
            let header = Header::Initial(InitialHeader {
                dst_cid: cid,
                src_cid: scid,
                token: Bytes::new(),
                number: PacketNumber::new_at_least(index as u64, 0, 2).unwrap(),
                version: Version::V1.to_wire().unwrap(),
            })
            .encode_with_max_packet_len(&mut packet, 1252);
            packet.push(6); // QUIC CRYPTO frame type.
            packet.write_var((index * 1000) as u64);
            packet.write_var(fragment.len() as u64);
            packet.extend_from_slice(fragment);
            packet.resize(1252, 0); // PADDING and space for the authentication tag.
            header
                .finish(
                    &mut packet,
                    &protection.header,
                    Some((index as u64, &protection.packet)),
                )
                .unwrap();
            packet
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn relaxed_limits_inspect_large_reordered_flights_and_configured_caps_fall_back() {
    let mut flight = large_initial_flight();
    assert!(flight.len() > CaptureLimits::default().datagrams);
    flight.reverse();
    flight.insert(1, flight[0].clone()); // A retransmission must agree and still count toward budgets.
    for relaxed in [true, false] {
        let (client, ingress) = MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(24000),
            SocketAddress::local_ipv4(24001),
            NonZeroUsize::new(128).unwrap(),
        );
        for packet in &flight {
            deliver(&ingress, &client, packet);
        }
        let packet_count = flight.len();
        let service = PeekQuicClientHelloService::new(
            keys(),
            service_fn(
                async |InputWithQuicClientHello { mut input, peeked }: InputWithQuicClientHello<
                    PrefixedDatagramSocket<MemoryDatagramSocket>,
                >| {
                    assert!(
                        input
                            .extensions()
                            .get_ref::<ClientHelloPeekStatus>()
                            .unwrap()
                            .failure
                            .is_none()
                    );
                    assert!(peeked.first_flight.is_some());
                    Ok::<_, BoxError>((true, drain(&mut input).await))
                },
            ),
        )
        .with_fallback(service_fn(
            move |mut input: PrefixedDatagramSocket<MemoryDatagramSocket>| async move {
                assert_eq!(
                    input
                        .extensions()
                        .get_ref::<ClientHelloPeekStatus>()
                        .unwrap()
                        .failure,
                    Some(PeekStopReason::MaxPeekSizeReached)
                );
                // Include unread datagrams too: inspection stops, forwarding does not lose data.
                let mut packets = drain(&mut input).await;
                let mut buffer = vec![0; kib(64)];
                while packets.len() < packet_count {
                    let metadata = input.recv(&mut buffer).await.unwrap();
                    packets.push(buffer[..metadata.len].to_vec());
                }
                Ok::<_, BoxError>((false, packets))
            },
        ));
        let service = if relaxed {
            service
        } else {
            service.with_limits(CaptureLimits::default())
        };
        let (inspected, replay) = service.serve(ingress).await.unwrap();
        assert_eq!(inspected, relaxed);
        assert_eq!(replay, flight);
    }
}
