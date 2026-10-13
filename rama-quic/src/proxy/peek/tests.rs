use std::{num::NonZeroUsize, time::Duration};

use rama_core::{Service, error::BoxError, io::BridgeIo, service::service_fn};
use rama_net::{address::SocketAddress, stream::Socket as _};
use rama_quic_proto::capture::KeyProvider;
use rama_udp::{
    DatagramMetadata, DatagramSenderExt as _, DatagramSocket as _, PrefixedDatagramSocket,
    SendDatagram, test_utils::MemoryDatagramSocket,
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
                async |InputWithQuicClientHello {
                           mut input,
                           client_hello,
                       }: InputWithQuicClientHello<
                    PrefixedDatagramSocket<MemoryDatagramSocket>,
                >| {
                    let sni = client_hello
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

#[tokio::test(start_paused = true)]
async fn an_incomplete_flight_at_the_deadline_falls_back_or_fails_by_policy() {
    timeout(Duration::from_secs(20), async {
        for policy in [PeekTimeoutPolicy::FailOpen, PeekTimeoutPolicy::FailClosed] {
            let (client, ingress) = association();
            let [first, _second] = chrome_initials();
            deliver(&ingress, &client, &first);
            let peek = PeekQuicClientHelloService::new(
                keys(),
                service_fn(async |_: InputWithQuicClientHello<_>| Ok::<_, BoxError>(None)),
            )
            .with_peek_timeout(Duration::from_millis(100))
            .with_peek_timeout_policy(policy)
            .with_fallback(service_fn(
                async |mut input: PrefixedDatagramSocket<MemoryDatagramSocket>| {
                    Ok::<_, BoxError>(Some(drain(&mut input).await))
                },
            ));
            let result = peek.serve(ingress).await;
            match policy {
                PeekTimeoutPolicy::FailOpen => {
                    assert_eq!(result.unwrap(), Some(vec![first]));
                }
                PeekTimeoutPolicy::FailClosed => {
                    result.unwrap_err();
                }
            }
            drop(client);
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
            service_fn(async |_: InputWithQuicClientHello<_>| Ok::<_, BoxError>(true)),
        )
        .with_peek_timeout(Duration::from_millis(100))
        .with_fallback(service_fn(async |_: PrefixedDatagramSocket<_>| {
            Ok::<_, BoxError>(false)
        }));
        let serving = peek.serve(ingress);
        // A late first poll, and the rest of the flight after the deadline, find it expired.
        advance(Duration::from_millis(150)).await;
        client
            .create_sender()
            .send(SendDatagram::new(ingress_address, &second))
            .await
            .unwrap();
        assert!(!serving.await.unwrap());
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
