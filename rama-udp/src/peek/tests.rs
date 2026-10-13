use std::num::NonZeroUsize;

use rama_core::{bytes::Bytes, io::BridgeIo};
use rama_net::address::SocketAddress;

use super::*;
use crate::{
    DatagramSenderExt as _, DatagramSocketExt as _, SendDatagram, test_utils::MemoryDatagramSocket,
};

fn address(port: u16) -> SocketAddress {
    SocketAddress::local_ipv4(port)
}

fn pair() -> (MemoryDatagramSocket, MemoryDatagramSocket) {
    MemoryDatagramSocket::pair(address(1), address(2), NonZeroUsize::new(8).unwrap())
}

fn retained(payload: &'static [u8], segment_size: Option<usize>) -> RetainedDatagram {
    let mut metadata = DatagramMetadata::empty();
    metadata.len = payload.len();
    metadata.original_len = payload.len();
    metadata.peer = address(2);
    metadata.local = address(1);
    metadata.segment_size = segment_size.and_then(NonZeroUsize::new);
    RetainedDatagram {
        payload: Bytes::from_static(payload),
        metadata,
    }
}

#[tokio::test]
async fn retained_datagrams_replay_in_order_before_later_input() {
    let (socket, mut peer) = pair();
    let prefix = [
        retained(b"first", None),
        retained(b"", None),
        retained(b"aabbc", Some(2)),
    ];
    let mut socket = PrefixedDatagramSocket::new(socket, prefix.clone());
    peer.create_sender()
        .send(SendDatagram::new(address(1), b"later"))
        .await
        .unwrap();

    let mut buffer = [0; 64];
    for expected in &prefix {
        let metadata = socket.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], expected.payload.as_ref());
        assert_eq!(metadata, expected.metadata);
    }
    let metadata = socket.recv(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..metadata.len], b"later");
    assert!(socket.retained().is_empty());
    let _keep_peer_open = &mut peer;
}

#[tokio::test]
async fn a_retained_datagram_larger_than_the_buffer_stays_queued() {
    let (socket, _peer) = pair();
    let mut socket = PrefixedDatagramSocket::new(socket, [retained(b"twelve bytes", None)]);
    let mut small = [0; 4];
    let error = socket.recv(&mut small).await.unwrap_err();
    assert!(
        matches!(error, DatagramError::PayloadTooLarge { len: 12, max: 4 }),
        "{error:?}"
    );
    assert_eq!(socket.retained().len(), 1);
    let mut large = [0; 12];
    let metadata = socket.recv(&mut large).await.unwrap();
    assert_eq!(&large[..metadata.len], b"twelve bytes");
}

#[tokio::test]
async fn bridge_peeks_ingress_and_keeps_egress() {
    let (ingress, _ingress_peer) = pair();
    let (egress, _egress_peer) = pair();
    let egress_local = egress.local_addr().unwrap();
    let mut bridge = BridgeIo(ingress, egress);
    assert_eq!(bridge.peek_socket_mut().local_addr().unwrap(), address(1));
    let BridgeIo(mut ingress, egress) = bridge
        .map_peek_socket(|socket| PrefixedDatagramSocket::new(socket, [retained(b"x", None)]));
    assert_eq!(egress.local_addr().unwrap(), egress_local);
    let mut buffer = [0; 4];
    let metadata = ingress.recv(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..metadata.len], b"x");
}
