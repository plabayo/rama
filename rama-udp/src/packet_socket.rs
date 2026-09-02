//! Tokio-backed implementation of the protocol-neutral datagram traits.

use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::{SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use tokio::io::Interest;

use rama_net::{
    address::{SocketAddress, ip::IntoCanonicalIpAddr as _},
    stream::Socket,
};

use crate::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    ReceiveTimestamp, SendDatagram, UdpSocket, meta::MAX_UDP_PAYLOAD_IPV4,
    meta::MAX_UDP_PAYLOAD_IPV6, sys,
};

/// Packet-oriented Tokio UDP socket with portable ancillary metadata.
#[derive(Debug)]
pub struct UdpPacketSocket {
    io: Arc<UdpSocket>,
    state: Arc<sys::UdpSocketState>,
    socket_is_ipv6: bool,
}

impl UdpPacketSocket {
    /// Bind a packet-oriented socket using default socket options.
    pub async fn bind(
        address: impl TryInto<SocketAddress, Error: Into<rama_core::error::BoxError>>,
    ) -> Result<Self, DatagramError> {
        crate::UdpSocketFactory::default().bind(address).await
    }

    /// Wrap an existing Tokio UDP socket and enable best-effort packet metadata.
    pub fn from_socket(socket: UdpSocket) -> Result<Self, DatagramError> {
        let socket_is_ipv6 = socket.local_addr()?.is_ipv6();
        let state = sys::UdpSocketState::new((&socket).into(), false)?;
        Ok(Self {
            io: Arc::new(socket),
            state: Arc::new(state),
            socket_is_ipv6,
        })
    }

    pub(crate) fn from_std(
        socket: std::net::UdpSocket,
        receive_original_destination: bool,
    ) -> Result<Self, DatagramError> {
        socket.set_nonblocking(true)?;
        let socket_is_ipv6 = socket.local_addr()?.is_ipv6();
        let state = sys::UdpSocketState::new((&socket).into(), receive_original_destination)?;
        let io = UdpSocket::from_std(socket)?;
        Ok(Self {
            io: Arc::new(io),
            state: Arc::new(state),
            socket_is_ipv6,
        })
    }

    fn current_capabilities(&self) -> DatagramCapabilities {
        capabilities(&self.state)
    }
}

impl DatagramSocket for UdpPacketSocket {
    type Sender = UdpPacketSender;

    fn create_sender(&self) -> Self::Sender {
        UdpPacketSender {
            io: self.io.clone(),
            state: self.state.clone(),
            socket_is_ipv6: self.socket_is_ipv6,
            writable: None,
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        if buffers.len() != metadata.len() {
            return Poll::Ready(Err(DatagramError::ReceiveSlotMismatch {
                buffers: buffers.len(),
                metadata: metadata.len(),
            }));
        }
        if buffers.is_empty() {
            return Poll::Ready(Err(DatagramError::EmptyReceiveBatch));
        }

        let count = buffers.len().min(sys::BATCH_SIZE);
        let mut raw_metadata = [sys::RecvMeta::default(); sys::BATCH_SIZE];
        loop {
            if let Err(error) = ready!(self.io.poll_recv_ready(cx)) {
                return Poll::Ready(Err(error.into()));
            }

            let result = self.io.try_io(Interest::READABLE, || {
                let socket = (&*self.io).into();
                self.state
                    .recv(&socket, &mut buffers[..count], &mut raw_metadata[..count])
            });
            match result {
                Ok(received) => {
                    let bound = match self.io.local_addr() {
                        Ok(address) => address,
                        Err(error) => return Poll::Ready(Err(error.into())),
                    };
                    for index in 0..received {
                        let raw = raw_metadata[index];
                        let local = SocketAddr::new(raw.dst_ip.unwrap_or(bound.ip()), bound.port())
                            .into_canonical_ip_addr()
                            .into();
                        let segment_size = receive_segment_size(raw);
                        metadata[index] = DatagramMetadata {
                            len: raw.len,
                            original_len: raw.original_len,
                            segment_size,
                            peer: raw.addr.into_canonical_ip_addr().into(),
                            local,
                            original_destination: raw
                                .original_destination
                                .map(|address| address.into_canonical_ip_addr().into()),
                            interface_index: raw.interface_index,
                            ecn: raw.ecn,
                            timestamp: raw.timestamp.map(ReceiveTimestamp::UnixEpoch),
                            truncated: raw.truncated,
                        };
                    }
                    return Poll::Ready(Ok(received));
                }
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Poll::Ready(Err(error.into())),
            }
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        self.current_capabilities()
    }
}

impl Socket for UdpPacketSocket {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.io
            .local_addr()
            .map(|address| address.into_canonical_ip_addr().into())
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        self.io
            .peer_addr()
            .map(|address| address.into_canonical_ip_addr().into())
    }
}

type WritableFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;

/// Send handle for a [`UdpPacketSocket`].
pub struct UdpPacketSender {
    io: Arc<UdpSocket>,
    state: Arc<sys::UdpSocketState>,
    socket_is_ipv6: bool,
    writable: Option<WritableFuture>,
}

impl std::fmt::Debug for UdpPacketSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpPacketSender")
            .finish_non_exhaustive()
    }
}

impl DatagramSender for UdpPacketSender {
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        let capabilities = capabilities(&self.state);
        if let Err(error) = datagram.validate(capabilities) {
            return Poll::Ready(Err(error));
        }
        let destination = sys_destination(datagram.destination(), self.socket_is_ipv6);
        let transmit = sys::Transmit {
            destination,
            ecn: datagram.ecn(),
            contents: datagram.payload(),
            segment_size: datagram.segment_size().map(NonZeroUsize::get),
            src_ip: datagram.source_ip(),
        };

        loop {
            if self.writable.is_none() {
                let io = self.io.clone();
                self.writable = Some(Box::pin(async move { io.writable().await }));
            }
            let Some(writable) = self.writable.as_mut() else {
                return Poll::Ready(Err(io::Error::other(
                    "failed to construct UDP write-readiness future",
                )
                .into()));
            };
            let readiness = ready!(writable.as_mut().poll(cx));
            self.writable = None;
            if let Err(error) = readiness {
                return Poll::Ready(Err(error.into()));
            }

            // `try_io` must observe `WouldBlock` from the syscall so Tokio can
            // clear its cached WRITABLE readiness before we wait again.
            let result = self.io.try_io(Interest::WRITABLE, || {
                let socket = (&*self.io).into();
                self.state.try_send(&socket, &transmit)
            });
            match result {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Poll::Ready(Err(error.into())),
            }
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        capabilities(&self.state)
    }
}

fn sys_destination(destination: SocketAddress, socket_is_ipv6: bool) -> SocketAddr {
    let destination = SocketAddr::from(destination);
    match (destination, socket_is_ipv6) {
        (SocketAddr::V4(destination), true) => SocketAddr::V6(SocketAddrV6::new(
            destination.ip().to_ipv6_mapped(),
            destination.port(),
            0,
            0,
        )),
        (destination, _) => destination,
    }
}

fn receive_segment_size(metadata: sys::RecvMeta) -> Option<NonZeroUsize> {
    (metadata.stride < metadata.original_len)
        .then(|| NonZeroUsize::new(metadata.stride))
        .flatten()
}

fn is_would_block(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

fn capabilities(state: &sys::UdpSocketState) -> DatagramCapabilities {
    let sys = state.capabilities();
    let max_gso_segments = state.max_gso_segments();
    let max_gro_segments = state.gro_segments();
    DatagramCapabilities {
        max_payload_ipv4: MAX_UDP_PAYLOAD_IPV4,
        max_payload_ipv6: MAX_UDP_PAYLOAD_IPV6,
        max_receive_batch: sys::BATCH_SIZE,
        max_send_batch: 1,
        max_send_segments: max_gso_segments,
        max_receive_segments: max_gro_segments,
        may_fragment: state.may_fragment(),
        send_ecn: sys.send_ecn,
        receive_ecn: sys.receive_ecn,
        send_source_ip: sys.send_source_ip,
        receive_local_ip: sys.receive_local_ip,
        receive_interface: sys.receive_interface,
        receive_original_destination: sys.receive_original_destination,
        receive_timestamp: sys.receive_timestamp,
        receive_truncation: sys.receive_truncation,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::IoSliceMut,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use super::*;
    use crate::{DatagramSenderExt as _, DatagramSocketExt as _, EcnCodepoint};
    use rama_net::socket::SocketOptions;

    async fn bind_pair(ipv6: bool) -> (UdpPacketSocket, UdpPacketSocket) {
        let address: SocketAddr = if ipv6 {
            "[::1]:0".parse().unwrap()
        } else {
            "127.0.0.1:0".parse().unwrap()
        };
        let receiver = UdpPacketSocket::bind(address).await.unwrap();
        let sender = UdpPacketSocket::bind(address).await.unwrap();
        (receiver, sender)
    }

    async fn loopback_batch(ipv6: bool) {
        let (mut receiver, sender_socket) = bind_pair(ipv6).await;
        let destination = receiver.local_addr().unwrap();
        let mut sender = sender_socket.create_sender();
        let packets = [
            SendDatagram::new(destination, b"first"),
            SendDatagram::new(destination, b"second"),
        ];
        assert_eq!(sender.send_batch(&packets).await.unwrap(), 2);

        let mut first = [0; 8];
        let mut second = [0; 8];
        let mut buffers = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let mut metadata = [DatagramMetadata::empty(); 2];
        let received = receiver
            .recv_batch(&mut buffers, &mut metadata)
            .await
            .unwrap();
        assert!((1..=receiver.capabilities().max_receive_batch.min(2)).contains(&received));
        assert_eq!(&first[..metadata[0].len], b"first");
        if received == 2 {
            assert_eq!(&second[..metadata[1].len], b"second");
        } else {
            let metadata = receiver.recv(&mut second).await.unwrap();
            assert_eq!(&second[..metadata.len], b"second");
        }
    }

    #[tokio::test]
    async fn ipv4_single_and_batch_loopback() {
        loopback_batch(false).await;
    }

    #[tokio::test]
    async fn ipv6_single_and_batch_loopback() {
        loopback_batch(true).await;
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn exposes_detected_socket_capabilities_to_senders() {
        let (socket, _peer) = bind_pair(false).await;
        let capabilities = socket.capabilities();
        assert!(capabilities.receive_truncation);
        assert_eq!(socket.create_sender().capabilities(), capabilities);
    }

    #[test]
    fn retries_only_would_block_errors() {
        assert!(is_would_block(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(!is_would_block(&io::Error::from(io::ErrorKind::BrokenPipe)));
    }

    #[tokio::test]
    async fn zero_length_truncation_and_following_packet() {
        let (mut receiver, sender_socket) = bind_pair(false).await;
        let destination = receiver.local_addr().unwrap();
        let mut sender = sender_socket.create_sender();
        sender
            .send(SendDatagram::new(destination, b""))
            .await
            .unwrap();
        sender
            .send(SendDatagram::new(destination, b"oversize"))
            .await
            .unwrap();
        sender
            .send(SendDatagram::new(destination, b"ok"))
            .await
            .unwrap();

        let mut buffer = [0; 16];
        let zero = receiver.recv(&mut buffer).await.unwrap();
        assert_eq!(zero.len, 0);
        assert_eq!(zero.segment_size, None);
        assert!(!zero.truncated);

        let mut small = [0; 2];
        let truncated = receiver.recv(&mut small).await.unwrap();
        assert_eq!(&small, b"ov");
        assert!(truncated.truncated);
        assert_eq!(truncated.segment_size, None);
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert_eq!(truncated.original_len, 8);
        }

        let following = receiver.recv(&mut small).await.unwrap();
        assert_eq!(&small[..following.len], b"ok");
        assert!(!following.truncated);
    }

    #[test]
    fn ordinary_truncation_is_not_coalescing() {
        let truncated = sys::RecvMeta {
            len: 2,
            original_len: 8,
            stride: 8,
            truncated: true,
            ..sys::RecvMeta::default()
        };
        assert_eq!(receive_segment_size(truncated), None);

        let coalesced = sys::RecvMeta {
            len: 8,
            original_len: 8,
            stride: 3,
            ..sys::RecvMeta::default()
        };
        assert_eq!(receive_segment_size(coalesced), NonZeroUsize::new(3));
    }

    #[tokio::test]
    async fn cancellation_does_not_consume_a_packet() {
        let (mut receiver, sender_socket) = bind_pair(false).await;
        let destination = receiver.local_addr().unwrap();
        let mut buffer = [0; 8];
        {
            let mut future = std::pin::pin!(receiver.recv(&mut buffer));
            assert!(matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(std::task::Waker::noop())),
                Poll::Pending
            ));
        }

        let mut sender = sender_socket.create_sender();
        sender
            .send(SendDatagram::new(destination, b"after"))
            .await
            .unwrap();
        let metadata = receiver.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"after");
    }

    async fn roundtrip_ancillary_metadata(ipv6: bool) {
        let (mut receiver, sender_socket) = bind_pair(ipv6).await;
        let receive_capabilities = receiver.capabilities();
        let destination = receiver.local_addr().unwrap();
        let mut sender = sender_socket.create_sender();
        let send_capabilities = sender.capabilities();
        let mut datagram = SendDatagram::new(destination, b"ecn");
        if send_capabilities.send_ecn {
            datagram.set_ecn(EcnCodepoint::Ect0);
        }
        if send_capabilities.send_source_ip {
            datagram.set_source_ip(if ipv6 {
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            });
        }
        sender.send(datagram).await.unwrap();

        let mut buffer = [0; 8];
        let metadata = receiver.recv(&mut buffer).await.unwrap();
        if send_capabilities.send_ecn && receive_capabilities.receive_ecn {
            assert_eq!(metadata.ecn, Some(EcnCodepoint::Ect0));
        }
        if receive_capabilities.receive_local_ip {
            assert_eq!(metadata.local, destination);
        }
        if receive_capabilities.receive_interface {
            assert!(metadata.interface_index.is_some());
        }
        assert_eq!(metadata.peer.ip_addr, destination.ip_addr);
    }

    #[tokio::test]
    async fn roundtrips_ecn_and_destination_metadata_when_supported() {
        roundtrip_ancillary_metadata(false).await;
        roundtrip_ancillary_metadata(true).await;
    }

    #[tokio::test]
    async fn dual_stack_reports_ipv4_traffic_canonically() {
        let mut options = SocketOptions::default_udp();
        options.only_v6 = Some(false);
        let config = crate::UdpSocketConfig::new().with_socket_options(options);
        let factory = crate::UdpSocketFactory::new(config);
        let mut receiver = factory.bind("[::]:0").await.unwrap();
        let sender_socket = UdpPacketSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = SocketAddress::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            receiver.local_addr().unwrap().port,
        );
        let capabilities = receiver.capabilities();
        let mut sender = sender_socket.create_sender();
        sender
            .send(SendDatagram::new(destination, b"mapped"))
            .await
            .unwrap();

        let mut buffer = [0; 16];
        let metadata = receiver.recv(&mut buffer).await.unwrap();
        assert!(metadata.peer.ip_addr.is_ipv4());
        if capabilities.receive_local_ip {
            assert_eq!(metadata.local, destination);
        }

        let mut reply_sender = receiver.create_sender();
        reply_sender
            .send(SendDatagram::new(metadata.peer, b"reply"))
            .await
            .unwrap();
        let mut sender_socket = sender_socket;
        let reply = sender_socket.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..reply.len], b"reply");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn segmented_loopback_preserves_each_datagram_boundary() {
        let (mut receiver, sender_socket) = bind_pair(false).await;
        let destination = receiver.local_addr().unwrap();
        let mut sender = sender_socket.create_sender();
        if sender.capabilities().max_send_segments == 1 {
            return;
        }

        let datagram = SendDatagram::new(destination, b"aaabbbcc")
            .with_segment_size(NonZeroUsize::new(3).unwrap());
        if let Err(error) = sender.send(datagram).await {
            assert!(matches!(error, DatagramError::Io(_)));
            assert_eq!(sender.capabilities().max_send_segments, 1);
            return;
        }

        let mut segments = Vec::new();
        while segments.len() < 3 {
            let mut buffer = [0; 32];
            let metadata = receiver.recv(&mut buffer).await.unwrap();
            assert!(!metadata.truncated);
            if let Some(size) = metadata.segment_size {
                let chunks: Vec<_> = buffer[..metadata.len].chunks(size.get()).collect();
                assert!(chunks.iter().all(|chunk| !chunk.is_empty()));
                assert!(
                    chunks
                        .iter()
                        .take(chunks.len().saturating_sub(1))
                        .all(|chunk| chunk.len() == size.get())
                );
                segments.extend(chunks.into_iter().map(<[u8]>::to_vec));
            } else {
                segments.push(buffer[..metadata.len].to_vec());
            }
        }
        assert_eq!(segments, [b"aaa".to_vec(), b"bbb".to_vec(), b"cc".to_vec()]);
    }
}
