//! ICMP error reports of a packet socket, out of band from its datagrams.

use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::{Context, Poll, ready},
};

use rama_net::ip::icmp::IcmpErrorReport;
use tokio::io::Interest;
use tokio_util::sync::ReusableBoxFuture;

use crate::{DatagramError, sys};

/// Receives the [`IcmpErrorReport`]s about datagrams a [`UdpPacketSocket`] sent: what the
/// network answered with ICMP, and what the local stack refused, such as a datagram over the
/// link MTU.
///
/// Created by [`UdpPacketSocket::icmp_error_receiver`]. While one exists the socket queues
/// these reports (Linux `IP_RECVERR` and `IPV6_RECVERR`); dropping the last one turns that off
/// and discards what is still queued. Other platforms have no such queue and refuse to create
/// one with an [`io::ErrorKind::Unsupported`] error.
///
/// Queued reports are charged to the socket's receive buffer: a receiver must keep draining,
/// or arriving datagrams are dropped once that buffer is full.
///
/// Reports never reach a datagram receive. Without the queue an ICMP error reaches a connected
/// socket as an error on its next send or receive; with it, such errors on any socket are
/// absorbed instead: a single, batched or coalesced receive returns the datagrams behind the
/// error, and a send that fails with one is retried once, so only an error of its own
/// remains. A receive that absorbs many in a row yields to the scheduler before trying again.
///
/// ICMP is not authenticated and is trivially spoofed: a report is a hint about a path, never
/// a reason to change connection state.
///
/// [`UdpPacketSocket`]: crate::UdpPacketSocket
/// [`UdpPacketSocket::icmp_error_receiver`]: crate::UdpPacketSocket::icmp_error_receiver
pub struct IcmpErrorReceiver {
    io: Arc<sys::PairedSocket>,
    ready: Option<ReusableBoxFuture<'static, io::Result<()>>>,
}

impl IcmpErrorReceiver {
    pub(crate) fn new(io: Arc<sys::PairedSocket>) -> Result<Self, DatagramError> {
        io.acquire_icmp_reports()?;
        Ok(Self { io, ready: None })
    }

    /// Receive the next report, or register for readiness.
    pub fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<IcmpErrorReport, DatagramError>> {
        loop {
            let ready = self
                .ready
                .get_or_insert_with(|| ReusableBoxFuture::new(wait_error(self.io.clone())));
            let readiness = ready!(ready.poll(cx));
            // A completed future is never polled again.
            ready.set(wait_error(self.io.clone()));
            if let Err(error) = readiness {
                return Poll::Ready(Err(error.into()));
            }
            // `try_io` must see `WouldBlock` so Tokio clears the error readiness.
            match self
                .io
                .try_io(Interest::ERROR, || self.io.recv_icmp_report())
            {
                Ok(report) => return Poll::Ready(Ok(report)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                // A run of skipped queue entries: drain further after other tasks ran.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(error.into())),
            }
        }
    }

    /// Receive the next report.
    pub fn recv(
        &mut self,
    ) -> impl Future<Output = Result<IcmpErrorReport, DatagramError>> + Send + '_ {
        poll_fn(|cx| self.poll_recv(cx))
    }
}

impl Drop for IcmpErrorReceiver {
    fn drop(&mut self) {
        self.io.release_icmp_reports();
    }
}

impl fmt::Debug for IcmpErrorReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IcmpErrorReceiver")
            .finish_non_exhaustive()
    }
}

// Construct every replacement through the same function so its layout always matches
// the future already stored in the reusable allocation.
async fn wait_error(io: Arc<sys::PairedSocket>) -> io::Result<()> {
    io.ready(Interest::ERROR).await.map(drop)
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod tests {
    use std::{mem::MaybeUninit, net::SocketAddr, time::Duration};

    use rama_net::{
        address::SocketAddress,
        ip::icmp::{IcmpErrorKind, IcmpErrorOrigin},
        stream::Socket as _,
    };

    use std::os::fd::AsRawFd as _;

    use crate::{
        DatagramSenderExt as _, DatagramSocket as _, DatagramSocketExt as _, SendDatagram,
        UdpPacketSocket,
    };

    /// A closed loopback port: one a socket was bound to and released.
    fn closed_port(ip: &str) -> SocketAddress {
        let address: SocketAddr = format!("{ip}:0").parse().unwrap();
        std::net::UdpSocket::bind(address)
            .unwrap()
            .local_addr()
            .unwrap()
            .into()
    }

    /// Wait until the socket has an error pending or queued, without consuming it.
    fn wait_for_error(socket: &UdpPacketSocket) {
        let mut poll = libc::pollfd {
            fd: socket.socket_ref().as_raw_fd(),
            events: 0,
            revents: 0,
        };
        // SAFETY: `poll(2)` reads and writes the one live `pollfd` it is given.
        let ready = unsafe { libc::poll(&raw mut poll, 1, 5_000) };
        assert_eq!(ready, 1, "an ICMP error arrives within five seconds");
        assert_ne!(poll.revents & libc::POLLERR, 0);
    }

    /// A send to a closed loopback port is reported port-unreachable, naming the datagram's
    /// destination and the host that refused it, in each family and on a dual-stack socket.
    #[tokio::test]
    async fn a_closed_port_is_reported_unreachable() {
        let cases = [
            (
                "127.0.0.1:0",
                "127.0.0.1",
                IcmpErrorOrigin::Icmpv4 {
                    icmp_type: 3,
                    code: 3,
                },
            ),
            (
                "[::1]:0",
                "[::1]",
                IcmpErrorOrigin::Icmpv6 {
                    icmp_type: 1,
                    code: 4,
                },
            ),
            (
                "[::]:0",
                "127.0.0.1",
                IcmpErrorOrigin::Icmpv4 {
                    icmp_type: 3,
                    code: 3,
                },
            ),
        ];
        for (bind, peer, origin) in cases {
            let socket = UdpPacketSocket::bind(bind).await.unwrap();
            let mut receiver = socket.icmp_error_receiver().unwrap();
            let closed = closed_port(peer);
            socket
                .create_sender()
                .send(SendDatagram::new(closed, b"void"))
                .await
                .unwrap();
            let report = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
                .await
                .expect("the report arrives")
                .unwrap();
            assert_eq!(report.origin(), origin, "{bind} to {peer}");
            assert_eq!(report.kind(), Some(IcmpErrorKind::PortUnreachable));
            assert_eq!(report.destination(), Some(closed), "{bind} to {peer}");
            assert_eq!(report.reporter(), Some(closed.ip_addr), "{bind} to {peer}");
        }
    }

    /// The kernel behaviour the absorption exists for: with the error queue on, an ICMP
    /// error fails the next receive of an unconnected socket too.
    #[tokio::test]
    async fn the_error_queue_fails_the_next_receive_of_an_unconnected_socket() {
        let socket = UdpPacketSocket::bind("127.0.0.1:0").await.unwrap();
        let _receiver = socket.icmp_error_receiver().unwrap();
        socket
            .create_sender()
            .send(SendDatagram::new(closed_port("127.0.0.1"), b"void"))
            .await
            .unwrap();
        wait_for_error(&socket);
        let error = socket
            .socket_ref()
            .recv(&mut [MaybeUninit::new(0); 8])
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ECONNREFUSED));
    }

    /// With reports on, an ICMP error neither fails the receive of the datagram behind it
    /// nor the next send.
    #[tokio::test]
    async fn datagrams_keep_flowing_while_reports_are_on() {
        let mut socket = UdpPacketSocket::bind("127.0.0.1:0").await.unwrap();
        let mut receiver = socket.icmp_error_receiver().unwrap();
        let mut peer = UdpPacketSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sender = socket.create_sender();
        let closed = closed_port("127.0.0.1");

        sender
            .send(SendDatagram::new(closed, b"void"))
            .await
            .unwrap();
        wait_for_error(&socket);
        peer.create_sender()
            .send(SendDatagram::new(socket.local_addr().unwrap(), b"hello"))
            .await
            .unwrap();
        let mut buffer = [0; 16];
        let metadata = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..metadata.len], b"hello");

        sender
            .send(SendDatagram::new(closed, b"void"))
            .await
            .unwrap();
        wait_for_error(&socket);
        sender
            .send(SendDatagram::new(peer.local_addr().unwrap(), b"after"))
            .await
            .expect("the send is not failed by the earlier datagram's error");
        let metadata = tokio::time::timeout(Duration::from_secs(5), peer.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..metadata.len], b"after");

        for _ in 0..2 {
            let report = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(report.destination(), Some(closed));
        }
    }

    /// Reports are queued only while a receiver exists; the last one dropped turns them off.
    #[tokio::test]
    async fn reports_stop_with_the_last_receiver() {
        let socket = UdpPacketSocket::bind("127.0.0.1:0").await.unwrap();
        let first = socket.icmp_error_receiver().unwrap();
        let second = socket.icmp_error_receiver().unwrap();
        drop(first);
        let reporting = |socket: &UdpPacketSocket| {
            let mut value: libc::c_int = 0;
            let mut len = size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: `getsockopt(2)` writes at most `len` bytes at `value` and the size to
            // `len`, both live locals.
            let rc = unsafe {
                libc::getsockopt(
                    socket.socket_ref().as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_RECVERR,
                    (&raw mut value).cast(),
                    &raw mut len,
                )
            };
            assert_eq!(rc, 0);
            value != 0
        };
        assert!(reporting(&socket), "a receiver remains");
        drop(second);
        assert!(!reporting(&socket));

        let mut sender = socket.create_sender();
        let unreported = closed_port("127.0.0.1");
        sender
            .send(SendDatagram::new(unreported, b"void"))
            .await
            .unwrap();
        let mut receiver = socket.icmp_error_receiver().unwrap();
        let reported = closed_port("127.0.0.1");
        assert_ne!(reported, unreported);
        sender
            .send(SendDatagram::new(reported, b"void"))
            .await
            .unwrap();
        let report = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            report.destination(),
            Some(reported),
            "nothing was queued while no receiver existed"
        );
    }
}

#[cfg(test)]
#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod unsupported_tests {
    use super::*;
    use crate::UdpPacketSocket;

    /// Without a socket error queue the receiver is refused, never silently inert.
    #[tokio::test]
    async fn platforms_without_an_error_queue_refuse_a_receiver() {
        let socket = UdpPacketSocket::bind("127.0.0.1:0").await.unwrap();
        match socket.icmp_error_receiver() {
            Err(DatagramError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            }
            other => panic!("expected an unsupported error, got {other:?}"),
        }
    }
}
