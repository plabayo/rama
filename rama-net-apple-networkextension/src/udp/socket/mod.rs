use std::{
    fmt, io,
    io::IoSliceMut,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_net::{
    address::{Host, SocketAddress, ip::IntoCanonicalIpAddr as _},
    stream::Socket,
};
use rama_udp::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    MAX_UDP_PAYLOAD_IPV4, MAX_UDP_PAYLOAD_IPV6, SendDatagram,
};

use super::{Datagram, UdpFlow};
use crate::tproxy::TransparentProxyFlowMeta;

/// A [`UdpFlow`] as a rama-udp [`DatagramSocket`], so a datagram demux can split it into one
/// association per destination the app addressed.
///
/// A received datagram's local address (and original destination) is the destination the app
/// sent it to, and its peer is the app. A reply must name its source, IP and port: it reaches
/// the app as sent by that destination (`sentBy`). A datagram the kernel gave no destination
/// cannot be attributed and is dropped and counted; one larger than the receive buffer is
/// reported truncated, as a kernel socket does.
pub struct UdpFlowSocket {
    flow: UdpFlow,
    app: SocketAddress,
    dropped_without_destination: Arc<AtomicU64>,
}

impl UdpFlowSocket {
    /// Wrap `flow`, whose app endpoint comes from its [`TransparentProxyFlowMeta`] when known.
    #[must_use]
    pub fn new(flow: UdpFlow) -> Self {
        let app = Self::app_endpoint(&flow);
        Self::with_app(flow, app)
    }

    fn app_endpoint(flow: &UdpFlow) -> SocketAddress {
        flow.extensions()
            .get_ref::<TransparentProxyFlowMeta>()
            .and_then(|meta| meta.local_endpoint.as_ref())
            .and_then(|endpoint| match endpoint.host {
                Host::Address(ip) => Some(SocketAddress::new(ip, endpoint.port)),
                _ => None,
            })
            .unwrap_or(SocketAddress::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn with_app(flow: UdpFlow, app: SocketAddress) -> Self {
        Self {
            flow,
            app,
            dropped_without_destination: Arc::default(),
        }
    }

    /// Datagrams dropped because the kernel gave them no destination.
    #[must_use]
    pub fn dropped_without_destination(&self) -> u64 {
        self.dropped_without_destination.load(Ordering::Relaxed)
    }
}

impl fmt::Debug for UdpFlowSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpFlowSocket")
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

impl ExtensionsRef for UdpFlowSocket {
    fn extensions(&self) -> &Extensions {
        self.flow.extensions()
    }
}

impl Socket for UdpFlowSocket {
    /// Unspecified: a flow answers as whichever destination its app addressed.
    fn local_addr(&self) -> io::Result<SocketAddress> {
        Ok(SocketAddress::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.app)
    }
}

impl DatagramSocket for UdpFlowSocket {
    type Sender = UdpFlowSender;

    fn create_sender(&self) -> Self::Sender {
        UdpFlowSender {
            outgoing: self.flow.outgoing.clone(),
            app: self.app,
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
        let Some(buffer) = buffers.first_mut() else {
            return Poll::Ready(Err(DatagramError::EmptyReceiveBatch));
        };
        let (datagram, destination) = loop {
            let datagram = match self.flow.poll_recv(cx) {
                Poll::Ready(Some(datagram)) => datagram,
                Poll::Ready(None) => return Poll::Ready(Err(DatagramError::Closed)),
                Poll::Pending => return Poll::Pending,
            };
            if let Some(destination) = datagram.peer {
                break (datagram, destination);
            }
            self.dropped_without_destination
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!("NE UDP flow datagram without a destination dropped");
        };
        // Too large for the buffer: what fits, reported truncated, as a kernel socket does.
        let original_len = datagram.payload.len();
        let len = original_len.min(buffer.len());
        buffer[..len].copy_from_slice(&datagram.payload[..len]);
        let destination = SocketAddress::from(destination).into_canonical_ip_addr();
        let mut received = DatagramMetadata::empty();
        received.len = len;
        received.original_len = original_len;
        received.peer = self.app;
        received.local = destination;
        received.original_destination = Some(destination);
        metadata[0] = received;
        Poll::Ready(Ok(1))
    }

    fn capabilities(&self) -> DatagramCapabilities {
        flow_capabilities()
    }
}

/// Writes replies to a [`UdpFlowSocket`]'s app, each as sent by the source it names.
#[derive(Clone)]
pub struct UdpFlowSender {
    outgoing: Arc<dyn Fn(Datagram) + Send + Sync + 'static>,
    app: SocketAddress,
}

impl fmt::Debug for UdpFlowSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpFlowSender")
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

impl DatagramSender for UdpFlowSender {
    fn poll_send(
        &mut self,
        _cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        // The app endpoint labels the flow; a socket's source-family rule does not apply to it.
        if let Err(error) = datagram
            .maybe_with_source_ip(None)
            .validate(flow_capabilities())
        {
            return Poll::Ready(Err(error));
        }
        if datagram.destination().into_canonical_ip_addr() != self.app.into_canonical_ip_addr() {
            return Poll::Ready(Err(DatagramError::ForeignDestination(
                datagram.destination(),
            )));
        }
        let (Some(ip), Some(port)) = (datagram.source_ip(), datagram.source_port()) else {
            return Poll::Ready(Err(DatagramError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a flow reply needs its source: a destination its app addressed",
            ))));
        };
        // An IPv6 app socket addressed an IPv4 server in its v4-mapped form.
        let ip = match (ip, self.app.ip_addr) {
            (IpAddr::V4(ip), IpAddr::V6(app)) if app.to_ipv4_mapped().is_none() => {
                IpAddr::V6(ip.to_ipv6_mapped())
            }
            _ => ip,
        };
        // Validation admits no segmented descriptor: one datagram, one write.
        (self.outgoing)(Datagram::new(
            Bytes::copy_from_slice(datagram.payload()),
            SocketAddr::new(ip, port),
        ));
        Poll::Ready(Ok(()))
    }

    fn capabilities(&self) -> DatagramCapabilities {
        flow_capabilities()
    }
}

/// One datagram at a time, each answered from a source the reply names.
const fn flow_capabilities() -> DatagramCapabilities {
    let mut capabilities = DatagramCapabilities::portable();
    capabilities.max_payload_ipv4 = MAX_UDP_PAYLOAD_IPV4;
    capabilities.max_payload_ipv6 = MAX_UDP_PAYLOAD_IPV6;
    capabilities.send_source_ip = true;
    capabilities.send_source_port = true;
    capabilities.receive_local_ip = true;
    capabilities.receive_original_destination = true;
    capabilities.receive_truncation = true;
    capabilities
}

#[cfg(test)]
mod tests;
