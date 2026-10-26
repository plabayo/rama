//! Bounded, packet-preserving forwarding between two fixed UDP peers: the datagram
//! counterpart of forwarding a byte stream untouched.
//!
//! This is address translation, not an IP tunnel. Payloads and datagram boundaries
//! are preserved, including empty datagrams and GRO groups. ECN preservation is
//! explicit; timestamps, interface indices and original destinations remain local
//! receive metadata. No QUIC parsing, retransmission or congestion control occurs.

use std::{error::Error, fmt, net::IpAddr, num::NonZeroUsize};

mod bridge;
pub use bridge::{
    DatagramBridgeInput, DatagramToProxyBridge, DatagramToProxyBridgeLayer, UdpConnector,
};

use rama_core::{Service, io::BridgeIo, telemetry::tracing};
use rama_utils::macros::generate_set_and_with;

use rama_net::address::{SocketAddress, ip::IntoCanonicalIpAddr as _};

use crate::{
    DatagramError, DatagramFeature, DatagramMetadata, DatagramSender, DatagramSenderExt as _,
    DatagramSocket, DatagramSocketExt as _, InvalidDatagramMetadata, SendDatagram, SendFailure,
};

/// ECN behavior selected before either direction starts sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnPolicy {
    /// Require receive/send support on both legs and an ECN value on every input.
    Preserve,
    /// Omit ECN on outgoing datagrams. This is an explicit metadata loss.
    Discard,
}

/// An application-authorized peer on a dedicated receive socket.
///
/// The address comes from trusted routing context, not a received payload.
/// Migration and rebinding are unsupported: input from another peer fails the
/// association. Do not share either receive side with another consumer.
#[derive(Debug)]
pub struct Peer<S> {
    pub socket: S,
    pub address: SocketAddress,
    /// Optional local source address for sends to this peer.
    pub source_ip: Option<IpAddr>,
}

impl<S: DatagramSocket> Peer<S> {
    /// The peer a connected socket is fixed to.
    pub fn connected(socket: S) -> Result<Self, DatagramError> {
        let address = socket.peer_addr().map_err(DatagramError::Io)?;
        Ok(Self {
            socket,
            address,
            source_ip: None,
        })
    }
}

/// How [`DatagramForwardService`] treats an error concerning one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketErrorPolicy {
    /// Every error ends forwarding.
    #[default]
    FailAll,
    /// Drop a datagram that cannot be forwarded on its own (too large for
    /// the path, the peer's payload limit or the receive buffer; refused by a
    /// transient resource shortage) and keep forwarding. An unreachable or refusing
    /// peer, a datagram from another peer, and an unusable socket still end forwarding.
    DropPacketLocal,
}

/// Per-association memory and metadata policy.
#[derive(Debug, Clone, Copy)]
pub struct DatagramForwardService {
    /// Receive-buffer bytes in each direction, including any GRO grouping.
    /// At most two such buffers are retained by this relay. A larger input fails
    /// as truncated; no partial datagram is forwarded.
    buffer_bytes: NonZeroUsize,
    ecn: EcnPolicy,
    packet_errors: PacketErrorPolicy,
}

/// A forwarding failure ends both directions; it never authorizes a route change.
#[derive(Debug)]
pub enum DatagramForwardError {
    Datagram(DatagramError),
    UnexpectedPeer {
        expected: SocketAddress,
        actual: SocketAddress,
    },
    Truncated,
    InvalidMetadata,
    MissingEcn,
}

impl fmt::Display for DatagramForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Datagram(error) => error.fmt(f),
            Self::UnexpectedPeer { expected, actual } => {
                write!(f, "UDP relay expected {expected}, received {actual}")
            }
            Self::Truncated => f.write_str("UDP relay received a truncated datagram"),
            Self::InvalidMetadata => {
                f.write_str("UDP relay received inconsistent datagram metadata")
            }
            Self::MissingEcn => f.write_str("UDP relay cannot preserve an unreported ECN value"),
        }
    }
}

impl Error for DatagramForwardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Datagram(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DatagramError> for DatagramForwardError {
    fn from(error: DatagramError) -> Self {
        Self::Datagram(error)
    }
}

impl<A: DatagramSocket, B: DatagramSocket> Service<BridgeIo<Peer<A>, Peer<B>>>
    for DatagramForwardService
{
    type Output = ();
    type Error = DatagramForwardError;

    /// Forward both directions until an I/O or preservation error occurs.
    /// Dropping the future drops its socket owners and pending send handles.
    /// Apply association admission, idle expiration and shutdown in the caller.
    async fn serve(
        &self,
        BridgeIo(mut ingress, mut egress): BridgeIo<Peer<A>, Peer<B>>,
    ) -> Result<(), DatagramForwardError> {
        ingress.address = ingress.address.into_canonical_ip_addr();
        egress.address = egress.address.into_canonical_ip_addr();
        let mut to_ingress = ingress.socket.create_sender();
        let mut to_egress = egress.socket.create_sender();

        // Reject known capability gaps before consuming or emitting any input.
        self.check(&ingress.socket, &to_egress, egress.source_ip)?;
        self.check(&egress.socket, &to_ingress, ingress.source_ip)?;

        tokio::try_join!(
            self.copy(
                &mut ingress.socket,
                ingress.address,
                &mut to_egress,
                egress.address,
                egress.source_ip
            ),
            self.copy(
                &mut egress.socket,
                egress.address,
                &mut to_ingress,
                ingress.address,
                ingress.source_ip
            ),
        )?;
        Ok(())
    }
}

/// Forward between two connected sockets, as [`Peer::connected`] makes them: a
/// [`DatagramToProxyBridge`] association, for example.
impl<A: DatagramSocket, B: DatagramSocket> Service<BridgeIo<A, B>> for DatagramForwardService {
    type Output = ();
    type Error = DatagramForwardError;

    async fn serve(&self, BridgeIo(ingress, egress): BridgeIo<A, B>) -> Result<(), Self::Error> {
        let peers = BridgeIo(Peer::connected(ingress)?, Peer::connected(egress)?);
        self.serve(peers).await
    }
}

impl DatagramForwardService {
    /// Bound each direction's receive buffer and select an explicit ECN policy.
    /// There is no implicit metadata loss or unbounded default allocation.
    #[must_use]
    pub const fn new(buffer_bytes: NonZeroUsize, ecn: EcnPolicy) -> Self {
        Self {
            buffer_bytes,
            ecn,
            packet_errors: PacketErrorPolicy::FailAll,
        }
    }

    generate_set_and_with! {
        /// Maximum receive-buffer bytes per direction, including a GRO group.
        /// Two buffers are retained at most; oversized input fails as truncated.
        pub fn buffer_bytes(mut self, bytes: NonZeroUsize) -> Self {
            self.buffer_bytes = bytes;
            self
        }
    }

    generate_set_and_with! {
        /// Select whether both directions preserve ECN or explicitly discard it.
        pub fn ecn(mut self, policy: EcnPolicy) -> Self {
            self.ecn = policy;
            self
        }
    }

    generate_set_and_with! {
        /// Select whether an error concerning one datagram ends forwarding.
        pub fn packet_errors(mut self, policy: PacketErrorPolicy) -> Self {
            self.packet_errors = policy;
            self
        }
    }

    /// Decide whether a send error only loses this datagram.
    fn drop_send_error(&self, error: &DatagramError, destination: SocketAddress) -> bool {
        if self.packet_errors == PacketErrorPolicy::FailAll || error.is_destination_unreachable() {
            return false;
        }
        match (error.send_failure(), error) {
            (SendFailure::TooLarge, _) | (_, DatagramError::PayloadTooLarge { .. }) => {
                tracing::trace!(%error, %destination, "dropped datagram too large to forward");
            }
            (SendFailure::Datagram, _) => {
                tracing::trace!(%error, %destination, "dropped datagram refused by the socket");
            }
            (SendFailure::Descriptor | SendFailure::Socket, _) => return false,
        }
        true
    }

    /// Decide whether a truncated receive only loses this datagram.
    fn drop_truncated(&self, peer: SocketAddress) -> bool {
        if self.packet_errors == PacketErrorPolicy::FailAll {
            return false;
        }
        tracing::trace!(%peer, "dropped truncated datagram");
        true
    }

    fn check<S: DatagramSocket, T: DatagramSender>(
        &self,
        from: &S,
        to: &T,
        source_ip: Option<IpAddr>,
    ) -> Result<(), DatagramForwardError> {
        if !from.capabilities().receive_truncation {
            return Err(DatagramError::Unsupported(DatagramFeature::ReceiveTruncation).into());
        }
        if self.ecn == EcnPolicy::Preserve {
            if !from.capabilities().receive_ecn {
                return Err(DatagramError::Unsupported(DatagramFeature::ReceiveEcn).into());
            }
            if !to.capabilities().send_ecn {
                return Err(DatagramError::Unsupported(DatagramFeature::SendEcn).into());
            }
        }
        if source_ip.is_some() && !to.capabilities().send_source_ip {
            return Err(DatagramError::Unsupported(DatagramFeature::SendSourceIp).into());
        }
        Ok(())
    }

    async fn copy<S: DatagramSocket, T: DatagramSender>(
        &self,
        from: &mut S,
        expected: SocketAddress,
        to: &mut T,
        destination: SocketAddress,
        source_ip: Option<IpAddr>,
    ) -> Result<(), DatagramForwardError> {
        let mut buffer = vec![0; self.buffer_bytes.get()];
        loop {
            let metadata = from.recv(&mut buffer).await?;
            match self.validate(&metadata, buffer.len(), expected) {
                Ok(()) => {}
                Err(DatagramForwardError::Truncated) if self.drop_truncated(expected) => continue,
                Err(error) => return Err(error),
            }
            let payload = &buffer[..metadata.len];
            let ecn = match self.ecn {
                EcnPolicy::Preserve => metadata.ecn,
                EcnPolicy::Discard => None,
            };
            // Split GRO into logical UDP datagrams. This works even when the
            // other leg has no segmentation support, with one bounded send at a time.
            for packet in metadata.segments(payload) {
                let sent = to
                    .send(
                        SendDatagram::new(destination, packet)
                            .maybe_with_ecn(ecn)
                            .maybe_with_source_ip(source_ip),
                    )
                    .await;
                match sent {
                    Ok(()) => {}
                    Err(error) if self.drop_send_error(&error, destination) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }

    fn validate(
        &self,
        metadata: &DatagramMetadata,
        capacity: usize,
        expected: SocketAddress,
    ) -> Result<(), DatagramForwardError> {
        if !metadata.is_from(expected) {
            return Err(DatagramForwardError::UnexpectedPeer {
                expected,
                actual: metadata.peer,
            });
        }
        metadata.validate(capacity).map_err(|error| match error {
            InvalidDatagramMetadata::Truncated => DatagramForwardError::Truncated,
            InvalidDatagramMetadata::Length | InvalidDatagramMetadata::Segments => {
                DatagramForwardError::InvalidMetadata
            }
        })?;
        if self.ecn == EcnPolicy::Preserve && metadata.ecn.is_none() {
            return Err(DatagramForwardError::MissingEcn);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
