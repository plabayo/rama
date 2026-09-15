//! Datagram metadata and platform capability types.

use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, Ipv6Addr},
    num::NonZeroUsize,
    time::Duration,
};

use rama_net::address::SocketAddress;

pub use rama_net::ip::EcnCodepoint;

/// Largest UDP payload representable by ordinary IPv4.
///
/// This is an implementation ceiling, not a path MTU. Applications should
/// normally send substantially smaller packets and perform path MTU discovery
/// in the protocol layer when appropriate.
pub const MAX_UDP_PAYLOAD_IPV4: usize = 65_507;

/// Largest UDP payload representable by ordinary IPv6 without jumbograms.
///
/// This is an implementation ceiling, not a path MTU.
pub const MAX_UDP_PAYLOAD_IPV6: usize = 65_527;

/// Receive time together with the clock domain used by its producer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ReceiveTimestamp {
    /// Duration since the Unix epoch, normally supplied by a kernel real-time clock.
    UnixEpoch(Duration),
    /// Duration on an implementation-defined monotonic timeline.
    ///
    /// Values are comparable only when they came from the same socket backend.
    Monotonic(Duration),
}

/// Metadata associated with one receive buffer.
///
/// A buffer normally contains one UDP datagram. When receive coalescing is in
/// use, it can contain several non-empty datagrams separated at
/// [`segment_size`] byte boundaries; only the final segment may be shorter.
/// With no truncation, `len` is the sum of those segment lengths. A zero-length
/// datagram is always represented alone with no segment size.
///
/// `truncated` applies to the entire received socket entry. If it is true, the
/// copied bytes are only an incomplete prefix of the datagram or coalesced
/// group and consumers must discard the whole entry rather than parse partial
/// segments. `original_len` is the kernel-reported pre-truncation size when the
/// platform makes it available.
///
/// [`segment_size`]: Self::segment_size
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct DatagramMetadata {
    /// Number of bytes copied into the receive buffer.
    pub len: usize,
    /// Original number of bytes reported by the socket before truncation.
    ///
    /// Some platforms cannot report the original size and use `len` here.
    pub original_len: usize,
    /// Size of each coalesced datagram except possibly the last.
    ///
    /// `None` represents exactly one datagram, including a zero-length datagram.
    pub segment_size: Option<NonZeroUsize>,
    /// Source address of the datagram.
    pub peer: SocketAddress,
    /// Effective local address of the socket for this datagram.
    ///
    /// On platforms without destination-address ancillary data this can retain
    /// an unspecified IP when the socket was bound to a wildcard address.
    pub local: SocketAddress,
    /// Original destination supplied by a transparent-proxy facility, if enabled.
    pub original_destination: Option<SocketAddress>,
    /// Index of the interface on which the datagram was received.
    pub interface_index: Option<u32>,
    /// Received ECN codepoint, or `None` when the platform did not report it.
    ///
    /// `Some(EcnCodepoint::NotEct)` is deliberately distinct from unavailable.
    pub ecn: Option<EcnCodepoint>,
    /// Kernel or implementation receive time, including its clock domain.
    pub timestamp: Option<ReceiveTimestamp>,
    /// Whether the datagram did not fit in the supplied buffer.
    pub truncated: bool,
}

impl DatagramMetadata {
    /// Construct an empty metadata slot to be filled by a receive operation.
    #[must_use]
    pub const fn empty() -> Self {
        let unspecified = SocketAddress::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        Self {
            len: 0,
            original_len: 0,
            segment_size: None,
            peer: unspecified,
            local: unspecified,
            original_destination: None,
            interface_index: None,
            ecn: None,
            timestamp: None,
            truncated: false,
        }
    }

    /// Number of complete or partial segment regions in the copied bytes.
    ///
    /// This is the actual datagram count only when [`truncated`] is false.
    /// A truncated entry must be discarded as a whole.
    ///
    /// [`truncated`]: Self::truncated
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segment_size
            .map_or(1, |size| self.len.div_ceil(size.get()).max(1))
    }
}

impl Default for DatagramMetadata {
    fn default() -> Self {
        Self::empty()
    }
}

/// UDP implementation and ancillary-I/O capabilities of a socket.
///
/// This is a snapshot. A backend can lower an offload limit after the kernel or
/// driver rejects an attempted operation, so callers should query capabilities
/// again after an offload error. A segmented send is atomic from this API's
/// perspective: implementations never hide such a rejection by splitting it
/// into several ordinary sends.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct DatagramCapabilities {
    /// Maximum unsegmented IPv4 UDP payload accepted by this implementation.
    pub max_payload_ipv4: usize,
    /// Maximum unsegmented IPv6 UDP payload accepted by this implementation.
    pub max_payload_ipv6: usize,
    /// Maximum receive entries that can be filled by one optimized operation.
    pub max_receive_batch: usize,
    /// Maximum send entries that can be attempted by one optimized operation.
    pub max_send_batch: usize,
    /// Maximum datagrams represented by one segmented send descriptor.
    ///
    /// This is the authoritative validation limit. It can be backed by native
    /// offload or by an implementation such as the deterministic test socket.
    pub max_send_segments: usize,
    /// Maximum datagrams represented by one receive buffer.
    ///
    /// This is the authoritative coalesced-entry limit, regardless of how the
    /// implementation produces such entries.
    pub max_receive_segments: usize,
    /// Whether outgoing IP packets might be fragmented by the network stack.
    ///
    /// This says only whether the socket backend successfully enabled a
    /// don't-fragment policy. It is not a path MTU estimate.
    pub may_fragment: bool,
    /// Whether outgoing ECN selection is supported.
    pub send_ecn: bool,
    /// Whether received ECN codepoints are reported.
    pub receive_ecn: bool,
    /// Whether an outgoing source IP can be selected per datagram.
    pub send_source_ip: bool,
    /// Whether the effective local destination IP is reported per datagram.
    pub receive_local_ip: bool,
    /// Whether the incoming interface index is reported.
    pub receive_interface: bool,
    /// Whether transparent-proxy original destinations are reported.
    pub receive_original_destination: bool,
    /// Whether receive timestamps are reported.
    pub receive_timestamp: bool,
    /// Whether receive truncation is detected instead of silently discarded.
    pub receive_truncation: bool,
}

impl DatagramCapabilities {
    /// Return the implementation payload ceiling for `address`'s IP family.
    #[must_use]
    pub const fn max_payload_for(self, address: SocketAddress) -> usize {
        match address.ip_addr {
            IpAddr::V4(_) => self.max_payload_ipv4,
            IpAddr::V6(address) if address.to_ipv4_mapped().is_some() => self.max_payload_ipv4,
            IpAddr::V6(_) => self.max_payload_ipv6,
        }
    }

    /// Whether this snapshot provides `feature`.
    #[must_use]
    pub const fn supports(self, feature: DatagramFeature) -> bool {
        match feature {
            DatagramFeature::SendEcn => self.send_ecn,
            DatagramFeature::ReceiveEcn => self.receive_ecn,
            DatagramFeature::SendSourceIp => self.send_source_ip,
            DatagramFeature::ReceiveLocalIp => self.receive_local_ip,
            DatagramFeature::ReceiveInterface => self.receive_interface,
            DatagramFeature::ReceiveOriginalDestination => self.receive_original_destination,
            DatagramFeature::ReceiveTimestamp => self.receive_timestamp,
            DatagramFeature::ReceiveTruncation => self.receive_truncation,
            DatagramFeature::PreventFragmentation => !self.may_fragment,
            DatagramFeature::Segmentation => self.max_send_segments > 1,
        }
    }

    /// Conservative capabilities for a portable one-packet fallback.
    #[must_use]
    pub const fn portable() -> Self {
        Self {
            max_payload_ipv4: MAX_UDP_PAYLOAD_IPV4,
            max_payload_ipv6: MAX_UDP_PAYLOAD_IPV6,
            max_receive_batch: 1,
            max_send_batch: 1,
            max_send_segments: 1,
            max_receive_segments: 1,
            may_fragment: true,
            send_ecn: false,
            receive_ecn: false,
            send_source_ip: false,
            receive_local_ip: false,
            receive_interface: false,
            receive_original_destination: false,
            receive_timestamp: false,
            receive_truncation: false,
        }
    }
}

impl Default for DatagramCapabilities {
    fn default() -> Self {
        Self::portable()
    }
}

/// Datagram feature that can be unavailable on a platform or socket provider.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum DatagramFeature {
    /// Sending an explicit ECN codepoint.
    SendEcn,
    /// Receiving ECN metadata.
    ReceiveEcn,
    /// Selecting a source IP for one send.
    SendSourceIp,
    /// Receiving the effective local destination IP.
    ReceiveLocalIp,
    /// Receiving the incoming interface index.
    ReceiveInterface,
    /// Receiving a transparent-proxy original destination.
    ReceiveOriginalDestination,
    /// Receiving a packet timestamp.
    ReceiveTimestamp,
    /// Detecting truncated datagrams.
    ReceiveTruncation,
    /// Preventing IP fragmentation at the socket layer.
    PreventFragmentation,
    /// Segmented send descriptors, whether native or deterministically simulated.
    Segmentation,
}

impl fmt::Display for DatagramFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SendEcn => "send ECN",
            Self::ReceiveEcn => "receive ECN",
            Self::SendSourceIp => "source IP selection",
            Self::ReceiveLocalIp => "local destination metadata",
            Self::ReceiveInterface => "receive interface metadata",
            Self::ReceiveOriginalDestination => "original destination metadata",
            Self::ReceiveTimestamp => "receive timestamps",
            Self::ReceiveTruncation => "receive truncation detection",
            Self::PreventFragmentation => "IP fragmentation prevention",
            Self::Segmentation => "UDP segmentation",
        };
        f.write_str(name)
    }
}

/// Error from a packet-oriented datagram operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum DatagramError {
    /// Operating-system or runtime I/O error.
    Io(io::Error),
    /// A validated segmented send was rejected by the socket's offload implementation.
    ///
    /// No segment was accepted. Query capabilities before retrying as ordinary datagrams.
    /// The original socket error is retained; other I/O failures are not classified this way.
    SegmentationRejected(io::Error),
    /// A requested feature is not available on this socket.
    Unsupported(DatagramFeature),
    /// An unsegmented payload exceeds the implementation ceiling.
    PayloadTooLarge {
        /// Submitted payload length.
        len: usize,
        /// Maximum accepted length.
        max: usize,
    },
    /// Segment metadata does not describe the submitted payload.
    InvalidSegmentSize {
        /// Submitted payload length.
        payload_len: usize,
        /// Submitted segment size.
        segment_size: usize,
    },
    /// A segmented datagram entry contains more segments than supported.
    TooManySegments {
        /// Submitted segment count.
        count: usize,
        /// Maximum accepted segment count.
        max: usize,
    },
    /// The selected source IP and destination use different address families.
    SourceAddressFamilyMismatch {
        /// Selected source IP.
        source: IpAddr,
        /// Submitted destination.
        destination: SocketAddress,
    },
    /// Receive buffers and metadata slots have different lengths.
    ReceiveSlotMismatch {
        /// Number of receive buffers.
        buffers: usize,
        /// Number of metadata slots.
        metadata: usize,
    },
    /// A receive operation was submitted without any buffers.
    EmptyReceiveBatch,
    /// The deterministic in-memory peer has shut down.
    Closed,
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "datagram I/O failed: {error}"),
            Self::SegmentationRejected(error) => write!(f, "UDP segmentation rejected: {error}"),
            Self::Unsupported(feature) => write!(f, "unsupported datagram feature: {feature}"),
            Self::PayloadTooLarge { len, max } => {
                write!(
                    f,
                    "UDP payload is {len} bytes; implementation maximum is {max}"
                )
            }
            Self::InvalidSegmentSize {
                payload_len,
                segment_size,
            } => write!(
                f,
                "segment size {segment_size} does not describe a {payload_len}-byte payload"
            ),
            Self::TooManySegments { count, max } => {
                write!(f, "datagram entry has {count} segments; maximum is {max}")
            }
            Self::SourceAddressFamilyMismatch {
                source,
                destination,
            } => write!(
                f,
                "source IP {source} and destination {destination} use different address families"
            ),
            Self::ReceiveSlotMismatch { buffers, metadata } => write!(
                f,
                "receive has {buffers} buffers but {metadata} metadata slots"
            ),
            Self::EmptyReceiveBatch => f.write_str("receive batch has no buffers"),
            Self::Closed => f.write_str("datagram peer is closed"),
        }
    }
}

impl Error for DatagramError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) | Self::SegmentationRejected(error) => Some(error),
            _ => None,
        }
    }
}

/// Coarse classification of a failed send.
///
/// Callers use it to decide whether one datagram was lost, the request itself was
/// invalid, or the socket can no longer be used at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendFailure {
    /// Only this datagram was refused; the socket stays usable.
    ///
    /// Covers destination and path feedback such as unreachable networks, filtered
    /// destinations and transient resource shortages.
    Datagram,
    /// The network stack rejected the datagram as too large for the destination path or
    /// interface. Smaller datagrams to the same destination can still succeed.
    TooLarge,
    /// The descriptor or a requested feature is invalid for this socket; retrying the same
    /// descriptor cannot succeed.
    Descriptor,
    /// The socket itself can no longer send.
    Socket,
}

impl DatagramError {
    /// Classify this error for a sender's failure policy.
    #[must_use]
    pub fn send_failure(&self) -> SendFailure {
        match self {
            Self::Io(error) => classify_send_io_error(error),
            Self::Closed => SendFailure::Socket,
            Self::SegmentationRejected(_)
            | Self::Unsupported(_)
            | Self::PayloadTooLarge { .. }
            | Self::InvalidSegmentSize { .. }
            | Self::TooManySegments { .. }
            | Self::SourceAddressFamilyMismatch { .. }
            | Self::ReceiveSlotMismatch { .. }
            | Self::EmptyReceiveBatch => SendFailure::Descriptor,
        }
    }
}

fn classify_send_io_error(error: &io::Error) -> SendFailure {
    if is_message_too_large(error) {
        return SendFailure::TooLarge;
    }
    if is_socket_unusable(error) {
        return SendFailure::Socket;
    }
    match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported => SendFailure::Descriptor,
        io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe => SendFailure::Socket,
        _ => SendFailure::Datagram,
    }
}

// Raw codes stay in the socket layer: the standard error kinds do not model them.
fn is_message_too_large(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EMSGSIZE)
    }
    #[cfg(windows)]
    {
        error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = error;
        false
    }
}

fn is_socket_unusable(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(error.raw_os_error(), Some(libc::EBADF | libc::ENOTSOCK))
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{WSAEBADF, WSAENOTSOCK, WSAESHUTDOWN};
        matches!(
            error.raw_os_error(),
            Some(WSAEBADF | WSAENOTSOCK | WSAESHUTDOWN)
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = error;
        false
    }
}

impl From<io::Error> for DatagramError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn selects_payload_limit_from_the_ip_family() {
        let capabilities = DatagramCapabilities {
            max_payload_ipv4: 4,
            max_payload_ipv6: 6,
            ..DatagramCapabilities::portable()
        };

        assert_eq!(
            capabilities.max_payload_for(SocketAddress::new(Ipv4Addr::LOCALHOST.into(), 1)),
            4
        );
        assert_eq!(
            capabilities.max_payload_for(SocketAddress::new(Ipv6Addr::LOCALHOST.into(), 1)),
            6
        );
        assert_eq!(
            capabilities.max_payload_for(SocketAddress::new(
                Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(),
                1,
            )),
            4
        );
    }

    #[test]
    fn maps_features_to_their_capabilities() {
        let features = [
            DatagramFeature::SendEcn,
            DatagramFeature::ReceiveEcn,
            DatagramFeature::SendSourceIp,
            DatagramFeature::ReceiveLocalIp,
            DatagramFeature::ReceiveInterface,
            DatagramFeature::ReceiveOriginalDestination,
            DatagramFeature::ReceiveTimestamp,
            DatagramFeature::ReceiveTruncation,
            DatagramFeature::PreventFragmentation,
            DatagramFeature::Segmentation,
        ];
        let portable = DatagramCapabilities::portable();
        assert!(
            features
                .into_iter()
                .all(|feature| !portable.supports(feature))
        );

        let capabilities = DatagramCapabilities {
            may_fragment: false,
            send_ecn: true,
            receive_ecn: true,
            send_source_ip: true,
            receive_local_ip: true,
            receive_interface: true,
            receive_original_destination: true,
            receive_timestamp: true,
            receive_truncation: true,
            max_send_segments: 2,
            ..portable
        };
        assert!(
            features
                .into_iter()
                .all(|feature| capabilities.supports(feature))
        );
    }

    #[test]
    fn errors_expose_context_and_io_sources() {
        assert_eq!(DatagramFeature::SendEcn.to_string(), "send ECN");

        let error = DatagramError::from(io::Error::other("socket closed"));
        assert_eq!(error.to_string(), "datagram I/O failed: socket closed");
        assert_eq!(error.source().unwrap().to_string(), "socket closed");
    }

    #[test]
    fn send_failures_classify_descriptor_socket_and_datagram_errors() {
        assert_eq!(
            DatagramError::Unsupported(DatagramFeature::SendSourceIp).send_failure(),
            SendFailure::Descriptor
        );
        assert_eq!(
            DatagramError::TooManySegments { count: 2, max: 1 }.send_failure(),
            SendFailure::Descriptor
        );
        assert_eq!(
            DatagramError::SegmentationRejected(io::Error::other("x")).send_failure(),
            SendFailure::Descriptor
        );
        assert_eq!(DatagramError::Closed.send_failure(), SendFailure::Socket);
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::Other,
        ] {
            assert_eq!(
                DatagramError::Io(io::Error::from(kind)).send_failure(),
                SendFailure::Datagram,
                "{kind:?}"
            );
        }
        for kind in [io::ErrorKind::InvalidInput, io::ErrorKind::Unsupported] {
            assert_eq!(
                DatagramError::Io(io::Error::from(kind)).send_failure(),
                SendFailure::Descriptor,
                "{kind:?}"
            );
        }
        for kind in [io::ErrorKind::NotConnected, io::ErrorKind::BrokenPipe] {
            assert_eq!(
                DatagramError::Io(io::Error::from(kind)).send_failure(),
                SendFailure::Socket,
                "{kind:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn send_failures_classify_native_unix_codes() {
        let raw = |code| DatagramError::Io(io::Error::from_raw_os_error(code)).send_failure();
        assert_eq!(raw(libc::EMSGSIZE), SendFailure::TooLarge);
        assert_eq!(raw(libc::EBADF), SendFailure::Socket);
        assert_eq!(raw(libc::ENOTSOCK), SendFailure::Socket);
        assert_eq!(raw(libc::ENETUNREACH), SendFailure::Datagram);
        assert_eq!(raw(libc::EHOSTUNREACH), SendFailure::Datagram);
        assert_eq!(raw(libc::EPERM), SendFailure::Datagram);
        assert_eq!(raw(libc::ENOBUFS), SendFailure::Datagram);
        assert_eq!(raw(libc::EINVAL), SendFailure::Descriptor);
    }

    /// The Winsock counterpart of the native Unix codes. `WSAESHUTDOWN` has no
    /// Unix equivalent here: a shut-down Winsock socket can no longer send, so
    /// it retires the socket rather than failing only this datagram.
    #[cfg(windows)]
    #[test]
    fn send_failures_classify_native_windows_codes() {
        use windows_sys::Win32::Networking::WinSock::{
            WSAEACCES, WSAEBADF, WSAEHOSTUNREACH, WSAEINVAL, WSAEMSGSIZE, WSAENETUNREACH,
            WSAENOBUFS, WSAENOTSOCK, WSAESHUTDOWN,
        };

        let raw = |code| DatagramError::Io(io::Error::from_raw_os_error(code)).send_failure();
        assert_eq!(raw(WSAEMSGSIZE), SendFailure::TooLarge);
        assert_eq!(raw(WSAEBADF), SendFailure::Socket);
        assert_eq!(raw(WSAENOTSOCK), SendFailure::Socket);
        assert_eq!(raw(WSAESHUTDOWN), SendFailure::Socket);
        assert_eq!(raw(WSAENETUNREACH), SendFailure::Datagram);
        assert_eq!(raw(WSAEHOSTUNREACH), SendFailure::Datagram);
        assert_eq!(raw(WSAEACCES), SendFailure::Datagram);
        assert_eq!(raw(WSAENOBUFS), SendFailure::Datagram);
        assert_eq!(raw(WSAEINVAL), SendFailure::Descriptor);
    }
}
