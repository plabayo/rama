//! Outgoing datagram descriptors.

use std::{net::IpAddr, num::NonZeroUsize};

use crate::{DatagramCapabilities, DatagramError, DatagramFeature, EcnCodepoint};
use rama_net::address::{SocketAddress, ip::IntoCanonicalIpAddr as _};

/// Borrowed description of one outgoing datagram or segmented datagram group.
///
/// This type contains UDP packet metadata only. It has no connection, packet
/// number, retransmission, or upper-protocol semantics.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct SendDatagram<'a> {
    /// Destination address.
    destination: SocketAddress,
    /// Datagram bytes, or concatenated bytes when `segment_size` is set.
    payload: &'a [u8],
    /// ECN codepoint to place in the IP traffic class.
    ecn: Option<EcnCodepoint>,
    /// Source IP to select for this datagram.
    source_ip: Option<IpAddr>,
    /// Size of each datagram except possibly the last when using segmentation.
    ///
    /// A segmented descriptor must represent at least two datagrams, so this
    /// value must be smaller than the payload length.
    segment_size: Option<NonZeroUsize>,
}

impl<'a> SendDatagram<'a> {
    /// Construct an ordinary unsegmented datagram.
    #[must_use]
    pub fn new(destination: impl Into<SocketAddress>, payload: &'a [u8]) -> Self {
        Self {
            destination: destination.into().into_canonical_ip_addr(),
            payload,
            ecn: None,
            source_ip: None,
            segment_size: None,
        }
    }

    /// Destination address.
    #[must_use]
    pub const fn destination(&self) -> SocketAddress {
        self.destination
    }

    /// Datagram bytes, or concatenated segmented bytes.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Selected ECN codepoint.
    #[must_use]
    pub const fn ecn(&self) -> Option<EcnCodepoint> {
        self.ecn
    }

    /// Selected source IP.
    #[must_use]
    pub const fn source_ip(&self) -> Option<IpAddr> {
        self.source_ip
    }

    /// Configured segment size.
    #[must_use]
    pub const fn segment_size(&self) -> Option<NonZeroUsize> {
        self.segment_size
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the ECN codepoint, or clear it to retain the socket default.
        pub fn ecn(mut self, ecn: Option<EcnCodepoint>) -> Self {
            self.ecn = ecn;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Select the outgoing source IP.
        pub fn source_ip(mut self, source_ip: Option<IpAddr>) -> Self {
            self.source_ip = source_ip.map(|ip| ip.into_canonical_ip_addr());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Describe concatenated datagrams for a segmented send.
        ///
        /// The size must be smaller than the payload length. Callers adapting
        /// descriptors from another API must omit a one-segment value equal to
        /// the payload length.
        pub fn segment_size(mut self, segment_size: Option<NonZeroUsize>) -> Self {
            self.segment_size = segment_size;
            self
        }
    }

    /// Number of UDP datagrams represented by this descriptor.
    #[must_use]
    pub fn segment_count(self) -> usize {
        self.segment_size
            .map_or(1, |size| self.payload.len().div_ceil(size.get()).max(1))
    }

    pub(crate) fn validate(self, capabilities: DatagramCapabilities) -> Result<(), DatagramError> {
        if self.ecn.is_some() && !capabilities.send_ecn {
            return Err(DatagramError::Unsupported(DatagramFeature::SendEcn));
        }
        if self.source_ip.is_some() && !capabilities.send_source_ip {
            return Err(DatagramError::Unsupported(DatagramFeature::SendSourceIp));
        }
        if let Some(source_ip) = self.source_ip
            && source_ip.is_ipv4() != self.destination.ip_addr.is_ipv4()
        {
            return Err(DatagramError::SourceAddressFamilyMismatch {
                source: source_ip,
                destination: self.destination,
            });
        }
        let max_payload = capabilities.max_payload_for(self.destination);
        let Some(segment_size) = self.segment_size else {
            if self.payload.len() > max_payload {
                return Err(DatagramError::PayloadTooLarge {
                    len: self.payload.len(),
                    max: max_payload,
                });
            }
            return Ok(());
        };

        let segment_size = segment_size.get();
        if self.payload.is_empty()
            || segment_size >= self.payload.len()
            || segment_size > max_payload
        {
            return Err(DatagramError::InvalidSegmentSize {
                payload_len: self.payload.len(),
                segment_size,
            });
        }
        if capabilities.max_send_segments <= 1 {
            return Err(DatagramError::Unsupported(DatagramFeature::Segmentation));
        }

        let count = self.payload.len().div_ceil(segment_size);
        if count > capabilities.max_send_segments {
            return Err(DatagramError::TooManySegments {
                count,
                max: capabilities.max_send_segments,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_family_payload_limits() {
        let capabilities = DatagramCapabilities::portable();
        let maximum = vec![0; crate::MAX_UDP_PAYLOAD_IPV4];
        let datagram = SendDatagram::new(([127, 0, 0, 1], 443), &maximum);
        datagram.validate(capabilities).unwrap();

        let payload = vec![0; crate::MAX_UDP_PAYLOAD_IPV4 + 1];
        let datagram = SendDatagram::new(([127, 0, 0, 1], 443), &payload);

        assert!(matches!(
            datagram.validate(capabilities),
            Err(DatagramError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_mismatched_source_family() {
        let mut capabilities = DatagramCapabilities::portable();
        capabilities.send_source_ip = true;
        let datagram = SendDatagram::new(([127, 0, 0, 1], 443), b"packet")
            .with_source_ip(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

        assert!(matches!(
            datagram.validate(capabilities),
            Err(DatagramError::SourceAddressFamilyMismatch { .. })
        ));
    }

    #[test]
    fn rejects_invalid_segmentation_and_unsupported_metadata() {
        let destination = SocketAddress::from(([127, 0, 0, 1], 443));
        assert!(matches!(
            SendDatagram::new(destination, b"abc")
                .with_segment_size(NonZeroUsize::new(3).unwrap())
                .validate(DatagramCapabilities::portable()),
            Err(DatagramError::InvalidSegmentSize { .. })
        ));
        assert!(matches!(
            SendDatagram::new(destination, b"abc")
                .with_ecn(EcnCodepoint::Ect0)
                .validate(DatagramCapabilities::portable()),
            Err(DatagramError::Unsupported(DatagramFeature::SendEcn))
        ));
    }

    #[test]
    fn canonicalizes_ipv4_mapped_addresses() {
        let mapped: SocketAddress = "[::ffff:127.0.0.1]:443".parse().unwrap();
        let datagram = SendDatagram::new(mapped, b"packet")
            .with_source_ip("::ffff:127.0.0.2".parse().unwrap());

        assert_eq!(
            datagram.destination(),
            SocketAddress::from(([127, 0, 0, 1], 443))
        );
        assert_eq!(datagram.source_ip(), Some([127, 0, 0, 2].into()));
    }

    #[test]
    fn enforces_the_segment_count_limit() {
        let mut capabilities = DatagramCapabilities::portable();
        capabilities.max_payload_ipv4 = 2;
        capabilities.max_send_segments = 2;
        let segment_size = NonZeroUsize::new(2).unwrap();

        let accepted =
            SendDatagram::new(([127, 0, 0, 1], 443), b"abcd").with_segment_size(segment_size);
        assert_eq!(accepted.segment_size(), Some(segment_size));
        assert_eq!(accepted.segment_count(), 2);
        accepted.validate(capabilities).unwrap();

        let rejected =
            SendDatagram::new(([127, 0, 0, 1], 443), b"abcde").with_segment_size(segment_size);
        assert_eq!(rejected.segment_count(), 3);
        assert!(matches!(
            rejected.validate(capabilities),
            Err(DatagramError::TooManySegments { count: 3, max: 2 })
        ));

        let oversized_segment = SendDatagram::new(([127, 0, 0, 1], 443), b"abcd")
            .with_segment_size(NonZeroUsize::new(3).unwrap());
        assert!(matches!(
            oversized_segment.validate(capabilities),
            Err(DatagramError::InvalidSegmentSize {
                payload_len: 4,
                segment_size: 3,
            })
        ));
    }
}
