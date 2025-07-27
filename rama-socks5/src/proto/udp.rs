//! Udp implementation of the SOCKS5 Protocol [RFC 1928].
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

use byteorder::{BigEndian, ReadBytesExt};
use rama_core::bytes::BufMut;
use std::io::Read;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::proto::common::write_authority_to_buf;

use super::{
    ProtocolError,
    common::{authority_length, read_authority, read_authority_sync},
};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Layout for a header sent by a UDP Client (as request) and UDP server (as resonse),
/// for any datagram (to be) relayed by the proxy.
///
/// A UDP-based client MUST send its datagrams to the UDP relay server at
/// the UDP port indicated by BND.PORT in the reply to the UDP ASSOCIATE
/// request.  If the selected authentication method provides
/// encapsulation for the purposes of authenticity, integrity, and/or
/// confidentiality, the datagram MUST be encapsulated using the
/// appropriate encapsulation.  Each UDP datagram carries a UDP request
/// header with it:
///
/// ```plain
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
///
/// When a UDP relay server decides to relay a UDP datagram, it does so
/// silently, without any notification to the requesting client.
/// Similarly, it will drop datagrams it cannot or will not relay.  When
/// a UDP relay server receives a reply datagram from a remote host, it
/// MUST encapsulate that datagram using the above UDP request header,
/// and any authentication-method-dependent encapsulation.
///
/// The UDP relay server MUST acquire from the SOCKS server the expected
/// IP address of the client that will send datagrams to the BND.PORT
/// given in the reply to UDP ASSOCIATE.  It MUST drop any datagrams
/// arriving from any source IP address other than the one recorded for
/// the particular association.
///
/// The FRAG field indicates whether or not this datagram is one of a
/// number of fragments.  If implemented, the high-order bit indicates
/// end-of-fragment sequence, while a value of X'00' indicates that this
/// datagram is standalone.  Values between 1 and 127 indicate the
/// fragment position within a fragment sequence.  Each receiver will
/// have a REASSEMBLY QUEUE and a REASSEMBLY TIMER associated with these
/// fragments.  The reassembly queue must be reinitialized and the
/// associated fragments abandoned whenever the REASSEMBLY TIMER expires,
/// or a new datagram arrives carrying a FRAG field whose value is less
/// than the highest FRAG value processed for this fragment sequence.
/// The reassembly timer MUST be no less than 5 seconds.  It is
/// recommended that fragmentation be avoided by applications wherever
/// possible.
///
/// Implementation of fragmentation is optional; an implementation that
/// does not support fragmentation MUST drop any datagram whose FRAG
/// field is other than X'00'.
///
/// The programming interface for a SOCKS-aware UDP MUST report an
/// available buffer space for UDP datagrams that is smaller than the
/// actual space provided by the operating system:
///
/// - if ATYP is X'01': 10+method_dependent octets smaller
/// - if ATYP is X'03': 262+method_dependent octets smaller
/// - if ATYP is X'04': 20+method_dependent octets smaller
///
/// # Fragmentation
///
/// Warning. Rama's build in Udp associator / relayer does not
/// support fragmentation and will reject any udp datagram
/// with a header containing a fragment number != 0.
///
/// # Data
///
/// The length of the data is not explicitly defined,
/// nor is the data NULL terminated, instead it is to be assumed
/// that the data (original UDP datagram) is all the bytes received
/// in the datagram containing the header except for the first bytes
/// encoding said header.
pub struct UdpHeader {
    pub fragment_number: u8,
    pub destination: rama_net::address::Authority,
}

impl UdpHeader {
    /// Read the [`UdpPacket`], decoded from binary format as specified by [RFC 1928] from the reader.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let _rsv = r.read_u16().await?;

        let fragment_number = r.read_u8().await?;

        let destination = read_authority(r).await?;

        Ok(Self {
            fragment_number,
            destination,
        })
    }

    /// Read the [`UdpPacket`], decoded from binary format as specified by [RFC 1928] from the reader.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn read_from_sync<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: Read,
    {
        let _rsv = r.read_u16::<BigEndian>()?;

        let fragment_number = r.read_u8()?;

        let destination = read_authority_sync(r)?;

        Ok(Self {
            fragment_number,
            destination,
        })
    }

    /// Write the [`UdpPacket`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(0 /* RSV */);
        buf.put_u8(self.fragment_number);
        write_authority_to_buf(&self.destination, buf);
    }

    pub(crate) fn serialized_len(&self) -> usize {
        5 + authority_length(&self.destination)
    }
}

#[cfg(test)]
mod tests {
    use rama_core::bytes::BytesMut;
    use rama_net::address::Authority;
    use std::io::Write;
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::*;
    use crate::proto::{test_write_read_eq, test_write_read_sync_eq};

    impl UdpHeader {
        // to expensive in production, so only enable in tests
        pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
        where
            W: AsyncWrite + Unpin,
        {
            let mut buf = BytesMut::with_capacity(self.serialized_len());
            self.write_to_buf(&mut buf);
            w.write_all(&buf).await
        }

        // to expensive in production, so only enable in tests
        pub fn write_to_sync<W>(&self, w: &mut W) -> Result<(), std::io::Error>
        where
            W: Write,
        {
            let mut buf = BytesMut::with_capacity(self.serialized_len());
            self.write_to_buf(&mut buf);
            w.write_all(&buf)
        }
    }

    #[tokio::test]
    async fn test_udp_packet_write_read_eq() {
        test_write_read_eq!(
            UdpHeader {
                fragment_number: 2,
                destination: Authority::local_ipv6(45),
            },
            UdpHeader
        );
    }

    #[test]
    fn test_udp_packet_write_read_sync_eq() {
        test_write_read_sync_eq!(
            UdpHeader {
                fragment_number: 2,
                destination: Authority::local_ipv6(45),
            },
            UdpHeader
        );
    }
}
