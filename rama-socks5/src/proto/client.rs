//! Client implementation of the SOCKS5 Protocol [RFC 1928]
//! and username-password protocol extension [RFC 1929].
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
//! [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929

use super::{
    Command, ProtocolError, ProtocolVersion, SocksMethod, UsernamePasswordSubnegotiationVersion,
    common::{authority_length, read_authority, write_authority_to_buf},
};
use bytes::{BufMut, BytesMut};
use rama_net::address::Authority;
use smallvec::{SmallVec, smallvec};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
/// The client connects to the server, and sends a header which
/// contains the protocol version desired and SOCKS methods supported by the client.
///
/// ```plain
/// +-----+----------+----------+
/// | VER | NMETHODS | METHODS  |
/// +-----+----------+----------+
/// |  1  |    1     | 1 to 255 |
/// +-----+----------+----------|
/// ```
///
/// Reference: https://datatracker.ietf.org/doc/html/rfc1928
pub struct Header {
    pub version: ProtocolVersion,
    pub methods: SmallVec<[SocksMethod; 2]>,
}

impl Header {
    /// Read the client [`Header`], decoded from binary format as specified by [RFC 1928] from the reader.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let version: ProtocolVersion = r.read_u8().await?.into();
        match version {
            ProtocolVersion::Socks5 => (),
            ProtocolVersion::Unknown(version) => {
                return Err(ProtocolError::UnexpectedByte {
                    pos: 0,
                    byte: version.into(),
                });
            }
        }

        let mlen = r.read_u8().await?;
        let methods = match mlen {
            0 => {
                return Err(ProtocolError::UnexpectedByte { pos: 1, byte: mlen });
            }
            1 => {
                let method: SocksMethod = r.read_u8().await?.into();
                smallvec![method]
            }
            2 => {
                let m1: SocksMethod = r.read_u8().await?.into();
                let m2: SocksMethod = r.read_u8().await?.into();
                smallvec![m1, m2]
            }
            n => {
                let mut slice = vec![0; n as usize];
                r.read_exact(&mut slice).await?;
                let mut methods = SmallVec::with_capacity(n as usize);
                for method in slice {
                    methods.push(method.into());
                }
                methods
            }
        };

        Ok(Header { version, methods })
    }

    /// Write the client [`Header`] in binary format as specified by [RFC 1928] into the writer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write the client [`Header`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());

        debug_assert!(self.methods.len() <= 255);
        buf.put_u8(self.methods.len() as u8);

        for method in self.methods.iter().copied() {
            buf.put_u8(method.into());
        }
    }

    fn serialized_len(&self) -> usize {
        1 + 1 + self.methods.len()
    }
}

#[derive(Debug, Clone)]
/// The SOCKS request sent by the client.
///
/// Once the method-dependent subnegotiation has completed, the client
/// sends the request details. If the negotiated method includes
/// encapsulation for purposes of integrity checking and/or
/// confidentiality, these requests MUST be encapsulated in the method-
/// dependent encapsulation.
///
/// The SOCKS request is formed as follows:
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
///
/// The SOCKS server will typically evaluate the request based on source
/// and destination addresses, and return one or more reply messages, as
/// appropriate for the request type.
pub struct Request {
    pub version: ProtocolVersion,
    pub command: Command,
    pub destination: Authority,
}

impl Request {
    /// Read the client [`Request`], decoded from binary format as specified by [RFC 1928] from the reader.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let version: ProtocolVersion = r.read_u8().await?.into();
        match version {
            ProtocolVersion::Socks5 => (),
            ProtocolVersion::Unknown(version) => {
                return Err(ProtocolError::UnexpectedByte {
                    pos: 0,
                    byte: version.into(),
                });
            }
        }

        let command: Command = r.read_u8().await?.into();

        let rsv = r.read_u8().await?.into();
        if rsv != 0 {
            return Err(ProtocolError::UnexpectedByte { pos: 2, byte: rsv });
        }

        let destination = read_authority(r).await?;

        Ok(Request {
            version,
            command,
            destination,
        })
    }

    /// Write the client [`Request`] in binary format as specified by [RFC 1928] into the writer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let self_ref = RequestRef {
            version: self.version,
            command: self.command,
            destination: &self.destination,
        };
        self_ref.write_to(w).await
    }
}

#[derive(Debug, Clone)]
/// The SOCKS request sent by the client.
///
/// Reference (write-only) version of [`Request`],
/// see the latter for more information.
pub struct RequestRef<'a> {
    pub version: ProtocolVersion,
    pub command: Command,
    pub destination: &'a Authority,
}

impl RequestRef<'_> {
    /// Write the client [`Request`] in binary format as specified by [RFC 1928] into the writer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write the client [`Request`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());
        buf.put_u8(self.command.into());
        buf.put_u8(0 /* RSV */);
        write_authority_to_buf(&self.destination, buf);
    }

    fn serialized_len(&self) -> usize {
        4 + authority_length(&self.destination)
    }
}

#[derive(Debug, Clone)]
/// Initial username-password negotiation starts with the client sending this request.
///
/// Once the SOCKS V5 server has started, and the client has selected the
/// Username/Password Authentication protocol, the Username/Password
/// subnegotiation begins.  This begins with the client producing a
/// Username/Password request:
///
/// ```plain
/// +----+------+----------+------+----------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +----+------+----------+------+----------+
/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +----+------+----------+------+----------+
/// ```
///
/// The VER field contains the current version of the subnegotiation,
/// which is X'01'. The ULEN field contains the length of the UNAME field
/// that follows. The UNAME field contains the username as known to the
/// source operating system. The PLEN field contains the length of the
/// PASSWD field that follows. The PASSWD field contains the password
/// association with the given UNAME.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc1929#section-2>
///
/// ## Security Considerations
///
/// Since the request carries the
/// password in cleartext, this subnegotiation is not recommended for
/// environments where "sniffing" is possible and practical.
pub struct UsernamePasswordRequest {
    pub version: UsernamePasswordSubnegotiationVersion,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl UsernamePasswordRequest {
    /// Read the client [`UsernamePasswordRequest`], decoded from binary format as specified by [RFC 1929] from the reader.
    ///
    /// [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let version: UsernamePasswordSubnegotiationVersion = r.read_u8().await?.into();
        match version {
            UsernamePasswordSubnegotiationVersion::One => (),
            UsernamePasswordSubnegotiationVersion::Unknown(version) => {
                return Err(ProtocolError::UnexpectedByte {
                    pos: 0,
                    byte: version.into(),
                });
            }
        }

        let username_length = r.read_u8().await?;
        if username_length == 0 {
            return Err(ProtocolError::UnexpectedByte {
                pos: 1,
                byte: username_length,
            });
        }
        let mut username = Vec::with_capacity(username_length as usize);
        r.read_exact(username.as_mut_slice()).await?;

        let password_length = r.read_u8().await?;
        if password_length == 0 {
            return Err(ProtocolError::UnexpectedByte {
                pos: (2 + (username_length as usize)),
                byte: password_length,
            });
        }
        let mut password = Vec::with_capacity(password_length as usize);
        r.read_exact(password.as_mut_slice()).await?;

        Ok(UsernamePasswordRequest {
            version,
            username,
            password,
        })
    }

    /// Write the client [`UsernamePasswordRequest`] in binary format as specified by [RFC 1929] into the writer.
    ///
    /// [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let self_ref = UsernamePasswordRequestRef {
            version: self.version,
            username: self.username.as_ref(),
            password: self.password.as_ref(),
        };
        self_ref.write_to(w).await
    }
}

#[derive(Debug, Clone)]
/// Initial username-password negotiation starts with the client sending this request.
///
/// Reference (write-only) version of [`UsernamePasswordRequest`],
/// see the latter for more information.
pub struct UsernamePasswordRequestRef<'a> {
    pub version: UsernamePasswordSubnegotiationVersion,
    pub username: &'a [u8],
    pub password: &'a [u8],
}

impl UsernamePasswordRequestRef<'_> {
    /// Write the client [`UsernamePasswordRequest`] in binary format as specified by [RFC 1929] into the writer.
    ///
    /// [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write the client [`UsernamePasswordRequest`] in binary format as specified by [RFC 1929] into the buffer.
    ///
    /// [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());

        debug_assert!(self.username.len() <= 255);
        buf.put_u8(self.username.len() as u8);
        buf.put_slice(&self.username[..]);

        debug_assert!(self.password.len() <= 255);
        buf.put_u8(self.password.len() as u8);
        buf.put_slice(&self.password[..]);
    }

    fn serialized_len(&self) -> usize {
        3 + self.username.len() + self.password.len()
    }
}

#[derive(Debug, Clone)]
/// Header for each datagram sent by a UDP Client.
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
pub struct UdpRequestHeader {
    pub fragment_number: u8,
    pub destination: Authority,
    pub data: Vec<u8>,
}

impl UdpRequestHeader {
    /// Read the client [`UdpRequestHeader`], decoded from binary format as specified by [RFC 1928] from the reader.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let _rsv = r.read_u16().await?;

        let fragment_number = r.read_u8().await?;

        let destination = read_authority(r).await?;

        let data_length = r.read_u8().await?;
        if data_length == 0 {
            return Err(ProtocolError::UnexpectedByte {
                pos: 4 + authority_length(&destination),
                byte: data_length,
            });
        }
        let mut data = Vec::with_capacity(data_length as usize);
        r.read_exact(data.as_mut_slice()).await?;

        Ok(UdpRequestHeader {
            fragment_number,
            destination,
            data,
        })
    }

    /// Write the client [`UdpRequestHeader`] in binary format as specified by [RFC 1928] into the writer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write the client [`UdpRequestHeader`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(0 /* RSV */);
        buf.put_u8(self.fragment_number);
        write_authority_to_buf(&self.destination, buf);

        debug_assert!(self.data.len() <= 255);
        buf.put_u8(self.data.len() as u8);
        buf.put_slice(&self.data[..]);
    }

    fn serialized_len(&self) -> usize {
        5 + authority_length(&self.destination) + self.data.len()
    }
}
