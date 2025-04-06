//! Server implementation of the SOCKS5 Protocol [RFC 1928]
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

use super::{
    ProtocolError, ProtocolVersion, ReplyKind, SocksMethod, UsernamePasswordSubnegotiationVersion,
    common::{authority_length, read_authority, write_authority_to_buf},
};
use bytes::{BufMut, BytesMut};
use rama_net::address::Authority;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
/// The server selects from one of the methods given in METHODS, and
/// sends a header back containing the selected METHOD and same Protocol vesion.
///
/// ```plain
/// +-----+--------+
/// | VER | METHOD |
/// +-----+--------+
/// |  1  |   1    |
/// +-----+--------+
/// ```
pub struct Header {
    pub version: ProtocolVersion,
    pub method: SocksMethod,
}

impl Header {
    /// Read the server [`Header`], decoded from binary format as specified by [RFC 1928] from the reader.
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
                    byte: version,
                });
            }
        }

        let method: SocksMethod = r.read_u8().await?.into();

        Ok(Self { version, method })
    }

    /// Write the server [`Header`] in binary format as specified by [RFC 1928] into the writer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await?;

        Ok(())
    }

    /// Write the server [`Header`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());
        buf.put_u8(self.method.into());
    }

    #[allow(clippy::unused_self)]
    const fn serialized_len(&self) -> usize {
        1 + 1
    }
}

#[derive(Debug, Clone)]
/// Sent by the server as a reply on an earlier client request.
///
/// The SOCKS request information is sent by the client as soon as it has
/// established a connection to the SOCKS server, and completed the
/// authentication negotiations.  The server evaluates the request, and
/// returns a reply formed as follows:
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
///
/// If the chosen method includes encapsulation for purposes of
/// authentication, integrity and/or confidentiality, the replies are
/// encapsulated in the method-dependent encapsulation.
pub struct Reply {
    pub version: ProtocolVersion,
    pub reply: ReplyKind,
    pub bind_address: Authority,
}

impl Reply {
    /// Read the server [`Reply`], decoded from binary format as specified by [RFC 1928] from the reader.
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
                    byte: version,
                });
            }
        }

        let reply: ReplyKind = r.read_u8().await?.into();

        let rsv = r.read_u8().await?;
        if rsv != 0 {
            return Err(ProtocolError::UnexpectedByte { pos: 2, byte: rsv });
        }

        let bind_address = read_authority(r).await?;

        Ok(Reply {
            version,
            reply,
            bind_address,
        })
    }

    /// Write the server [`Reply`] in binary format as specified by [RFC 1928] into the writer.
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

    /// Write the server [`Reply`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());
        buf.put_u8(self.reply.into());
        buf.put_u8(0 /* RSV */);
        write_authority_to_buf(&self.bind_address, buf);
    }

    fn serialized_len(&self) -> usize {
        4 + authority_length(&self.bind_address)
    }
}

#[derive(Debug, Clone)]
/// Response to the username-password request sent by the client.
///
/// he server verifies the supplied UNAME and PASSWD, and sends the
/// following response:
///
/// ```plain
/// +----+--------+
/// |VER | STATUS |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
///
/// A STATUS field of X'00' indicates success. If the server returns a
/// `failure' (STATUS value other than X'00') status, it MUST close the
/// connection.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc1929#section-2>
pub struct UsernamePasswordResponse {
    pub version: UsernamePasswordSubnegotiationVersion,
    pub status: u8,
}

impl UsernamePasswordResponse {
    /// Create a new [`UsernamePasswordResponse`] to indicate success.
    pub fn new_success() -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            status: 0,
        }
    }

    /// Create a new failure [`UsernamePasswordResponse`] to indicate
    /// the received credentials are partial or invalid otherwise.
    pub fn new_invalid_credentails() -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            status: 1,
        }
    }

    /// Create a new failure [`UsernamePasswordResponse`] to indicate
    /// no user cound be found for the given credentials.
    pub fn new_user_not_found() -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            status: 2,
        }
    }

    /// Create a new [`UsernamePasswordResponse`]
    /// to indicate the user couldn't be authorized
    /// as the authorization used by the server is unavailable.
    pub fn new_auth_system_unavailable() -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            status: 4,
        }
    }

    /// Indicates if the (auth) response from the server indicates success.
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

impl UsernamePasswordResponse {
    /// Read the server [`UsernamePasswordResponse`], decoded from binary format as specified by [RFC 1928] from the reader.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
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
                    byte: version,
                });
            }
        }

        let status = r.read_u8().await?;

        Ok(UsernamePasswordResponse { version, status })
    }

    /// Write the server [`UsernamePasswordResponse`] in binary format as specified by [RFC 1928] into the writer.
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

    /// Write the server [`UsernamePasswordResponse`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());
        buf.put_u8(self.status);
    }

    #[allow(clippy::unused_self)]
    fn serialized_len(&self) -> usize {
        2
    }
}
