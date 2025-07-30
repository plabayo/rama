//! Server implementation of the SOCKS5 Protocol [RFC 1928]
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

use std::net::IpAddr;

use super::{
    ProtocolError, ProtocolVersion, ReplyKind, SocksMethod, UsernamePasswordSubnegotiationVersion,
    common::{authority_length, read_authority, write_authority_to_buf},
};
use rama_core::bytes::{BufMut, BytesMut};
use rama_core::telemetry::tracing;
use rama_net::address::Authority;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Create a new server [`Header`].
    #[must_use]
    pub fn new(method: SocksMethod) -> Self {
        Self {
            version: ProtocolVersion::Socks5,
            method,
        }
    }

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
        tracing::trace!("write socks5 server headerr: on stack (w=2)");
        let mut buf = [0u8; 2];
        self.write_to_buf(&mut buf.as_mut_slice());
        w.write_all(&buf[..]).await
    }

    /// Write the server [`Header`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());
        buf.put_u8(self.method.into());
    }

    #[allow(unused)]
    #[allow(clippy::unused_self)]
    const fn serialized_len(&self) -> usize {
        1 + 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Create a new success [`Reply`].
    pub fn new(addr: impl Into<Authority>) -> Self {
        Self {
            version: ProtocolVersion::Socks5,
            reply: ReplyKind::Succeeded,
            bind_address: addr.into(),
        }
    }

    /// [`Reply`] with an error.
    #[must_use]
    pub fn error_reply(kind: ReplyKind) -> Self {
        Self {
            version: ProtocolVersion::Socks5,
            reply: kind,
            bind_address: Authority::default_ipv4(0),
        }
    }

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
                return Err(ProtocolError::unexpected_byte(0, version));
            }
        }

        let reply: ReplyKind = r.read_u8().await?.into();

        let rsv = r.read_u8().await?;
        if rsv != 0 {
            return Err(ProtocolError::unexpected_byte(2, rsv));
        }

        let bind_address = read_authority(r).await?;

        Ok(Self {
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
        let n = self.serialized_len();

        match self.bind_address.host() {
            rama_net::address::Host::Address(IpAddr::V4(_)) => {
                tracing::trace!("write socks5 server reply w/ Ipv4 addr: on stack (w={n})");
                debug_assert_eq!(4 + 4 + 2, n);
                let mut buf = [0u8; 10];
                self.write_to_buf(&mut buf.as_mut_slice());
                w.write_all(&buf[..]).await
            }
            rama_net::address::Host::Name(_) => {
                const SMALL_LEN: usize = 32 + 1 + 6;
                const MED_LEN: usize = 64 + 1 + 6;

                if n <= SMALL_LEN {
                    tracing::trace!(
                        "write socks5 server reply w/ (small) domain name: on stack (w={n})",
                    );
                    let mut buf = [0u8; SMALL_LEN];
                    self.write_to_buf(&mut buf.as_mut_slice());
                    w.write_all(&buf[..n]).await
                } else if n <= MED_LEN {
                    tracing::trace!(
                        "write socks5 server reply w/ (medium) domain name: on stack (w={n})",
                    );
                    let mut buf = [0u8; MED_LEN];
                    self.write_to_buf(&mut buf.as_mut_slice());
                    w.write_all(&buf[..n]).await
                } else {
                    tracing::trace!(
                        "write socks5 server reply w/ (large) domain name: on heap (w={n})"
                    );
                    let mut buf = BytesMut::with_capacity(n);
                    self.write_to_buf(&mut buf);
                    w.write_all(&buf).await
                }
            }
            rama_net::address::Host::Address(IpAddr::V6(_)) => {
                tracing::trace!("write socks5 server reply w/ Ipv6 addr: on stack (w={n})");
                debug_assert_eq!(4 + 16 + 2, n);
                let mut buf = [0u8; 22];
                self.write_to_buf(&mut buf.as_mut_slice());
                w.write_all(&buf[..]).await
            }
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    #[must_use]
    pub fn new_success() -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            status: 0,
        }
    }

    /// Create a new failure [`UsernamePasswordResponse`] to indicate
    /// the received credentials are partial or invalid otherwise.
    #[must_use]
    pub fn new_invalid_credentails() -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            status: 1,
        }
    }

    /// Create a new failure [`UsernamePasswordResponse`] to indicate
    /// no user cound be found for the given credentials.
    #[must_use]
    pub fn new_user_not_found() -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            status: 2,
        }
    }

    /// Create a new [`UsernamePasswordResponse`]
    /// to indicate the user couldn't be authorized
    /// as the authorization used by the server is unavailable.
    #[must_use]
    pub fn new_auth_system_unavailable() -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            status: 4,
        }
    }

    /// Indicates if the (auth) response from the server indicates success.
    #[must_use]
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
                return Err(ProtocolError::unexpected_byte(0, version));
            }
        }

        let status = r.read_u8().await?;

        Ok(Self { version, status })
    }

    /// Write the server [`UsernamePasswordResponse`] in binary format as specified by [RFC 1928] into the writer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        tracing::trace!("write socks5 server headerr: on stack (w=2)");
        let mut buf = [0u8; 2];
        self.write_to_buf(&mut buf.as_mut_slice());
        w.write_all(&buf[..]).await
    }

    /// Write the server [`UsernamePasswordResponse`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());
        buf.put_u8(self.status);
    }

    #[allow(unused)]
    #[allow(clippy::unused_self)]
    fn serialized_len(&self) -> usize {
        1 + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::test_write_read_eq;

    #[tokio::test]
    async fn test_header_write_read_eq() {
        test_write_read_eq!(Header::new(SocksMethod::JSONParameterBlock), Header,);
    }

    #[tokio::test]
    async fn test_reply_write_read_eq() {
        test_write_read_eq!(
            Reply {
                version: ProtocolVersion::Socks5,
                reply: ReplyKind::Succeeded,
                bind_address: Authority::default_ipv4(4128)
            },
            Reply,
        );

        test_write_read_eq!(Reply::error_reply(ReplyKind::ConnectionNotAllowed), Reply,);
    }

    #[tokio::test]
    async fn test_username_password_response_write_read_eq() {
        test_write_read_eq!(
            UsernamePasswordResponse::new_success(),
            UsernamePasswordResponse,
        );
        test_write_read_eq!(
            UsernamePasswordResponse::new_invalid_credentails(),
            UsernamePasswordResponse,
        );
    }
}
