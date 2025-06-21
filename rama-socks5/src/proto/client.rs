//! Client implementation of the SOCKS5 Protocol [RFC 1928]
//! and username-password protocol extension [RFC 1929].
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
//! [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929

use std::{fmt, net::IpAddr};

use super::{
    Command, ProtocolError, ProtocolVersion, SocksMethod, UsernamePasswordSubnegotiationVersion,
    common::{authority_length, read_authority, write_authority_to_buf},
};
use rama_core::bytes::{BufMut, BytesMut};
use rama_core::telemetry::tracing;
use rama_net::address::Authority;
use smallvec::{SmallVec, smallvec};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn new(methods: impl Into<SmallVec<[SocksMethod; 2]>>) -> Self {
        Self {
            version: ProtocolVersion::Socks5,
            methods: methods.into(),
        }
    }

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
                    byte: version,
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
        let n = self.serialized_len();
        if n == 3 {
            tracing::trace!("write socks5 client header w/ 1 method: on stack (w={n})");
            let mut buf = [0u8; 3];
            self.write_to_buf(&mut buf.as_mut_slice());
            w.write_all(&buf[..]).await
        } else if n == 4 {
            tracing::trace!("write socks5 client header w/ 2 methods: on stack (w={n})");
            let mut buf = [0u8; 4];
            self.write_to_buf(&mut buf.as_mut_slice());
            w.write_all(&buf[..]).await
        } else if n == 5 {
            tracing::trace!("write socks5 client header w/ 3 methods: on stack (w={n})");
            let mut buf = [0u8; 5];
            self.write_to_buf(&mut buf.as_mut_slice());
            w.write_all(&buf[..]).await
        } else {
            tracing::trace!("write socks5 client header w/ > 3 methods: on heap (w={n})",);
            let mut buf = BytesMut::with_capacity(n);
            self.write_to_buf(&mut buf);
            w.write_all(&buf).await
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
                    byte: version,
                });
            }
        }

        let command: Command = r.read_u8().await?.into();

        let rsv = r.read_u8().await?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// The SOCKS request sent by the client.
///
/// Reference (write-only) version of [`Request`],
/// see the latter for more information.
pub struct RequestRef<'a> {
    pub version: ProtocolVersion,
    pub command: Command,
    pub destination: &'a Authority,
}

impl PartialEq<Request> for RequestRef<'_> {
    fn eq(&self, other: &Request) -> bool {
        self.version == other.version
            && self.command == other.command
            && self.destination.eq(&other.destination)
    }
}

impl PartialEq<RequestRef<'_>> for Request {
    #[inline]
    fn eq(&self, other: &RequestRef<'_>) -> bool {
        other == self
    }
}

impl<'a> RequestRef<'a> {
    pub fn new(command: Command, destination: &'a Authority) -> Self {
        Self {
            version: ProtocolVersion::Socks5,
            command,
            destination,
        }
    }
}

impl RequestRef<'_> {
    /// Write the client [`Request`] in binary format as specified by [RFC 1928] into the writer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let n = self.serialized_len();

        match self.destination.host() {
            rama_net::address::Host::Address(IpAddr::V4(_)) => {
                tracing::trace!("write socks5 client request w/ Ipv4 addr: on stack (w={n})");
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
                        "write socks5 client request w/ (small) domain name: on stack (w={n})",
                    );
                    let mut buf = [0u8; SMALL_LEN];
                    self.write_to_buf(&mut buf.as_mut_slice());
                    w.write_all(&buf[..n]).await
                } else if n <= MED_LEN {
                    tracing::trace!(
                        "write socks5 client request w/ (medium) domain name: on stack (w={n})",
                    );
                    let mut buf = [0u8; MED_LEN];
                    self.write_to_buf(&mut buf.as_mut_slice());
                    w.write_all(&buf[..n]).await
                } else {
                    tracing::trace!(
                        "write socks5 client request w/ (large) domain name: on heap (w={n})"
                    );
                    let mut buf = BytesMut::with_capacity(n);
                    self.write_to_buf(&mut buf);
                    w.write_all(&buf).await
                }
            }
            rama_net::address::Host::Address(IpAddr::V6(_)) => {
                tracing::trace!("write socks5 client request w/ Ipv6 addr: on stack (w={n})");
                debug_assert_eq!(4 + 16 + 2, n);
                let mut buf = [0u8; 22];
                self.write_to_buf(&mut buf.as_mut_slice());
                w.write_all(&buf[..]).await
            }
        }
    }

    /// Write the client [`Request`] in binary format as specified by [RFC 1928] into the buffer.
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());
        buf.put_u8(self.command.into());
        buf.put_u8(0 /* RSV */);
        write_authority_to_buf(self.destination, buf);
    }

    fn serialized_len(&self) -> usize {
        4 + authority_length(self.destination)
    }
}

#[derive(Clone, PartialEq, Eq)]
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
    pub password: Option<Vec<u8>>,
}

impl fmt::Debug for UsernamePasswordRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsernamePasswordRequest")
            .field("version", &self.username)
            .field("username", &self.username)
            .field("password_defined", &self.password.is_some())
            .finish()
    }
}

impl UsernamePasswordRequest {
    /// Create a new [`UsernamePasswordRequest`].
    pub fn new(username: impl Into<Vec<u8>>, password: impl Into<Vec<u8>>) -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            username: username.into(),
            password: Some(password.into()),
        }
    }

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
                    byte: version,
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
        let mut username = vec![0u8; username_length as usize];
        r.read_exact(username.as_mut_slice()).await?;

        let password_length = r.read_u8().await?;
        let password = if password_length == 0 {
            None
        } else {
            let mut password = vec![0u8; password_length as usize];
            r.read_exact(password.as_mut_slice()).await?;
            Some(password)
        };

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
            password: self.password.as_deref(),
        };
        self_ref.write_to(w).await
    }
}

#[derive(Clone, PartialEq, Eq)]
/// Initial username-password negotiation starts with the client sending this request.
///
/// Reference (write-only) version of [`UsernamePasswordRequest`],
/// see the latter for more information.
pub struct UsernamePasswordRequestRef<'a> {
    pub version: UsernamePasswordSubnegotiationVersion,
    pub username: &'a [u8],
    pub password: Option<&'a [u8]>,
}

impl fmt::Debug for UsernamePasswordRequestRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsernamePasswordRequestRef")
            .field("version", &self.username)
            .field("username", &self.username)
            .field("password_defined", &self.password.is_some())
            .finish()
    }
}

impl PartialEq<UsernamePasswordRequest> for UsernamePasswordRequestRef<'_> {
    fn eq(&self, other: &UsernamePasswordRequest) -> bool {
        self.version == other.version
            && self.username == other.username
            && self.password == other.password.as_deref()
    }
}

impl PartialEq<UsernamePasswordRequestRef<'_>> for UsernamePasswordRequest {
    #[inline]
    fn eq(&self, other: &UsernamePasswordRequestRef<'_>) -> bool {
        other == self
    }
}

impl<'a> UsernamePasswordRequestRef<'a> {
    pub fn new(username: &'a [u8], password: &'a [u8]) -> Self {
        Self {
            version: UsernamePasswordSubnegotiationVersion::One,
            username,
            password: Some(password),
        }
    }

    /// Write the client [`UsernamePasswordRequest`] in binary format as specified by [RFC 1929] into the writer.
    ///
    /// [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        const SMALL_LEN: usize = 3 + 8 + 8;
        const MED_LEN: usize = 3 + 16 + 16;
        const LARGE_LEN: usize = 3 + 32 + 32;

        let n = self.serialized_len();

        if n <= SMALL_LEN {
            tracing::trace!(
                "write socks5 Username/Password request w/ (small) credentials: on stack (w={n})"
            );
            let mut buf = [0u8; SMALL_LEN];
            self.write_to_buf(&mut buf.as_mut_slice());
            w.write_all(&buf[..n]).await
        } else if n <= MED_LEN {
            tracing::trace!(
                "write socks5 Username/Password request w/ (medium) credentials: on stack (w={n})"
            );
            let mut buf = [0u8; MED_LEN];
            self.write_to_buf(&mut buf.as_mut_slice());
            w.write_all(&buf[..n]).await
        } else if n <= LARGE_LEN {
            tracing::trace!(
                "write socks5 Username/Password request w/ (large) credentials: on stack (w={n})"
            );
            let mut buf = [0u8; LARGE_LEN];
            self.write_to_buf(&mut buf.as_mut_slice());
            w.write_all(&buf[..n]).await
        } else {
            tracing::trace!(
                "write socks5 Username/Password request w/ (jumbo) credentials: on heap (w={n})"
            );
            let mut buf = BytesMut::with_capacity(n);
            self.write_to_buf(&mut buf);
            w.write_all(&buf).await
        }
    }

    /// Write the client [`UsernamePasswordRequest`] in binary format as specified by [RFC 1929] into the buffer.
    ///
    /// [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.version.into());

        debug_assert!((1..=255).contains(&self.username.len()));
        buf.put_u8(self.username.len() as u8);
        buf.put_slice(self.username);

        match self.password {
            Some(password) => {
                if password.is_empty() {
                    buf.put_u8(0)
                } else {
                    debug_assert!((1..=255).contains(&password.len()));
                    buf.put_u8(password.len() as u8);
                    buf.put_slice(password);
                }
            }
            None => buf.put_u8(0),
        }
    }

    fn serialized_len(&self) -> usize {
        3 + self.username.len() + self.password.map(|p| p.len()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::test_write_read_eq;
    use rama_net::address::{Domain, Host};

    use super::*;

    #[tokio::test]
    async fn test_header_write_read_eq() {
        test_write_read_eq!(
            Header::new(smallvec::smallvec![SocksMethod::NoAuthenticationRequired]),
            Header,
        );
        test_write_read_eq!(
            Header::new([SocksMethod::NoAuthenticationRequired, SocksMethod::GSSAPI]),
            Header,
        );
    }

    #[tokio::test]
    async fn test_request_write_read_eq() {
        test_write_read_eq!(
            Request {
                version: ProtocolVersion::Socks5,
                command: Command::Connect,
                destination: Authority::local_ipv4(1234)
            },
            Request,
        );

        test_write_read_eq!(
            Request {
                version: ProtocolVersion::Socks5,
                command: Command::Connect,
                destination: Authority::local_ipv6(1450)
            },
            Request,
        );

        test_write_read_eq!(
            RequestRef {
                version: ProtocolVersion::Socks5,
                command: Command::Bind,
                destination: &Authority::new(Host::Name(Domain::example()), 1450),
            },
            Request,
        );
    }

    #[tokio::test]
    async fn test_username_password_request_write_read_eq() {
        test_write_read_eq!(
            UsernamePasswordRequest::new("john", "secret"),
            UsernamePasswordRequest,
        );

        test_write_read_eq!(
            UsernamePasswordRequestRef {
                version: UsernamePasswordSubnegotiationVersion::One,
                username: b"a",
                password: Some(b"b"),
            },
            UsernamePasswordRequest,
        );

        test_write_read_eq!(
            UsernamePasswordRequestRef {
                version: UsernamePasswordSubnegotiationVersion::One,
                username: b"adasdadadadadsadasdasdasdasddada",
                password: Some(b"bdafasdfdasdadasfsfsfdsasdasdsadsadsad"),
            },
            UsernamePasswordRequest,
        );

        test_write_read_eq!(
            UsernamePasswordRequestRef {
                version: UsernamePasswordSubnegotiationVersion::One,
                username: b"a",
                password: None,
            },
            UsernamePasswordRequest,
        );
    }
}
