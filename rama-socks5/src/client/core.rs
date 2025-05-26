use crate::{
    Socks5Auth,
    client::udp::UdpSocketRelayBinder,
    proto::{
        Command, ProtocolError, ProtocolVersion, ReplyKind, SocksMethod,
        UsernamePasswordSubnegotiationVersion,
        client::{Header, Request, RequestRef, UsernamePasswordRequestRef},
        server::{self, Reply},
    },
};
use rama_core::error::BoxError;
use rama_net::{
    address::{Authority, Host, SocketAddress},
    stream::Stream,
};
use rama_utils::macros::generate_field_setters;
use std::fmt;

use super::bind::Binder;

#[derive(Debug, Clone, Default)]
/// Socks5 client implementation of [RFC 1928]
///
/// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
pub struct Client {
    auth: Option<Socks5Auth>,
}

impl Client {
    /// Creates a new socks5 [`Client`].
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    generate_field_setters!(auth, Socks5Auth);
}

#[derive(Debug)]
/// Client-side error returned in case of a failure during the handshake process.
pub struct HandshakeError {
    kind: HandshakeErrorKind,
    context: Option<&'static str>,
}

impl HandshakeError {
    pub(crate) fn io(err: std::io::Error) -> Self {
        Self {
            kind: HandshakeErrorKind::IO(err),
            context: None,
        }
    }

    pub(crate) fn other(err: impl Into<BoxError>) -> Self {
        Self {
            kind: HandshakeErrorKind::Other(err.into()),
            context: None,
        }
    }

    pub(crate) fn protocol(value: ProtocolError) -> Self {
        Self {
            kind: HandshakeErrorKind::Protocol(value),
            context: None,
        }
    }

    pub(crate) fn reply_kind(kind: ReplyKind) -> Self {
        Self {
            kind: HandshakeErrorKind::Reply(kind),
            context: None,
        }
    }

    fn method_mismatch(method: SocksMethod) -> Self {
        Self {
            kind: HandshakeErrorKind::MethodMismatch(method),
            context: None,
        }
    }

    fn unauthorized(status: u8) -> Self {
        Self {
            kind: HandshakeErrorKind::Unauthorized(status),
            context: None,
        }
    }

    pub(crate) fn with_context(mut self, context: &'static str) -> Self {
        self.context = Some(context);
        self
    }
}

impl HandshakeError {
    /// [`ReplyKind::GeneralServerFailure`] is returned in case of an error
    /// that is returned in case no reply was received from the (socks5) server.
    pub fn reply(&self) -> ReplyKind {
        match self.kind {
            HandshakeErrorKind::IO(_)
            | HandshakeErrorKind::Protocol(_)
            | HandshakeErrorKind::MethodMismatch(_)
            | HandshakeErrorKind::Other(_) => ReplyKind::GeneralServerFailure,
            HandshakeErrorKind::Unauthorized(_) => ReplyKind::ConnectionNotAllowed,
            HandshakeErrorKind::Reply(reply_kind) => reply_kind,
        }
    }
}

#[derive(Debug)]
enum HandshakeErrorKind {
    IO(std::io::Error),
    Protocol(ProtocolError),
    MethodMismatch(SocksMethod),
    Reply(ReplyKind),
    Unauthorized(u8),
    Other(BoxError),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let context = self.context.unwrap_or("no context");
        match &self.kind {
            HandshakeErrorKind::IO(error) => {
                write!(f, "client: handshake eror: I/O: {error} ({context})")
            }
            HandshakeErrorKind::Protocol(error) => {
                write!(
                    f,
                    "client: handshake eror: protocol error: {error} ({context})"
                )
            }
            HandshakeErrorKind::MethodMismatch(method) => {
                write!(
                    f,
                    "client: handshake error: method mistmatch: {method:?} ({context})"
                )
            }
            HandshakeErrorKind::Reply(reply) => {
                write!(
                    f,
                    "client: handshake error: error reply: {reply:?} ({context})"
                )
            }
            HandshakeErrorKind::Unauthorized(status) => {
                write!(
                    f,
                    "client: handshake error: unauthorized: {status} ({context})"
                )
            }
            HandshakeErrorKind::Other(error) => {
                write!(f, "client: handshake eror: other: {error} ({context})")
            }
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            HandshakeErrorKind::IO(err) => Some(err as &(dyn std::error::Error + 'static)),
            HandshakeErrorKind::Protocol(err) => Some(
                err.source()
                    .unwrap_or(err as &(dyn std::error::Error + 'static)),
            ),
            HandshakeErrorKind::MethodMismatch(_)
            | HandshakeErrorKind::Reply(_)
            | HandshakeErrorKind::Unauthorized(_)
            | HandshakeErrorKind::Other(_) => None,
        }
    }
}

impl Client {
    /// Establish a connection with a Socks5 server making use of the [`Command::Connect`] flow.
    ///
    /// In case the handshake was sucessfull it will return
    /// the local address used by the Socks5 (proxy) server
    /// to connect to the destination [`Authority`] on behalf of this [`Client`].
    pub async fn handshake_connect<S: Stream + Unpin>(
        &self,
        stream: &mut S,
        destination: &Authority,
    ) -> Result<Authority, HandshakeError> {
        let selected_method = match self.auth.as_ref() {
            Some(auth) => self.handshake_headers_auth(stream, auth).await?,
            None => self.handshake_headers_no_auth(stream).await?,
        };

        let request = RequestRef::new(Command::Connect, destination);
        request
            .write_to(stream)
            .await
            .map_err(|err| HandshakeError::io(err).with_context("write client request: connect"))?;

        tracing::trace!(
            %selected_method,
            %destination,
            "socks5 client: client request sent"
        );

        let server_reply = server::Reply::read_from(stream)
            .await
            .map_err(|err| HandshakeError::protocol(err).with_context("read server reply"))?;
        if server_reply.reply != ReplyKind::Succeeded {
            return Err(HandshakeError::reply_kind(server_reply.reply)
                .with_context("server responded with non-success reply"));
        }

        tracing::trace!(%selected_method, %destination, "socks5 client: connected");
        Ok(server_reply.bind_address)
    }

    /// Establish a connection with a Socks5 server making use of the [`Command::Bind`] flow.
    ///
    /// Usually you do not request a bind address yourself, but for some special-purpose or local
    /// setups it might be desired that the client requests a specific bind interface to the server.
    ///
    /// Note that the server is free to ignore this request, even when requested.
    /// You can use [`Binder::selected_bind_address`] to compare it with [`Binder::requested_bind_address`]
    /// in case your special purpose use-case requires the client's bind address choice to be respected.
    ///
    /// This method returns a [`Binder`] that contains the address to which the target server
    /// is to connect to the socks5 server on behalf of the client (callee of this call).
    /// The [`Binder`] takes ownership over of the input [`Stream`] such that it can
    /// await the established connection from target server to socks5 server.
    pub async fn handshake_bind<S: Stream + Unpin>(
        &self,
        mut stream: S,
        requested_bind_address: Option<SocketAddress>,
    ) -> Result<Binder<S>, HandshakeError> {
        let selected_method = match self.auth.as_ref() {
            Some(auth) => self.handshake_headers_auth(&mut stream, auth).await?,
            None => self.handshake_headers_no_auth(&mut stream).await?,
        };

        let destination = requested_bind_address.unwrap_or_else(|| SocketAddress::local_ipv4(0));

        let request = Request {
            version: ProtocolVersion::Socks5,
            command: Command::Bind,
            destination: destination.into(),
        };
        request
            .write_to(&mut stream)
            .await
            .map_err(|err| HandshakeError::io(err).with_context("write client request: bind"))?;

        tracing::trace!(
            requested_bind_address = %destination,
            %selected_method,
            "socks5 client: bind handshake initiated"
        );

        let server_reply = server::Reply::read_from(&mut stream)
            .await
            .map_err(|err| HandshakeError::protocol(err).with_context("read server reply"))?;
        if server_reply.reply != ReplyKind::Succeeded {
            return Err(HandshakeError::reply_kind(server_reply.reply)
                .with_context("server responded with non-success reply"));
        }

        let (select_host, selected_port) = server_reply.bind_address.into_parts();
        let selected_addr = match select_host {
            Host::Name(domain) => {
                tracing::debug!(
                    %domain,
                    "bind command response does not accept domain as bind address",
                );
                let reply_kind = ReplyKind::AddressTypeNotSupported;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        HandshakeError::io(err).with_context("read server response: bind failed")
                    })?;
                return Err(
                    HandshakeError::reply_kind(ReplyKind::AddressTypeNotSupported)
                        .with_context("selected bind addr cannot be a domain name"),
                );
            }
            Host::Address(ip_addr) => ip_addr,
        };
        let selected_bind_address = SocketAddress::new(selected_addr, selected_port);

        tracing::trace!(
            %selected_method,
            requested_bind_address = %destination,
            %selected_bind_address,
            "socks5 client: socks5 server ready to bind",
        );

        Ok(Binder::new(
            stream,
            requested_bind_address,
            selected_bind_address,
        ))
    }

    /// Establish a connection with a Socks5 server making use of the [`Command::UdpAssociate`] flow.
    ///
    /// This method returns a [`UdpSocketRelayBinder`] that can be used
    /// to bind to an interface as to get a [`UdpSocketRelay`] ready to to send udp packets through
    /// socks5 proxy server to the required.
    pub async fn handshake_udp<S: Stream + Unpin>(
        &self,
        mut stream: S,
    ) -> Result<UdpSocketRelayBinder<S>, HandshakeError> {
        let selected_method = match self.auth.as_ref() {
            Some(auth) => self.handshake_headers_auth(&mut stream, auth).await?,
            None => self.handshake_headers_no_auth(&mut stream).await?,
        };

        tracing::trace!(
            %selected_method,
            "socks5 client: ready for udp association",
        );

        Ok(UdpSocketRelayBinder::new(stream))
    }

    async fn handshake_headers_auth<S: Stream + Unpin>(
        &self,
        stream: &mut S,
        auth: &Socks5Auth,
    ) -> Result<SocksMethod, HandshakeError> {
        let auth_method = auth.socks5_method();
        let header = Header::new([SocksMethod::NoAuthenticationRequired, auth_method]);
        header.write_to(stream).await.map_err(|err| {
            HandshakeError::io(err).with_context("write client header: with auth method")
        })?;
        let methods = header.methods;

        tracing::trace!(?methods, "socks5 client: header with auth written");

        let server_header = server::Header::read_from(stream).await.map_err(|err| {
            HandshakeError::protocol(err).with_context("read server header (auth?)")
        })?;

        tracing::trace!(
            ?methods,
            selected_method = ?server_header.method,
            "socks5 client: headers exchanged with auth as a provided method",
        );

        if server_header.method == SocksMethod::NoAuthenticationRequired {
            // all good, but server is fine without auth
            return Ok(SocksMethod::NoAuthenticationRequired);
        }

        if server_header.method != auth_method {
            return Err(HandshakeError::method_mismatch(server_header.method)
                .with_context("unsolicited auth method"));
        }

        tracing::trace!(
            ?methods,
            selected_method = ?server_header.method,
            "socks5 client: auth sub-negotation started",
        );

        match auth {
            Socks5Auth::UsernamePassword { username, password } => {
                UsernamePasswordRequestRef {
                    version: UsernamePasswordSubnegotiationVersion::One,
                    username: username.as_ref(),
                    password: password.as_deref(),
                }
                .write_to(stream)
                .await
                .map_err(|err| {
                    HandshakeError::io(err).with_context(
                        "write client sub-negotiation request: username-password auth",
                    )
                })?;

                tracing::trace!(
                    ?methods,
                    selected_method = ?server_header.method,
                    "socks5 client: username-password request sent"
                );

                let auth_reply = server::UsernamePasswordResponse::read_from(stream)
                    .await
                    .map_err(|err| {
                        HandshakeError::protocol(err).with_context(
                            "read server sub-negotiation response: username-password auth",
                        )
                    })?;
                if !auth_reply.success() {
                    return Err(HandshakeError::unauthorized(auth_reply.status));
                }

                tracing::trace!(
                    ?methods,
                    selected_method = %server_header.method,
                    "socks5 client: authorized using username-password"
                );
            }
        }

        Ok(auth_method)
    }

    async fn handshake_headers_no_auth<S: Stream + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<SocksMethod, HandshakeError> {
        let header = Header::new(smallvec::smallvec![SocksMethod::NoAuthenticationRequired]);
        header.write_to(stream).await.map_err(|err| {
            HandshakeError::io(err).with_context("write client headers: no auth required")
        })?;
        let methods = header.methods;

        tracing::trace!(?methods, "socks5 client: header without auth written");

        let server_header = server::Header::read_from(stream).await.map_err(|err| {
            HandshakeError::protocol(err).with_context("read server headers: no auth required (?)")
        })?;

        tracing::trace!(
            ?methods,
            selected_method = %server_header.method,
            "socks5 client: headers exchanged without auth",
        );

        if server_header.method != SocksMethod::NoAuthenticationRequired {
            return Err(HandshakeError::method_mismatch(server_header.method)
                .with_context("expected 'no auth required' method"));
        }

        Ok(SocksMethod::NoAuthenticationRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_net::address::Host;

    #[tokio::test]
    async fn test_client_handshake_connect_no_auth_failure_command_not_supported() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x01\x00")
            // server header
            .read(b"\x05\x00")
            // client request
            .write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .read(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .build();

        let client = Client::new();
        let err = client
            .handshake_connect(&mut stream, &Authority::default_ipv4(0))
            .await
            .unwrap_err();
        assert_eq!(err.reply(), ReplyKind::CommandNotSupported);
    }

    #[tokio::test]
    async fn test_client_handshake_connect_auth_error_guest() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x01\x00")
            // server header
            .read(b"\x05\xff")
            .build();

        let client = Client::default();
        let err = client
            .handshake_connect(&mut stream, &Authority::default_ipv4(0))
            .await
            .unwrap_err();
        assert_eq!(err.reply(), ReplyKind::GeneralServerFailure);
    }

    #[tokio::test]
    async fn test_client_handshake_connect_auth_not_used_by_server_failure_command_not_supported() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x02\x00\x02")
            // server header
            .read(b"\x05\x00")
            // client request
            .write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .read(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .build();

        let client = Client::default().with_auth(Socks5Auth::username_password("john", "secret"));
        let err = client
            .handshake_connect(&mut stream, &Authority::default_ipv4(0))
            .await
            .unwrap_err();
        assert_eq!(err.reply(), ReplyKind::CommandNotSupported);
    }

    #[tokio::test]
    async fn test_client_handshake_connect_with_auth_flow_failure_command_not_supported() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x02\x00\x02")
            // server header
            .read(b"\x05\x02")
            // client username-password request
            .write("\x01\x04john\x06secret".as_bytes())
            // server username-password response
            .read(b"\x01\x00")
            // client request
            .write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .read(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .build();

        let client = Client::default().with_auth(Socks5Auth::username_password("john", "secret"));
        let err = client
            .handshake_connect(&mut stream, &Authority::default_ipv4(0))
            .await
            .unwrap_err();
        assert_eq!(err.reply(), ReplyKind::CommandNotSupported);
    }

    #[tokio::test]
    async fn test_client_handshake_connect_with_auth_flow_failure_invalid_credentials() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x02\x00\x02")
            // server header
            .read(b"\x05\x02")
            // client username-password request
            .write("\x01\x04john\x06secret".as_bytes())
            // server username-password response
            .read(b"\x01\x01")
            .build();

        let client = Client::default().with_auth(Socks5Auth::username_password("john", "secret"));
        let err = client
            .handshake_connect(&mut stream, &Authority::default_ipv4(0))
            .await
            .unwrap_err();
        assert_eq!(err.reply(), ReplyKind::ConnectionNotAllowed);
    }

    #[tokio::test]
    async fn test_client_handshake_connect_failure_method_mismatch() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x01\x00")
            // server header
            .read(b"\x05\x02")
            .build();

        let client = Client::default();
        let err = client
            .handshake_connect(&mut stream, &Authority::default_ipv4(0))
            .await
            .unwrap_err();
        assert_eq!(err.reply(), ReplyKind::GeneralServerFailure);
    }

    #[tokio::test]
    async fn test_client_handshake_connect_guest_connect_established() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x01\x00")
            // server header
            .read(b"\x05\x00")
            // client request
            .write(&[
                b'\x05', b'\x01', b'\x00', b'\x04', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 1,
            ])
            // server reply
            .read(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 65])
            .build();

        let client = Client::default();
        let local_addr = client
            .handshake_connect(&mut stream, &Authority::local_ipv6(1))
            .await
            .unwrap();
        assert_eq!(local_addr, Authority::local_ipv4(65));
    }

    #[tokio::test]
    async fn test_client_handshake_connect_guest_connect_established_domain() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x01\x00")
            // server header
            .read(b"\x05\x00")
            // client request
            .write("\x05\x01\x00\x03\x0bexample.com\x00\x01".as_bytes())
            // server reply
            .read(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 1])
            .build();

        let client = Client::default();
        let local_addr = client
            .handshake_connect(&mut stream, &Authority::new(Host::EXAMPLE_NAME, 1))
            .await
            .unwrap();
        assert_eq!(local_addr, Authority::local_ipv4(1));
    }

    #[tokio::test]
    async fn test_client_handshake_connect_guest_connect_established_domain_with_auth_flow() {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x02\x00\x02")
            // server header
            .read(b"\x05\x02")
            // client username-password request
            .write(b"\x01\x04john\x06secret")
            // server username-password response
            .read(b"\x01\x00")
            // client request
            .write(b"\x05\x01\x00\x03\x0bexample.com\x00\x01")
            // server reply
            .read(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 1])
            .build();

        let client = Client::default().with_auth(Socks5Auth::username_password("john", "secret"));
        let local_addr = client
            .handshake_connect(&mut stream, &Authority::new(Host::EXAMPLE_NAME, 1))
            .await
            .unwrap();
        assert_eq!(local_addr, Authority::local_ipv4(1));
    }

    #[tokio::test]
    async fn test_client_handshake_connect_guest_connect_established_domain_with_auth_flow_username_only()
     {
        let mut stream = tokio_test::io::Builder::new()
            // client header
            .write(b"\x05\x02\x00\x02")
            // server header
            .read(b"\x05\x02")
            // client username-password request
            .write(b"\x01\x04john\x00")
            // server username-password response
            .read(b"\x01\x00")
            // client request
            .write(b"\x05\x01\x00\x03\x0bexample.com\x00\x01")
            // server reply
            .read(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 1])
            .build();

        let client = Client::default().with_auth(Socks5Auth::username("john"));
        let local_addr = client
            .handshake_connect(&mut stream, &Authority::new(Host::EXAMPLE_NAME, 1))
            .await
            .unwrap();
        assert_eq!(local_addr, Authority::local_ipv4(1));
    }
}
