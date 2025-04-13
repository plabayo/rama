use std::fmt;

use crate::{
    Socks5Auth,
    proto::{
        Command, ProtocolError, ReplyKind, SocksMethod, UsernamePasswordSubnegotiationVersion,
        client::{Header, RequestRef, UsernamePasswordRequestRef},
        server,
    },
};
use rama_net::{address::Authority, stream::Stream};

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
}

#[derive(Debug)]
/// Client-side error returned in case of a failure during the handshake process.
pub struct HandshakeError {
    kind: HandshakeErrorKind,
    context: Option<&'static str>,
}

impl HandshakeError {
    fn io(err: std::io::Error) -> Self {
        Self {
            kind: HandshakeErrorKind::IO(err),
            context: None,
        }
    }

    fn protocol(value: ProtocolError) -> Self {
        Self {
            kind: HandshakeErrorKind::Protocol(value),
            context: None,
        }
    }

    fn reply_kind(kind: ReplyKind) -> Self {
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

    fn with_context(mut self, context: &'static str) -> Self {
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
            | HandshakeErrorKind::MethodMismatch(_) => ReplyKind::GeneralServerFailure,
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
            | HandshakeErrorKind::Unauthorized(_) => None,
        }
    }
}

impl Client {
    rama_utils::macros::generate_field_setters!(auth, Socks5Auth);

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
    use rama_net::address::Host;

    use super::*;

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
}
