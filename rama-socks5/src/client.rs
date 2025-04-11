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
            HandshakeErrorKind::IO(err) => Some(
                err.source()
                    .unwrap_or(err as &(dyn std::error::Error + 'static)),
            ),
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
            ?selected_method,
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

        tracing::trace!(?selected_method, %destination, "socks5 client: connected");
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
                    selected_method = ?server_header.method,
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
            selected_method = ?server_header.method,
            "socks5 client: headers exchanged without auth",
        );

        if server_header.method != SocksMethod::NoAuthenticationRequired {
            return Err(HandshakeError::method_mismatch(server_header.method)
                .with_context("expected 'no auth required' method"));
        }

        Ok(SocksMethod::NoAuthenticationRequired)
    }
}
