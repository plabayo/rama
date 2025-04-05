use std::fmt;

use crate::{
    Socks5Auth,
    proto::{
        Command, ProtocolError, ProtocolVersion, ReplyKind, SocksMethod,
        UsernamePasswordSubnegotiationVersion,
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
        match &self.kind {
            HandshakeErrorKind::IO(error) => {
                write!(f, "client: handshake eror: I/O: {error}")
            }
            HandshakeErrorKind::Protocol(error) => {
                write!(f, "client: handshake eror: protocol error: {error}")
            }
            HandshakeErrorKind::MethodMismatch(method) => {
                write!(f, "client: handshake error: method mistmatch: {method:?}")
            }
            HandshakeErrorKind::Reply(reply) => {
                write!(f, "client: handshake error: error reply: {reply:?}")
            }
            HandshakeErrorKind::Unauthorized(status) => {
                write!(f, "client: handshake error: unauthorized: {status}")
            }
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            HandshakeErrorKind::IO(err) => Some(
                err.source()
                    .unwrap_or_else(|| err as &(dyn std::error::Error + 'static)),
            ),
            HandshakeErrorKind::Protocol(err) => Some(
                err.source()
                    .unwrap_or_else(|| err as &(dyn std::error::Error + 'static)),
            ),
            HandshakeErrorKind::MethodMismatch(_)
            | HandshakeErrorKind::Reply(_)
            | HandshakeErrorKind::Unauthorized(_) => None,
        }
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(value: std::io::Error) -> Self {
        Self {
            kind: HandshakeErrorKind::IO(value),
        }
    }
}

impl From<ProtocolError> for HandshakeError {
    fn from(value: ProtocolError) -> Self {
        Self {
            kind: HandshakeErrorKind::Protocol(value),
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
        let client_method = self
            .auth
            .as_ref()
            .map(|a| a.socks5_method())
            .unwrap_or(SocksMethod::NoAuthenticationRequired);
        let header = Header {
            version: ProtocolVersion::Socks5,
            methods: smallvec::smallvec![client_method],
        };
        header.write_to(stream).await?;

        tracing::trace!(?client_method, "socks5 client: header written");

        let server_header = server::Header::read_from(stream).await?;
        if server_header.method != client_method {
            return Err(HandshakeError {
                kind: HandshakeErrorKind::MethodMismatch(server_header.method),
            });
        }

        tracing::trace!(?client_method, "socks5 client: headers exchanged");

        let request = RequestRef {
            version: ProtocolVersion::Socks5,
            command: Command::Connect,
            destination,
        };
        request.write_to(stream).await?;

        tracing::trace!(
            ?client_method,
            ?destination,
            "socks5 client: client request sent"
        );

        let server_reply = server::Reply::read_from(stream).await?;
        if server_reply.reply != ReplyKind::Succeeded {
            return Err(HandshakeError {
                kind: HandshakeErrorKind::Reply(server_reply.reply),
            });
        }

        tracing::trace!(
            ?client_method,
            ?destination,
            "socks5 client: handshake succeeded"
        );

        if let Some(auth) = self.auth.as_ref() {
            match auth {
                Socks5Auth::UsernamePassword { username, password } => {
                    UsernamePasswordRequestRef {
                        version: UsernamePasswordSubnegotiationVersion::One,
                        username: username.as_ref(),
                        password: password.as_ref(),
                    }
                    .write_to(stream)
                    .await?;

                    tracing::trace!(
                        ?client_method,
                        ?destination,
                        "socks5 client: username-password request sent"
                    );

                    let auth_reply = server::UsernamePasswordResponse::read_from(stream).await?;
                    if auth_reply.status != 0 {
                        return Err(HandshakeError {
                            kind: HandshakeErrorKind::Unauthorized(auth_reply.status),
                        });
                    }

                    tracing::trace!(
                        ?client_method,
                        ?destination,
                        "socks5 client: authorized using username-password"
                    );
                }
            }
        }

        tracing::trace!(?client_method, ?destination, "socks5 client: connected");
        Ok(server_reply.bind_address)
    }
}
