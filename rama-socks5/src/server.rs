use std::fmt;

use crate::{
    Socks5Auth,
    proto::{
        Command, ProtocolError, ProtocolVersion, ReplyKind, SocksMethod,
        UsernamePasswordSubnegotiationVersion, client,
        server::{Header, Reply, UsernamePasswordResponse},
    },
};
use rama_net::{address::Authority, stream::Stream};

#[derive(Debug, Clone, Default)]
/// Socks5 server implementation of [RFC 1928]
///
/// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
pub struct Socks5Acceptor {
    // TODO: replace with proper auth support
    // <https://github.com/plabayo/rama/issues/496>
    auth: Option<Socks5Auth>,
}

#[derive(Debug)]
/// Server-side error returned in case of a failure during the handshake process.
pub struct HandshakeError {
    kind: HandshakeErrorKind,
}

impl HandshakeError {
    fn aborted(reason: &'static str) -> Self {
        Self {
            kind: HandshakeErrorKind::Aborted(reason),
        }
    }
}

#[derive(Debug)]
enum HandshakeErrorKind {
    IO(std::io::Error),
    Protocol(ProtocolError),
    Aborted(&'static str),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            HandshakeErrorKind::IO(error) => {
                write!(f, "server: handshake eror: I/O: {error}")
            }
            HandshakeErrorKind::Protocol(error) => {
                write!(f, "server: handshake eror: protocol error: {error}")
            }
            HandshakeErrorKind::Aborted(reason) => {
                write!(f, "server: handshake eror: aborted: {reason}")
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
            HandshakeErrorKind::Aborted(_) => None,
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

impl Socks5Acceptor {
    rama_utils::macros::generate_field_setters!(auth, Socks5Auth);

    pub async fn accept<S: Stream + Unpin>(&self, stream: &mut S) -> Result<(), HandshakeError> {
        let client_header = client::Header::read_from(stream).await?;
        let negotiated_method = self.handle_method(&client_header.methods, stream).await?;

        tracing::trace!(
            client_methods = ?client_header.methods,
            ?negotiated_method,
            "socks5 server: headers exchanged"
        );

        let client_request = client::Request::read_from(stream).await?;
        tracing::trace!(
            client_methods = ?client_header.methods,
            ?negotiated_method,
            command = ?client_request.command,
            destination = ?client_request.destination,
            "socks5 server: client request received"
        );

        match client_request.command {
            Command::Connect => {
                self.accept_connect(stream, client_header, negotiated_method, client_request)
                    .await
            }
            Command::Bind => {
                self.accept_bind(stream, client_header, negotiated_method, client_request)
                    .await
            }
            Command::UdpAssociate => {
                self.accept_udp_associate(stream, client_header, negotiated_method, client_request)
                    .await
            }
            Command::Unknown(_) => {
                self.accept_unknown(stream, client_header, negotiated_method, client_request)
                    .await
            }
        }
    }

    async fn handle_method<S: Stream + Unpin>(
        &self,
        methods: &[SocksMethod],
        stream: &mut S,
    ) -> Result<SocksMethod, HandshakeError> {
        match self.auth.as_ref() {
            Some(Socks5Auth::UsernamePassword { username, password }) => {
                if methods.contains(&SocksMethod::UsernamePassword) {
                    Header {
                        version: ProtocolVersion::Socks5,
                        method: SocksMethod::UsernamePassword,
                    }
                    .write_to(stream)
                    .await?;

                    let client_auth_req =
                        client::UsernamePasswordRequest::read_from(stream).await?;
                    if username.eq(&client_auth_req.username)
                        && password.eq(&client_auth_req.password)
                    {
                        UsernamePasswordResponse {
                            version: UsernamePasswordSubnegotiationVersion::One,
                            // TODO: define constants, there must be pseudo standards about this
                            status: 0,
                        }
                        .write_to(stream)
                        .await?;
                        Ok(SocksMethod::UsernamePassword)
                    } else {
                        UsernamePasswordResponse {
                            version: UsernamePasswordSubnegotiationVersion::One,
                            // TODO: define constants, there must be pseudo standards about this
                            status: 1,
                        }
                        .write_to(stream)
                        .await?;
                        Err(HandshakeError::aborted(
                            "username-password: client unauthorized",
                        ))
                    }
                } else {
                    Header {
                        version: ProtocolVersion::Socks5,
                        method: SocksMethod::NoAcceptableMethods,
                    }
                    .write_to(stream)
                    .await?;
                    Err(HandshakeError::aborted(
                        "username-password required but client doesn't support the method",
                    ))
                }
            }
            None => {
                if methods.contains(&SocksMethod::NoAuthenticationRequired) {
                    Header {
                        version: ProtocolVersion::Socks5,
                        method: SocksMethod::NoAuthenticationRequired,
                    }
                    .write_to(stream)
                    .await?;

                    return Ok(SocksMethod::NoAuthenticationRequired);
                }

                Header {
                    version: ProtocolVersion::Socks5,
                    method: SocksMethod::NoAcceptableMethods,
                }
                .write_to(stream)
                .await?;
                Err(HandshakeError::aborted("no acceptable methods"))
            }
        }
    }

    async fn accept_connect<S: Stream + Unpin>(
        &self,
        stream: &mut S,
        header: client::Header,
        negotiated_method: SocksMethod,
        request: client::Request,
    ) -> Result<(), HandshakeError> {
        tracing::debug!(
            client_methods = ?header.methods,
                ?negotiated_method,
                command = ?request.command,
                destination = ?request.destination,
                command = ?Command::Connect,
                "socks5 server: abort: command not supported: Connect",
        );

        Reply {
            version: ProtocolVersion::Socks5,
            reply: ReplyKind::CommandNotSupported,
            bind_address: Authority::default_ipv4(0),
        }
        .write_to(stream)
        .await?;
        Err(HandshakeError::aborted("command not supported: Connect"))
    }

    async fn accept_bind<S: Stream + Unpin>(
        &self,
        stream: &mut S,
        header: client::Header,
        negotiated_method: SocksMethod,
        request: client::Request,
    ) -> Result<(), HandshakeError> {
        tracing::debug!(
            client_methods = ?header.methods,
                ?negotiated_method,
                command = ?request.command,
                destination = ?request.destination,
                command = ?Command::Bind,
                "socks5 server: abort: command not supported: Bind",
        );

        Reply {
            version: ProtocolVersion::Socks5,
            reply: ReplyKind::CommandNotSupported,
            bind_address: Authority::default_ipv4(0),
        }
        .write_to(stream)
        .await?;
        Err(HandshakeError::aborted("command not supported: Bind"))
    }

    async fn accept_udp_associate<S: Stream + Unpin>(
        &self,
        stream: &mut S,
        header: client::Header,
        negotiated_method: SocksMethod,
        request: client::Request,
    ) -> Result<(), HandshakeError> {
        tracing::debug!(
            client_methods = ?header.methods,
                ?negotiated_method,
                command = ?request.command,
                destination = ?request.destination,
                command = ?Command::UdpAssociate,
                "socks5 server: abort: command not supported: UDP Associate",
        );

        Reply {
            version: ProtocolVersion::Socks5,
            reply: ReplyKind::CommandNotSupported,
            bind_address: Authority::default_ipv4(0),
        }
        .write_to(stream)
        .await?;
        Err(HandshakeError::aborted(
            "command not supported: UDP Associate",
        ))
    }

    async fn accept_unknown<S: Stream + Unpin>(
        &self,
        stream: &mut S,
        header: client::Header,
        negotiated_method: SocksMethod,
        request: client::Request,
    ) -> Result<(), HandshakeError> {
        tracing::debug!(
            client_methods = ?header.methods,
                ?negotiated_method,
                command = ?request.command,
                destination = ?request.destination,
                command = ?request.command,
                "socks5 server: abort: unknown command not supported",
        );

        Reply {
            version: ProtocolVersion::Socks5,
            reply: ReplyKind::CommandNotSupported,
            bind_address: Authority::default_ipv4(0),
        }
        .write_to(stream)
        .await?;
        Err(HandshakeError::aborted("unknown command not supported"))
    }
}
