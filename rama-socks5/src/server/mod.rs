//! Socks5 Server Implementation for Rama.

use crate::{
    Socks5Auth,
    proto::{
        Command, ProtocolError, ReplyKind, SocksMethod, client,
        server::{Header, Reply, UsernamePasswordResponse},
    },
};
use rama_core::{Context, error::BoxError};
use rama_net::stream::Stream;
use std::fmt;

mod connect;
pub use connect::Socks5Connector;

mod bind;
pub use bind::Socks5Binder;

mod udp;
pub use udp::Socks5UdpAssociator;

/// Socks5 server implementation of [RFC 1928]
///
/// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
pub struct Socks5Acceptor<C = (), B = (), U = ()> {
    connector: C,
    binder: B,
    udp_associator: U,

    // TODO: replace with proper auth support
    // <https://github.com/plabayo/rama/issues/496>
    auth: Option<Socks5Auth>,
}

impl<C: fmt::Debug, B: fmt::Debug, U: fmt::Debug> fmt::Debug for Socks5Acceptor<C, B, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Acceptor")
            .field("connector", &self.connector)
            .field("binder", &self.binder)
            .field("udp_associator", &self.udp_associator)
            .field("auth", &self.auth)
            .finish()
    }
}

impl<C: Clone, B: Clone, U: Clone> Clone for Socks5Acceptor<C, B, U> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            binder: self.binder.clone(),
            udp_associator: self.udp_associator.clone(),
            auth: self.auth.clone(),
        }
    }
}

#[derive(Debug)]
/// Server-side error returned in case of a failure during the handshake process.
pub struct Error {
    kind: ErrorKind,
    context: Option<&'static str>,
}

impl Error {
    fn io(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::IO(err),
            context: None,
        }
    }

    fn protocol(value: ProtocolError) -> Self {
        Self {
            kind: ErrorKind::Protocol(value),
            context: None,
        }
    }

    fn aborted(reason: &'static str) -> Self {
        Self {
            kind: ErrorKind::Aborted(reason),
            context: None,
        }
    }

    fn with_context(mut self, context: &'static str) -> Self {
        self.context = Some(context);
        self
    }
}

#[derive(Debug)]
enum ErrorKind {
    IO(std::io::Error),
    Protocol(ProtocolError),
    Aborted(&'static str),
    #[expect(dead_code)]
    Service(BoxError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let context = self.context.unwrap_or("no context");
        match &self.kind {
            ErrorKind::IO(error) => {
                write!(f, "server: handshake eror: I/O: {error} ({context})")
            }
            ErrorKind::Protocol(error) => {
                write!(
                    f,
                    "server: handshake eror: protocol error: {error} ({context})"
                )
            }
            ErrorKind::Aborted(reason) => {
                write!(f, "server: handshake eror: aborted: {reason} ({context})")
            }
            ErrorKind::Service(error) => {
                write!(f, "server: service eror: {error} ({context})")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::IO(err) => Some(
                err.source()
                    .unwrap_or(err as &(dyn std::error::Error + 'static)),
            ),
            ErrorKind::Protocol(err) => Some(
                err.source()
                    .unwrap_or(err as &(dyn std::error::Error + 'static)),
            ),
            ErrorKind::Aborted(_) => None,
            ErrorKind::Service(err) => err.source(),
        }
    }
}

impl<C, B, U> Socks5Acceptor<C, B, U>
where
    C: Socks5Connector,
    B: Socks5Binder,
    U: Socks5UdpAssociator,
{
    rama_utils::macros::generate_field_setters!(auth, Socks5Auth);

    pub async fn accept<S, State>(&self, ctx: Context<State>, mut stream: S) -> Result<(), Error>
    where
        S: Stream + Unpin,
        State: Clone + Send + Sync + 'static,
    {
        let client_header = client::Header::read_from(&mut stream)
            .await
            .map_err(|err| Error::protocol(err).with_context("read client header"))?;

        let negotiated_method = self
            .handle_method(&client_header.methods, &mut stream)
            .await?;

        tracing::trace!(
            client_methods = ?client_header.methods,
            ?negotiated_method,
            "socks5 server: headers exchanged"
        );

        let client_request = client::Request::read_from(&mut stream)
            .await
            .map_err(|err| Error::protocol(err).with_context("read client request"))?;
        tracing::trace!(
            client_methods = ?client_header.methods,
            ?negotiated_method,
            command = ?client_request.command,
            destination = %client_request.destination,
            "socks5 server: client request received"
        );

        match client_request.command {
            Command::Connect => {
                self.connector
                    .accept_connect(ctx, stream, client_request.destination)
                    .await
            }
            Command::Bind => {
                self.binder
                    .accept_bind(ctx, stream, client_request.destination)
                    .await
            }
            Command::UdpAssociate => {
                self.udp_associator
                    .accept_udp_associate(ctx, stream, client_request.destination)
                    .await
            }
            Command::Unknown(_) => {
                tracing::debug!(
                    client_methods = ?client_header.methods,
                    ?negotiated_method,
                    command = ?client_request.command,
                    destination = %client_request.destination,
                    "socks5 server: abort: unknown command not supported",
                );

                Reply::error_reply(ReplyKind::CommandNotSupported)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err)
                            .with_context("write server reply: unknown command not supported")
                    })?;
                Err(Error::aborted("unknown command not supported"))
            }
        }
    }

    async fn handle_method<S: Stream + Unpin>(
        &self,
        methods: &[SocksMethod],
        stream: &mut S,
    ) -> Result<SocksMethod, Error> {
        match self.auth.as_ref() {
            Some(Socks5Auth::UsernamePassword { username, password }) => {
                if methods.contains(&SocksMethod::UsernamePassword) {
                    Header::new(SocksMethod::UsernamePassword)
                        .write_to(stream)
                        .await
                        .map_err(|err| {
                            Error::io(err)
                                .with_context("write server reply: auth (username-password)")
                        })?;

                    let client_auth_req = client::UsernamePasswordRequest::read_from(stream)
                        .await
                        .map_err(|err| {
                            Error::protocol(err).with_context(
                                "read client auth sub-negotiation request: username-password",
                            )
                        })?;
                    if username.eq(&client_auth_req.username)
                        && password.eq(&client_auth_req.password)
                    {
                        UsernamePasswordResponse::new_success()
                            .write_to(stream)
                            .await
                            .map_err(|err| {
                                Error::io(err).with_context(
                                    "write server auth sub-negotiation success response",
                                )
                            })?;
                        Ok(SocksMethod::UsernamePassword)
                    } else {
                        UsernamePasswordResponse::new_invalid_credentails()
                            .write_to(stream)
                            .await
                            .map_err(|err| {
                                Error::io(err).with_context(
                                    "write server auth sub-negotiation error response: unauthorized",
                                )
                            })?;
                        Err(Error::aborted("username-password: client unauthorized"))
                    }
                } else {
                    Header::new(SocksMethod::NoAcceptableMethods)
                    .write_to(stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context(
                            "write server auth sub-negotiation error response: no acceptable methods",
                        )
                    })?;
                    Err(Error::aborted(
                        "username-password required but client doesn't support the method (auth == required)",
                    ))
                }
            }
            None => {
                if methods.contains(&SocksMethod::NoAuthenticationRequired) {
                    Header::new(SocksMethod::NoAuthenticationRequired)
                        .write_to(stream)
                        .await
                        .map_err(|err| {
                            Error::io(err).with_context("write server reply: no auth required")
                        })?;

                    return Ok(SocksMethod::NoAuthenticationRequired);
                }

                Header::new(SocksMethod::NoAcceptableMethods)
                    .write_to(stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context(
                        "write server auth sub-negotiation error response: no acceptable methods",
                    )
                    })?;
                Err(Error::aborted("no acceptable methods"))
            }
        }
    }
}
