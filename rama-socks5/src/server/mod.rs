//! Socks5 Server Implementation for Rama.
//!
//! See [`Socks5Acceptor`] for more information,
//! its [`Default`] implementation only
//! supports the [`Command::Connect`] method using the [`DefaultConnector`],
//! but custom connectors as well as binders and udp associators
//! are optionally possible.

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
pub use connect::{Connector, DefaultConnector, Socks5Connector};

mod bind;
pub use bind::Socks5Binder;

mod udp;
pub use udp::Socks5UdpAssociator;

/// Socks5 server implementation of [RFC 1928]
///
/// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
///
/// An instance constructed with [`Socks5Acceptor::new`]
/// is one that accepts none of the available [`Command`]s,
/// until you embed one or more of: connector, binder and udp associator.
///
/// # [`Default`]
///
/// The [`Default`] implementation of the [`Socks5Acceptor`] only
/// supports the [`Command::Connect`] method using the [`DefaultConnector`],
/// but custom connectors as well as binders and udp associators
/// are optionally possible.
pub struct Socks5Acceptor<C = DefaultConnector, B = (), U = ()> {
    connector: C,
    binder: B,
    udp_associator: U,

    // TODO: replace with proper auth support
    // <https://github.com/plabayo/rama/issues/496>
    auth: Option<Socks5Auth>,

    // opt-in flag which allows even if server has auth configured
    // to also support a client which doesn't support username-password auth,
    // despite it normally working with authentication.
    //
    // This can be useful in case you also wish to support guest users.
    auth_opt: bool,
}

impl Socks5Acceptor<(), (), ()> {
    /// Create a new [`Socks5Acceptor`] which supports none of the valid [`Command`]s.
    ///
    /// Use [`Socks5Acceptor::default`] instead if you wish to create a default
    /// [`Socks5Acceptor`] which can be used as a simple and honest byte-byte proxy.
    pub fn new() -> Self {
        Self {
            connector: (),
            binder: (),
            udp_associator: (),
            auth: None,
            auth_opt: false,
        }
    }
}

impl<C, B, U> Socks5Acceptor<C, B, U> {
    rama_utils::macros::generate_field_setters!(auth, Socks5Auth);

    /// Define whether or not the authentication (if supported by this [`Socks5Acceptor`]) is optional,
    /// by default it is no optional.
    ///
    /// Making authentication optional, despite supporting authentication on server side,
    /// can be useful in case you wish to support so called Guest users.
    pub fn set_auth_optional(&mut self, optional: bool) -> &mut Self {
        self.auth_opt = optional;
        self
    }

    /// Define whether or not the authentication (if supported by this [`Socks5Acceptor`]) is optional,
    /// by default it is no optional.
    ///
    /// Making authentication optional, despite supporting authentication on server side,
    /// can be useful in case you wish to support so called Guest users.
    pub fn with_auth_optional(mut self, optional: bool) -> Self {
        self.auth_opt = optional;
        self
    }
}

impl<B, U> Socks5Acceptor<(), B, U> {
    /// Attach a [`Socks5Connector`] to this [`Socks5Acceptor`],
    /// used to accept incoming [`Command::Connect`] [`client::Request`]s.
    ///
    /// Use [`Socks5Acceptor::with_default_connector`] in case you
    /// the [`DefaultConnector`] serves your needs just fine.
    pub fn with_connector<C>(self, connector: C) -> Socks5Acceptor<C, B, U> {
        Socks5Acceptor {
            connector,
            binder: self.binder,
            udp_associator: self.udp_associator,
            auth: self.auth,
            auth_opt: self.auth_opt,
        }
    }

    /// Attach a the [`DefaultConnector`] to this [`Socks5Acceptor`],
    /// used to accept incoming [`Command::Connect`] [`client::Request`]s.
    ///
    /// Use [`Socks5Acceptor::with_connector`] in case you want to use a custom
    /// [`Socks5Connector`] or customised [`Connector`].
    #[inline]
    pub fn with_default_connector(self) -> Socks5Acceptor<DefaultConnector, B, U> {
        self.with_connector(DefaultConnector::default())
    }
}

impl Default for Socks5Acceptor {
    #[inline]
    fn default() -> Self {
        Socks5Acceptor::new().with_default_connector()
    }
}

impl<C: fmt::Debug, B: fmt::Debug, U: fmt::Debug> fmt::Debug for Socks5Acceptor<C, B, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Acceptor")
            .field("connector", &self.connector)
            .field("binder", &self.binder)
            .field("udp_associator", &self.udp_associator)
            .field("auth", &self.auth)
            .field("auth_opt", &self.auth_opt)
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
            auth_opt: self.auth_opt,
        }
    }
}

#[derive(Debug)]
/// Server-side error returned in case of a failure during the handshake process.
pub struct Error {
    kind: ErrorKind,
    context: ErrorContext,
}

#[derive(Debug)]
enum ErrorContext {
    None,
    Message(&'static str),
    ReplyKind(ReplyKind),
}

impl From<&'static str> for ErrorContext {
    fn from(value: &'static str) -> Self {
        ErrorContext::Message(value)
    }
}

impl From<ReplyKind> for ErrorContext {
    fn from(value: ReplyKind) -> Self {
        ErrorContext::ReplyKind(value)
    }
}

impl Error {
    fn io(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::IO(err),
            context: ErrorContext::None,
        }
    }

    fn protocol(value: ProtocolError) -> Self {
        Self {
            kind: ErrorKind::Protocol(value),
            context: ErrorContext::None,
        }
    }

    fn aborted(reason: &'static str) -> Self {
        Self {
            kind: ErrorKind::Aborted(reason),
            context: ErrorContext::None,
        }
    }

    fn service(error: impl Into<BoxError>) -> Self {
        Self {
            kind: ErrorKind::Service(error.into()),
            context: ErrorContext::None,
        }
    }

    fn with_context(mut self, context: impl Into<ErrorContext>) -> Self {
        self.context = context.into();
        self
    }
}

#[derive(Debug)]
enum ErrorKind {
    IO(std::io::Error),
    Protocol(ProtocolError),
    Aborted(&'static str),
    Service(BoxError),
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorContext::Message(message) => write!(f, "{message}"),
            ErrorContext::ReplyKind(kind) => write!(f, "reply: {kind}"),
            ErrorContext::None => write!(f, "no context"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let context = &self.context;
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
    B: Socks5Binder,
    U: Socks5UdpAssociator,
{
    pub async fn accept<S, State>(&self, ctx: Context<State>, mut stream: S) -> Result<(), Error>
    where
        C: Socks5Connector<S, State>,
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
                Err(Error::aborted("unknown command not supported")
                    .with_context(ReplyKind::CommandNotSupported))
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
                } else if self.auth_opt && methods.contains(&SocksMethod::NoAuthenticationRequired)
                {
                    tracing::trace!(
                        "socks5 server: auth supported but optional: skipping auth as client does not support username-passowrd auth",
                    );

                    Header::new(SocksMethod::NoAuthenticationRequired)
                        .write_to(stream)
                        .await
                        .map_err(|err| {
                            Error::io(err).with_context("write server reply: no auth required")
                        })?;

                    return Ok(SocksMethod::NoAuthenticationRequired);
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

#[cfg(test)]
mod test {
    use rama_net::address::Authority;

    use super::*;
    use crate::server::connect::MockConnector;

    #[tokio::test]
    async fn test_socks5_acceptor_no_auth_client_connect_failure_method_not_supported() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x01\x00")
            // server header
            .write(b"\x05\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .build();

        let server = Socks5Acceptor::new();
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_auth_flow_declined_connect_failure_method_not_supported() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x02\x00\x02")
            // server header
            .write(b"\x05\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .build();

        let server = Socks5Acceptor::new();
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_auth_flow_used_connect_failure_method_not_supported() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x02\x00\x02")
            // server header
            .write(b"\x05\x02")
            // client username-password request
            .read(b"\x01\x04john\x06secret")
            // server username-password response
            .write(b"\x01\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .build();

        let server =
            Socks5Acceptor::new().with_auth(Socks5Auth::username_password("john", "secret"));
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_auth_flow_username_only_sed_connect_failure_method_not_supported()
    {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x02\x00\x02")
            // server header
            .write(b"\x05\x02")
            // client username-password request
            .read(b"\x01\x04john\x00")
            // server username-password response
            .write(b"\x01\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .build();

        let server = Socks5Acceptor::new().with_auth(Socks5Auth::username("john"));
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_auth_flow_used_connect_failure_unauthorized() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x02\x00\x02")
            // server header
            .write(b"\x05\x02")
            // client username-password request
            .read(b"\x01\x03jan\x06secret")
            // server username-password response
            .write(b"\x01\x01")
            .build();

        let server =
            Socks5Acceptor::new().with_auth(Socks5Auth::username_password("john", "secret"));
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_auth_flow_used_connect_failure_unauthorized_missing_password() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x02\x00\x02")
            // server header
            .write(b"\x05\x02")
            // client username-password request
            .read(b"\x01\x04john\x00")
            // server username-password response
            .write(b"\x01\x01")
            .build();

        let server =
            Socks5Acceptor::new().with_auth(Socks5Auth::username_password("john", "secret"));
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_no_auth_client_connect_mock_failure() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x01\x00")
            // server header
            .write(b"\x05\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            .build();

        let server = Socks5Acceptor::new()
            .with_connector(MockConnector::new_err(ReplyKind::ConnectionRefused));
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_no_auth_client_connect_mock_success_no_data() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x01\x00")
            // server header
            .write(b"\x05\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
            .build();

        let server =
            Socks5Acceptor::new().with_connector(MockConnector::new(Authority::local_ipv4(42)));
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_no_auth_client_connect_mock_success_with_data() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x01\x00")
            // server header
            .write(b"\x05\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
            // client data
            .read(b"ping")
            // server data
            .write(b"pong")
            .build();

        let server = Socks5Acceptor::new().with_connector(
            MockConnector::new(Authority::local_ipv4(42)).with_proxy_data(
                tokio_test::io::Builder::new()
                    // client data
                    .write(b"ping")
                    // server data
                    .read(b"pong")
                    .build(),
            ),
        );
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_with_auth_flow_client_connect_mock_success_with_data() {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x02\x00\x02")
            // server header
            .write(b"\x05\x02")
            // client username-password request
            .read(b"\x01\x04john\x06secret")
            // server username-password response
            .write(b"\x01\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
            // client data
            .read(b"ping")
            // server data
            .write(b"pong")
            .build();

        let server = Socks5Acceptor::new()
            .with_auth(Socks5Auth::username_password("john", "secret"))
            .with_connector(
                MockConnector::new(Authority::local_ipv4(42)).with_proxy_data(
                    tokio_test::io::Builder::new()
                        // client data
                        .write(b"ping")
                        // server data
                        .read(b"pong")
                        .build(),
                ),
            );
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_socks5_acceptor_with_auth_flow_username_only_client_connect_mock_success_with_data()
     {
        let stream = tokio_test::io::Builder::new()
            // client header
            .read(b"\x05\x02\x00\x02")
            // server header
            .write(b"\x05\x02")
            // client username-password request
            .read(b"\x01\x04john\x00")
            // server username-password response
            .write(b"\x01\x00")
            // client request
            .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            // server reply
            .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
            // client data
            .read(b"ping")
            // server data
            .write(b"pong")
            .build();

        let server = Socks5Acceptor::new()
            .with_auth(Socks5Auth::username("john"))
            .with_connector(
                MockConnector::new(Authority::local_ipv4(42)).with_proxy_data(
                    tokio_test::io::Builder::new()
                        // client data
                        .write(b"ping")
                        // server data
                        .read(b"pong")
                        .build(),
                ),
            );
        let result = server.accept(Context::default(), stream).await;
        assert!(result.is_ok());
    }
}
