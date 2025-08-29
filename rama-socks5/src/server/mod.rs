//! Socks5 Server Implementation for Rama.
//!
//! See [`Socks5Acceptor`] for more information,
//! its [`Default`] implementation only
//! supports the [`Command::Connect`] method using the [`DefaultConnector`],
//! but custom connectors as well as binders and udp associators
//! are optionally possible.
//!
//! For MITM socks5 proxies you can use [`LazyConnector`] as the
//! connector service of [`Socks5Acceptor`].

use crate::proto::{
    Command, ProtocolError, ReplyKind, SocksMethod, client,
    server::{Header, Reply, UsernamePasswordResponse},
};
use rama_core::{Context, Service, context::Extensions, error::BoxError, telemetry::tracing};
use rama_net::{
    socket::Interface,
    stream::Stream,
    user::{self, authority::Authorizer},
};
use rama_tcp::{TcpStream, server::TcpListener};
use std::fmt;

mod peek;
#[doc(inline)]
pub use peek::{NoSocks5RejectError, Socks5PeekRouter, Socks5PeekStream};

mod connect;
pub use connect::{Connector, DefaultConnector, LazyConnector, Socks5Connector};

pub mod bind;
pub use bind::{Binder, DefaultBinder, Socks5Binder};

pub mod udp;
pub use udp::{DefaultUdpRelay, Socks5UdpAssociator, UdpRelay};

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
pub struct Socks5Acceptor<C = DefaultConnector, B = (), U = (), A = ()> {
    connector: C,
    binder: B,
    udp_associator: U,

    auth: AuthKind<A>,

    // opt-in flag which allows even if server has auth configured
    // to also support a client which doesn't support username-password auth,
    // despite it normally working with authentication.
    //
    // This can be useful in case you also wish to support guest users.
    auth_opt: bool,
}

enum AuthKind<A> {
    NoAuth(A),
    WithAuth(A),
}

impl<A: fmt::Debug> fmt::Debug for AuthKind<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAuth(auth) => write!(f, "AuthKind::NoAuth({auth:?})"),
            Self::WithAuth(auth) => write!(f, "AuthKind::WithAuth({auth:?})"),
        }
    }
}

impl<A: Clone> Clone for AuthKind<A> {
    fn clone(&self) -> Self {
        match self {
            Self::NoAuth(auth) => Self::NoAuth(auth.clone()),
            Self::WithAuth(auth) => Self::WithAuth(auth.clone()),
        }
    }
}

impl Socks5Acceptor<(), (), (), ()> {
    /// Create a new [`Socks5Acceptor`] which supports none of the valid [`Command`]s.
    ///
    /// Use [`Socks5Acceptor::default`] instead if you wish to create a default
    /// [`Socks5Acceptor`] which can be used as a simple and honest byte-byte proxy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connector: (),
            binder: (),
            udp_associator: (),
            auth: AuthKind::NoAuth(()),
            auth_opt: false,
        }
    }
}

impl<C, B, U> Socks5Acceptor<C, B, U> {
    pub fn with_authorizer<A>(self, authorizer: A) -> Socks5Acceptor<C, B, U, A> {
        Socks5Acceptor {
            connector: self.connector,
            binder: self.binder,
            udp_associator: self.udp_associator,
            auth: AuthKind::WithAuth(authorizer),
            auth_opt: self.auth_opt,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define whether or not the authentication (if supported by this [`Socks5Acceptor`]) is optional,
        /// by default it is no optional.
        ///
        /// Making authentication optional, despite supporting authentication on server side,
        /// can be useful in case you wish to support so called Guest users.
        pub fn auth_optional(mut self, optional: bool) -> Self {
            self.auth_opt = optional;
            self
        }
    }
}

impl<B, U, A> Socks5Acceptor<(), B, U, A> {
    /// Attach a [`Socks5Connector`] to this [`Socks5Acceptor`],
    /// used to accept incoming [`Command::Connect`] [`client::Request`]s.
    ///
    /// Use [`Socks5Acceptor::with_default_connector`] in case
    /// the [`DefaultConnector`] serves your needs just fine.
    pub fn with_connector<C>(self, connector: C) -> Socks5Acceptor<C, B, U, A> {
        Socks5Acceptor {
            connector,
            binder: self.binder,
            udp_associator: self.udp_associator,
            auth: self.auth,
            auth_opt: self.auth_opt,
        }
    }

    /// Attach the [`DefaultConnector`] to this [`Socks5Acceptor`],
    /// used to accept incoming [`Command::Connect`] [`client::Request`]s.
    ///
    /// Use [`Socks5Acceptor::with_connector`] in case you want to use a custom
    /// [`Socks5Connector`] or customised [`Connector`].
    #[inline]
    pub fn with_default_connector(self) -> Socks5Acceptor<DefaultConnector, B, U, A> {
        self.with_connector(DefaultConnector::default())
    }
}

impl<C, U, A> Socks5Acceptor<C, (), U, A> {
    /// Attach a [`Socks5Binder`] to this [`Socks5Acceptor`],
    /// used to accept incoming [`Command::Bind`] [`client::Request`]s.
    ///
    /// Use [`Socks5Acceptor::with_default_binder`] in case
    /// the [`DefaultConnector`] serves your needs just fine.
    pub fn with_binder<B>(self, binder: B) -> Socks5Acceptor<C, B, U, A> {
        Socks5Acceptor {
            connector: self.connector,
            binder,
            udp_associator: self.udp_associator,
            auth: self.auth,
            auth_opt: self.auth_opt,
        }
    }

    /// Attach the [`DefaultBinder`] to this [`Socks5Acceptor`],
    /// used to accept incoming [`Command::Bind`] [`client::Request`]s.
    ///
    /// Use [`Socks5Acceptor::with_binder`] in case you want to use a custom
    /// [`Socks5Binder`] or customised [`Binder`].
    #[inline]
    pub fn with_default_binder(self) -> Socks5Acceptor<C, DefaultBinder, U, A> {
        self.with_binder(DefaultBinder::default())
    }
}

impl<C, B, A> Socks5Acceptor<C, B, (), A> {
    /// Attach a [`Socks5UdpAssociator`] to this [`Socks5Acceptor`],
    /// used to accept incoming [`Command::UdpAssociate`] [`client::Request`]s.
    ///
    /// Use [`Socks5Acceptor::with_default_udp_associator`] in case
    /// the [`DefaultUdpRelay`] serves your needs just fine.
    pub fn with_udp_associator<U>(self, udp_associator: U) -> Socks5Acceptor<C, B, U, A> {
        Socks5Acceptor {
            connector: self.connector,
            binder: self.binder,
            udp_associator,
            auth: self.auth,
            auth_opt: self.auth_opt,
        }
    }

    /// Attach the [`DefaultUdpRelay`] to this [`Socks5Acceptor`],
    /// used to accept incoming [`Command::UdpAssociate`] [`client::Request`]s.
    ///
    /// Use [`Socks5Acceptor::with_udp_associator`] in case you want to use a custom
    /// [`Socks5UdpAssociator`] or customised [`udp::UdpRelay`].
    #[inline]
    pub fn with_default_udp_associator(self) -> Socks5Acceptor<C, B, DefaultUdpRelay, A> {
        self.with_udp_associator(DefaultUdpRelay::default())
    }
}

impl Default for Socks5Acceptor {
    #[inline]
    fn default() -> Self {
        Socks5Acceptor::new().with_default_connector()
    }
}

impl<C: fmt::Debug, B: fmt::Debug, U: fmt::Debug, A: fmt::Debug> fmt::Debug
    for Socks5Acceptor<C, B, U, A>
{
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

impl<C: Clone, B: Clone, U: Clone, A: Clone> Clone for Socks5Acceptor<C, B, U, A> {
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
    source: Option<BoxError>,
}

#[derive(Debug)]
enum ErrorContext {
    None,
    Message(&'static str),
    ReplyKind(ReplyKind),
}

impl From<&'static str> for ErrorContext {
    fn from(value: &'static str) -> Self {
        Self::Message(value)
    }
}

impl From<ReplyKind> for ErrorContext {
    fn from(value: ReplyKind) -> Self {
        Self::ReplyKind(value)
    }
}

impl Error {
    fn io(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::IO,
            context: ErrorContext::None,
            source: Some(err.into()),
        }
    }

    fn protocol(err: ProtocolError) -> Self {
        Self {
            kind: ErrorKind::Protocol,
            context: ErrorContext::None,
            source: Some(err.into()),
        }
    }

    fn aborted(reason: &'static str) -> Self {
        Self {
            kind: ErrorKind::Aborted(reason),
            context: ErrorContext::None,
            source: None,
        }
    }

    fn service(error: impl Into<BoxError>) -> Self {
        Self {
            kind: ErrorKind::Service,
            context: ErrorContext::None,
            source: Some(error.into()),
        }
    }

    fn with_context(mut self, context: impl Into<ErrorContext>) -> Self {
        self.context = context.into();
        self
    }

    fn with_source(mut self, err: impl Into<BoxError>) -> Self {
        self.source = Some(err.into());
        self
    }
}

#[derive(Debug)]
enum ErrorKind {
    IO,
    Protocol,
    Aborted(&'static str),
    Service,
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => write!(f, "{message}"),
            Self::ReplyKind(kind) => write!(f, "reply: {kind}"),
            Self::None => write!(f, "no context"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let context = &self.context;
        match &self.kind {
            ErrorKind::IO => {
                write!(f, "server: handshake eror: I/O ({context})")
            }
            ErrorKind::Protocol => {
                write!(f, "server: handshake eror: protocol error ({context})")
            }
            ErrorKind::Aborted(reason) => {
                write!(f, "server: handshake eror: aborted: {reason} ({context})")
            }
            ErrorKind::Service => {
                write!(f, "server: service eror ({context})")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().and_then(|e| e.source())
    }
}

impl<C, B, U, A> Socks5Acceptor<C, B, U, A> {
    pub async fn accept<S>(&self, mut ctx: Context, mut stream: S) -> Result<(), Error>
    where
        C: Socks5Connector<S>,
        U: Socks5UdpAssociator<S>,
        A: Authorizer<user::Basic, Error: fmt::Debug>,
        B: Socks5Binder<S>,
        S: Stream + Unpin,
    {
        let client_header = client::Header::read_from(&mut stream)
            .await
            .map_err(|err| Error::protocol(err).with_context("read client header"))?;

        let (negotiated_method, maybe_ext) = self
            .handle_method(&client_header.methods, &mut stream)
            .await?;

        if let Some(ext) = maybe_ext {
            ctx.extend(ext);
        }

        tracing::trace!(
            "socks5 server: headers exchanged negotiated method = {negotiated_method:?} (for client methods: {:?}",
            client_header.methods,
        );

        let client_request = client::Request::read_from(&mut stream)
            .await
            .map_err(|err| Error::protocol(err).with_context("read client request"))?;
        tracing::trace!(
            "socks5 server w/ destination {} and negotiated method {:?} (for client methods: {:?}): client request received cmd {:?}",
            client_request.destination,
            negotiated_method,
            client_header.methods,
            client_request.command,
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
                    "socks5 server w/ destination {} for negotiated method: {:?} (for client methods: {:?}): abort: unknown command {:?} not supported",
                    client_request.destination,
                    negotiated_method,
                    client_header.methods,
                    client_request.command,
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
}

impl<C, B, U, A: Authorizer<user::Basic, Error: fmt::Debug>> Socks5Acceptor<C, B, U, A> {
    async fn handle_method<S: Stream + Unpin>(
        &self,
        methods: &[SocksMethod],
        stream: &mut S,
    ) -> Result<(SocksMethod, Option<Extensions>), Error> {
        match &self.auth {
            AuthKind::WithAuth(authorizer) => {
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
                    let user::authority::AuthorizeResult { result, .. } =
                        authorizer.authorize(client_auth_req.basic).await;
                    match result {
                        Ok(maybe_ext) => {
                            UsernamePasswordResponse::new_success()
                                .write_to(stream)
                                .await
                                .map_err(|err| {
                                    Error::io(err).with_context(
                                        "write server auth sub-negotiation success response",
                                    )
                                })?;
                            Ok((SocksMethod::UsernamePassword, maybe_ext))
                        }
                        Err(err) => {
                            tracing::trace!(
                                "socks5 acceptor's authorizer stopped inc request: {err:?}"
                            );
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

                    Ok((SocksMethod::NoAuthenticationRequired, None))
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
            AuthKind::NoAuth(_) => {
                if methods.contains(&SocksMethod::NoAuthenticationRequired) {
                    Header::new(SocksMethod::NoAuthenticationRequired)
                        .write_to(stream)
                        .await
                        .map_err(|err| {
                            Error::io(err).with_context("write server reply: no auth required")
                        })?;

                    return Ok((SocksMethod::NoAuthenticationRequired, None));
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

impl<C, B, U, A, S> Service<S> for Socks5Acceptor<C, B, U, A>
where
    C: Socks5Connector<S>,
    U: Socks5UdpAssociator<S>,
    A: Authorizer<user::Basic, Error: fmt::Debug>,
    B: Socks5Binder<S>,
    S: Stream + Unpin,
{
    type Response = ();
    type Error = Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context,
        stream: S,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.accept(ctx, stream)
    }
}

impl<C, B, U, A> Socks5Acceptor<C, B, U, A>
where
    C: Socks5Connector<TcpStream>,
    U: Socks5UdpAssociator<TcpStream>,
    A: Authorizer<user::Basic, Error: fmt::Debug>,
    B: Socks5Binder<TcpStream>,
{
    /// Listen for connections on the given [`Interface`], serving Socks5(h) connections.
    ///
    /// It's a shortcut in case you don't need to operate on the transport layer directly.
    pub async fn listen<I>(self, interface: I) -> Result<(), BoxError>
    where
        I: TryInto<Interface, Error: Into<BoxError>>,
    {
        let tcp = TcpListener::bind(interface).await?;
        tcp.serve(self).await;
        Ok(())
    }
}

#[cfg(test)]
mod test;
