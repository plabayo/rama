use std::{fmt, io, sync::Arc, time::Duration};

use rama_core::{Context, Service, error::BoxError};
use rama_net::{
    address::{Authority, Host, Interface, SocketAddress},
    proxy::{ProxyRequest, StreamForwardService},
    stream::Stream,
};
use rama_tcp::{TcpStream, server::TcpListener};
use rama_utils::macros::generate_field_setters;

use super::Error;
use crate::proto::{ReplyKind, server::Reply};

/// Types which can be used as socks5 [`Command::Bind`] drivers on the server side.
///
/// Typically used as a component part of a [`Socks5Acceptor`].
///
/// The actual underlying trait is sealed and not exposed for usage.
/// No custom binders can be implemented. You can however customise
/// the individual steps as provided and used by `Binder`.
///
/// [`Socks5Acceptor`]: crate::server::Socks5Acceptor
/// [`Command::Bind`]: crate::proto::Command::Bind
pub trait Socks5Binder<S, State>: Socks5BinderSeal<S, State> {}

impl<S, State, C> Socks5Binder<S, State> for C where C: Socks5BinderSeal<S, State> {}

pub trait Socks5BinderSeal<S, State>: Send + Sync + 'static {
    fn accept_bind(
        &self,
        ctx: Context<State>,
        stream: S,
        destination: Authority,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_;
}

impl<S, State> Socks5BinderSeal<S, State> for ()
where
    S: Stream + Unpin,
    State: Clone + Send + Sync + 'static,
{
    async fn accept_bind(
        &self,
        _ctx: Context<State>,
        mut stream: S,
        destination: Authority,
    ) -> Result<(), Error> {
        tracing::debug!(
            %destination,
            "socks5 server: abort: command not supported: Bind",
        );

        Reply::error_reply(ReplyKind::CommandNotSupported)
            .write_to(&mut stream)
            .await
            .map_err(|err| {
                Error::io(err).with_context("write server reply: command not supported (bind)")
            })?;
        Err(Error::aborted("command not supported: Bind"))
    }
}

/// Default [`Binder`] type.
pub type DefaultBinder = Binder<(), StreamForwardService>;

/// Only "useful" public [`Socks5Binder`] implementation,
/// which actually is able to accept bind requests and process them.
///
/// The [`Default`] implementation opens a new socket for accepting 1
/// incoming connection. Once received it will pipe the original request (source)
/// stream together with the received inbound stream from the secondary callee.
///
/// You can customise the [`Binder`] fully by creating it using [`Binder::new`]
/// or overwrite any of the default components using either or both of [`Binder::with_acceptor`]
/// and [`Binder::with_service`].
pub struct Binder<A, S> {
    acceptor: A,
    service: S,

    bind_interface: Interface,

    strict: bool,
    accept_timeout: Option<Duration>,
}

impl<A, S> Binder<A, S> {
    /// Create a new [`Binder`].
    ///
    /// In case you only wish to overwrite one of these components
    /// you can also use a [`Default`] [`Binder`] and overwrite the specific component
    /// using [`Binder::with_acceptor`] or [`Binder::with_service`].
    pub fn new(acceptor: A, service: S) -> Self {
        Self {
            acceptor,
            service,
            bind_interface: Interface::default_ipv4(0),
            strict: false,
            accept_timeout: None,
        }
    }
}

impl<A, S> Binder<A, S> {
    /// Overwrite the [`Binder`]'s [`AcceptorFactory`],
    /// used to open a listener, return the address and
    /// wait for an incoming connection which it will return.
    pub fn with_acceptor<T>(self, acceptor: T) -> Binder<T, S> {
        Binder {
            acceptor,
            service: self.service,
            bind_interface: self.bind_interface,
            strict: self.strict,
            accept_timeout: self.accept_timeout,
        }
    }

    /// Overwrite the [`Connector`]'s [`Service`]
    /// used to actually do the proxy between the source and incoming bind [`Stream`].
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (Context<State>, ProxyRequest) -> ((), Into<BoxError>)
    /// ```
    pub fn with_service<T>(self, service: T) -> Binder<A, T> {
        Binder {
            acceptor: self.acceptor,
            service,
            bind_interface: self.bind_interface,
            strict: self.strict,
            accept_timeout: self.accept_timeout,
        }
    }

    /// Define whether or not to strictly compare the incoming
    /// connection's address against the bind request bind address, partly or fully, if defined at all.
    pub fn set_strict_security(&mut self, strict: bool) -> &mut Self {
        self.strict = strict;
        self
    }

    /// Define whether or not to strictly compare the incoming
    /// connection's address against the bind request bind address, partly or fully, if defined at all.
    pub fn with_strict_security(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Define the (network) [`Interface`] to bind to.
    pub fn set_bind_interface(&mut self, interface: Interface) -> &mut Self {
        self.bind_interface = interface;
        self
    }

    /// Define the (network) [`Interface`] to bind to.
    pub fn with_bind_interface(mut self, interface: Interface) -> Self {
        self.bind_interface = interface;
        self
    }

    generate_field_setters!(accept_timeout, Duration);
}

impl<A: fmt::Debug, S: fmt::Debug> fmt::Debug for Binder<A, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Binder")
            .field("acceptor", &self.acceptor)
            .field("service", &self.service)
            .field("bind_interface", &self.bind_interface)
            .field("strict", &self.strict)
            .field("accept_timeout", &self.accept_timeout)
            .finish()
    }
}

impl<A: Clone, S: Clone> Clone for Binder<A, S> {
    fn clone(&self) -> Self {
        Self {
            acceptor: self.acceptor.clone(),
            service: self.service.clone(),
            bind_interface: self.bind_interface.clone(),
            strict: self.strict,
            accept_timeout: self.accept_timeout,
        }
    }
}

/// An [`AcceptorFactory`] used to create a [`Acceptor`] in function of a [`Binder`].
pub trait AcceptorFactory: Send + Sync + 'static {
    /// The [`Acceptor`] to be returned by this factory;
    type Acceptor: Acceptor;
    /// Error to be returned in case of failure.
    type Error: Send + 'static;

    /// Create a new [`Acceptor`] ready to do the 2-step "bind" dance.
    fn make_acceptor(
        &self,
        interface: Interface,
    ) -> impl Future<Output = Result<Self::Acceptor, Self::Error>> + Send + '_;
}

impl<F: AcceptorFactory> AcceptorFactory for Arc<F> {
    type Acceptor = F::Acceptor;
    type Error = F::Error;

    fn make_acceptor(
        &self,
        interface: Interface,
    ) -> impl Future<Output = Result<Self::Acceptor, Self::Error>> + Send + '_ {
        (**self).make_acceptor(interface)
    }
}

impl AcceptorFactory for () {
    type Acceptor = TcpListener<()>;
    type Error = BoxError;

    fn make_acceptor(
        &self,
        interface: Interface,
    ) -> impl Future<Output = Result<Self::Acceptor, Self::Error>> + Send + '_ {
        TcpListener::bind(interface)
    }
}

impl<F, Fut, A, E> AcceptorFactory for F
where
    F: FnOnce(Interface) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<A, E>> + Send + 'static,
    A: Acceptor,
    E: Send + 'static,
{
    type Acceptor = A;
    type Error = E;

    fn make_acceptor(
        &self,
        interface: Interface,
    ) -> impl Future<Output = Result<Self::Acceptor, Self::Error>> + Send + '_ {
        (self.clone())(interface)
    }
}

/// [`Acceptor`] created by an [`AcceptorFactory`] in function of a [`Binder`].
pub trait Acceptor: Send + Sync + 'static {
    /// The [`Stream`] returned by this [`Acceptor`].
    type Stream: Stream;

    /// Returns the local address that this listener is bound to.
    fn local_addr(&self) -> io::Result<SocketAddress>;

    /// Returns the first succesfully accepted connection.
    fn accept(self) -> impl Future<Output = Result<(Self::Stream, SocketAddress), Error>> + Send;
}

impl<S> Acceptor for TcpListener<S>
where
    S: Clone + Send + Sync + 'static,
{
    type Stream = TcpStream;

    fn local_addr(&self) -> io::Result<SocketAddress> {
        TcpListener::local_addr(self).map(Into::into)
    }

    #[inline]
    async fn accept(self) -> Result<(Self::Stream, SocketAddress), Error> {
        let (stream, addr) = TcpListener::accept(&self).await.map_err(Error::io)?;
        tracing::trace!(
            peer_addr = %addr,
            "accepted incoming TCP connection"
        );
        Ok((stream, addr))
    }
}

// TODO: add mock binder
// TODO: add test

impl Default for DefaultBinder {
    fn default() -> Self {
        Self {
            acceptor: (),
            service: StreamForwardService::default(),
            bind_interface: Interface::default_ipv4(0),
            strict: false,
            accept_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl<S, State, F, StreamService> Socks5BinderSeal<S, State> for Binder<F, StreamService>
where
    S: Stream + Unpin,
    State: Clone + Send + Sync + 'static,
    F: AcceptorFactory<Error: Into<BoxError>>,
    <F::Acceptor as Acceptor>::Stream: Unpin,
    StreamService: Service<
            State,
            ProxyRequest<S, <F::Acceptor as Acceptor>::Stream>,
            Response = (),
            Error: Into<BoxError>,
        >,
{
    async fn accept_bind(
        &self,
        ctx: Context<State>,
        mut stream: S,
        destination: Authority,
    ) -> Result<(), Error> {
        tracing::trace!(
            %destination,
            "socks5 server: bind: try to create acceptor",
        );

        let (dest_host, dest_port) = destination.into_parts();
        let dest_addr = match dest_host {
            Host::Name(domain) => {
                tracing::debug!(
                    %domain,
                    "bind command does not accept domain as bind address",
                );
                let reply_kind = ReplyKind::AddressTypeNotSupported;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: bind failed")
                    })?;
                return Err(Error::aborted("bind failed").with_context(reply_kind));
            }
            Host::Address(ip_addr) => ip_addr,
        };
        let destination = SocketAddress::new(dest_addr, dest_port);

        let acceptor: F::Acceptor = self
            .acceptor
            .make_acceptor(self.bind_interface.clone())
            .await
            .map_err(Error::service)?;

        let bind_address = acceptor.local_addr().map_err(Error::io)?;
        Reply::new(bind_address.into())
            .write_to(&mut stream)
            .await
            .map_err(|err| {
                Error::io(err).with_context("write server reply: bind: acceptor listener ready")
            })?;

        let accept_future = acceptor.accept();

        let result = match self.accept_timeout {
            Some(duration) => match tokio::time::timeout(duration, accept_future).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::debug!(
                        timeout_err=?err,
                        "accept future timed out",
                    );
                    let reply_kind = ReplyKind::TtlExpired;
                    Reply::error_reply(reply_kind)
                        .write_to(&mut stream)
                        .await
                        .map_err(|err| {
                            Error::io(err).with_context("write server reply: bind failed")
                        })?;
                    return Err(Error::aborted("bind failed").with_context(reply_kind));
                }
            },
            None => accept_future.await,
        };

        let (target, incoming_addr) = match result {
            Ok((stream, addr)) => (stream, addr),
            Err(err) => {
                let err: BoxError = err.into();
                tracing::debug!(
                    %destination,
                    ?err,
                    "socks5 server: abort: bind failed",
                );

                let reply_kind = (&err).into();
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: bind failed")
                    })?;
                return Err(Error::aborted("bind failed").with_context(reply_kind));
            }
        };

        if self.strict {
            let destination_ip_addr = destination.ip_addr();
            let incoming_ip_addr = incoming_addr.ip_addr();
            if !destination_ip_addr.is_unspecified() && destination_ip_addr != incoming_ip_addr {
                tracing::debug!(
                    %destination_ip_addr,
                    %incoming_ip_addr,
                    "strict mode: security: unexpected incoming ip address",
                );
                let reply_kind = ReplyKind::ConnectionNotAllowed;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err)
                            .with_context("write server reply: invalid incoming ip address")
                    })?;
                return Err(Error::aborted("bind failed").with_context(reply_kind));
            }

            let destination_port = destination.port();
            let incoming_port = incoming_addr.port();
            if destination_port != 0 && destination_port != incoming_port {
                tracing::debug!(
                    %destination_ip_addr,
                    %destination_port,
                    %incoming_ip_addr,
                    %incoming_port,
                    "strict mode: security: unexpected incoming port",
                );
                let reply_kind = ReplyKind::ConnectionNotAllowed;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: invalid incoming port")
                    })?;
                return Err(Error::aborted("bind failed").with_context(reply_kind));
            }
        } else {
            tracing::trace!(
                %destination,
                %incoming_addr,
                "non-strict mode: do not validate address of incoming connection",
            );
        }

        self.service
            .serve(
                ctx,
                ProxyRequest {
                    source: stream,
                    target,
                },
            )
            .await
            .map_err(|err| Error::service(err).with_context("serve bind pipe"))
    }
}
