use std::{io, net::IpAddr, sync::Arc};

use rama_core::{Context, error::BoxError};
use rama_net::{
    address::{Authority, SocketAddress},
    stream::Stream,
};
use rama_tcp::{TcpStream, server::TcpListener};

use crate::proto::{ReplyKind, server::Reply};

use super::Error;

/// Types which can be used as socks5 [`Command::Bind`] drivers on the server side.
///
/// Typically used as a component part of a [`Socks5Acceptor`].
///
/// The actual underlying trait is sealed and not exposed for usage.
/// No custom binders can be implemented. You can however customise
/// the individual steps as provided and used by `Binder` (TODO).
///
/// [`Socks5Acceptor`]: crate::server::Socks5Acceptor
/// [`Command::Bind`]: crate::proto::Command::Bind
pub trait Socks5Binder: Socks5BinderSeal {}

impl<C> Socks5Binder for C where C: Socks5BinderSeal {}

pub trait Socks5BinderSeal: Send + Sync + 'static {
    fn accept_bind<S, State>(
        &self,
        ctx: Context<State>,
        stream: S,
        destination: Authority,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_
    where
        S: Stream + Unpin,
        State: Clone + Send + Sync + 'static;
}

impl Socks5BinderSeal for () {
    async fn accept_bind<S, State>(
        &self,
        _ctx: Context<State>,
        mut stream: S,
        destination: Authority,
    ) -> Result<(), Error>
    where
        S: Stream + Unpin,
        State: Clone + Send + Sync + 'static,
    {
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
}

impl<A, S> Binder<A, S> {
    /// Create a new [`Binder`].
    ///
    /// In case you only wish to overwrite one of these components
    /// you can also use a [`Default`] [`Binder`] and overwrite the specific component
    /// using [`Binder::with_acceptor`] or [`Binder::with_service`].
    pub fn new(acceptor: A, service: S) -> Self {
        Self { acceptor, service }
    }
}

impl<A, S> Binder<A, S> {
    /// Overwrite the [`Binder`]'s acceptor [`Service`]
    /// used to open a listener, return the address and
    /// wait for an incoming connection which it will return.
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (Context<State>, Acceptor)
    ///     -> (EstablishedConnection<T, State, TcpRequest>, Into<BoxError>)
    /// ```
    pub fn with_acceptor<T>(self, acceptor: T) -> Binder<T, S> {
        // TODO: change doc comment
        Binder {
            acceptor,
            service: self.service,
        }
    }

    /// Overwrite the [`Connector`]'s [`Service`]
    /// used to actually do the proxy between the source and target [`Stream`].
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (Context<State>, ProxyRequest) -> ((), Into<BoxError>)
    /// ```
    pub fn with_service<T>(self, service: T) -> Binder<A, T> {
        // TODO: change doc comment
        Binder {
            acceptor: self.acceptor,
            service,
        }
    }
}

/// An [`AcceptorFactory`] used to create a [`Acceptor`] in function of a [`Binder`].
pub trait AcceptorFactory: Send + Sync + 'static {
    /// The [`Acceptor`] to be returned by this factory;
    type Acceptor: Acceptor;
    /// Error to be returned in case of failure.
    type Error: Send + 'static;

    // TODO: support also Interface names etc for unix envs and w/e, to be added to rama-net

    /// Create a new [`Acceptor`] ready to do the 2-step "bind" dance.
    fn make_acceptor(
        &self,
        interface: IpAddr,
    ) -> impl Future<Output = Result<Self::Acceptor, Self::Error>> + Send + '_;
}

impl<F: AcceptorFactory> AcceptorFactory for Arc<F> {
    type Acceptor = F::Acceptor;
    type Error = F::Error;

    fn make_acceptor(
        &self,
        interface: IpAddr,
    ) -> impl Future<Output = Result<Self::Acceptor, Self::Error>> + Send + '_ {
        (**self).make_acceptor(interface)
    }
}

impl AcceptorFactory for () {
    type Acceptor = TcpListener<()>;
    type Error = BoxError;

    fn make_acceptor(
        &self,
        interface: IpAddr,
    ) -> impl Future<Output = Result<Self::Acceptor, Self::Error>> + Send + '_ {
        TcpListener::bind(SocketAddress::new(interface, 0))
        // TODO: support other interfaces, not just ip addr, e.g. IF_NAME (eth0, ...)
    }
}

impl<F, Fut, A, E> AcceptorFactory for F
where
    F: FnOnce(IpAddr) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<A, E>> + Send + 'static,
    A: Acceptor,
    E: Send + 'static,
{
    type Acceptor = A;
    type Error = E;

    fn make_acceptor(
        &self,
        interface: IpAddr,
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

// TODO: implement default binder, binder, and core logic
// TODO: add mock binder
// TODO: add test

// impl Default for DefaultConnector {
//     fn default() -> Self {
//         Self {
//             connector: TcpConnector::default(),
//             service: StreamForwardService::default(),
//             hide_local_address: false,
//         }
//     }
// }

// impl<C: fmt::Debug, S: fmt::Debug> fmt::Debug for Connector<C, S> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         f.debug_struct("Connector")
//             .field("connector", &self.connector)
//             .field("service", &self.service)
//             .field("hide_local_address", &self.hide_local_address)
//             .finish()
//     }
// }

// impl<C: Clone, S: Clone> Clone for Connector<C, S> {
//     fn clone(&self) -> Self {
//         Self {
//             connector: self.connector.clone(),
//             service: self.service.clone(),
//             hide_local_address: self.hide_local_address,
//         }
//     }
// }

// impl<S, T, State, InnerConnector, StreamService> Socks5ConnectorSeal<S, State>
//     for Connector<InnerConnector, StreamService>
// where
//     S: Stream + Unpin,
//     T: Stream + Socket + Unpin,
//     State: Clone + Send + Sync + 'static,
//     InnerConnector: Service<
//             State,
//             TcpRequest,
//             Response = EstablishedClientConnection<T, State, TcpRequest>,
//             Error: Into<BoxError>,
//         >,
//     StreamService: Service<State, ProxyRequest<S, T>, Response = (), Error: Into<BoxError>>,
// {
//     async fn accept_connect(
//         &self,
//         ctx: Context<State>,
//         mut stream: S,
//         destination: Authority,
//     ) -> Result<(), Error> {
//         tracing::trace!(
//             %destination,
//             "socks5 server: connect: try to establish connection",
//         );

//         let EstablishedClientConnection {
//             ctx, conn: target, ..
//         } = match self
//             .connector
//             .serve(ctx, TcpRequest::new(destination.clone()))
//             .await
//         {
//             Ok(ecs) => ecs,
//             Err(err) => {
//                 let err: BoxError = err.into();
//                 tracing::debug!(
//                     %destination,
//                     ?err,
//                     "socks5 server: abort: connect failed",
//                 );

//                 let reply_kind = if let Some(err) = err.downcast_ref::<std::io::Error>() {
//                     match err.kind() {
//                         std::io::ErrorKind::PermissionDenied => ReplyKind::ConnectionNotAllowed,
//                         std::io::ErrorKind::HostUnreachable => ReplyKind::HostUnreachable,
//                         std::io::ErrorKind::NetworkUnreachable => ReplyKind::NetworkUnreachable,
//                         std::io::ErrorKind::TimedOut | std::io::ErrorKind::UnexpectedEof => {
//                             ReplyKind::TtlExpired
//                         }
//                         _ => ReplyKind::ConnectionRefused,
//                     }
//                 } else {
//                     ReplyKind::ConnectionRefused
//                 };

//                 Reply::error_reply(reply_kind)
//                     .write_to(&mut stream)
//                     .await
//                     .map_err(|err| {
//                         Error::io(err).with_context("write server reply: connect failed")
//                     })?;
//                 return Err(Error::aborted("connect failed").with_context(reply_kind));
//             }
//         };

//         let local_addr = target
//             .local_addr()
//             .map(Into::into)
//             .inspect_err(|err| {
//                 tracing::debug!(
//                     %destination,
//                     %err,
//                     "socks5 server: connect: failed to retrieve local addr from established conn, use default '0.0.0.0:0'",
//                 );
//             })
//             .unwrap_or(Authority::default_ipv4(0));
//         let peer_addr = target.peer_addr();

//         tracing::trace!(
//             %destination,
//             %local_addr,
//             ?peer_addr,
//             "socks5 server: connect: connection established, serve pipe",
//         );

//         Reply::new(if self.hide_local_address {
//             Authority::default_ipv4(0)
//         } else {
//             local_addr.clone()
//         })
//         .write_to(&mut stream)
//         .await
//         .map_err(|err| Error::io(err).with_context("write server reply: connect succeeded"))?;

//         tracing::trace!(
//             %destination,
//             %local_addr,
//             ?peer_addr,
//             "socks5 server: connect: reply sent, start serving source-target pipe",
//         );

//         self.service
//             .serve(
//                 ctx,
//                 ProxyRequest {
//                     source: stream,
//                     target,
//                 },
//             )
//             .await
//             .map_err(|err| Error::service(err).with_context("serve connect pipe"))
//     }
// }
