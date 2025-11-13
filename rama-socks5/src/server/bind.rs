use std::{fmt, io, time::Duration};

use rama_core::telemetry::tracing::{self, Instrument};
use rama_core::{Service, error::BoxError, layer::timeout::DefaultTimeout, stream::Stream};
use rama_net::{
    address::{Authority, Host, SocketAddress},
    proxy::{ProxyRequest, StreamForwardService},
    socket::{Interface, SocketService},
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
pub trait Socks5Binder<S>: Socks5BinderSeal<S> {}

impl<S, C> Socks5Binder<S> for C where C: Socks5BinderSeal<S> {}

pub trait Socks5BinderSeal<S>: Send + Sync + 'static {
    fn accept_bind(
        &self,

        stream: S,
        destination: Authority,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_;
}

impl<S> Socks5BinderSeal<S> for ()
where
    S: Stream + Unpin,
{
    async fn accept_bind(&self, mut stream: S, destination: Authority) -> Result<(), Error> {
        tracing::debug!(
            server.address = %destination.host(),
            server.port = %destination.port(),
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
pub type DefaultBinder = Binder<DefaultTimeout<DefaultAcceptorFactory>, StreamForwardService>;

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

    bind_interface: Option<Interface>,

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
            bind_interface: None,
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
            accept_timeout: self.accept_timeout,
        }
    }

    /// Overwrite the [`Binder`]'s [`Service`]
    /// used to actually do the proxy between the source and incoming bind [`Stream`].
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (Context, ProxyRequest) -> ((), Into<BoxError>)
    /// ```
    pub fn with_service<T>(self, service: T) -> Binder<A, T> {
        Binder {
            acceptor: self.acceptor,
            service,
            bind_interface: self.bind_interface,
            accept_timeout: self.accept_timeout,
        }
    }

    /// Define the (network) [`Interface`] to bind to.
    ///
    /// By default it will use the client's requested bind address,
    /// which is in many cases not what you want.
    pub fn set_bind_interface(&mut self, interface: impl Into<Interface>) -> &mut Self {
        self.bind_interface = Some(interface.into());
        self
    }

    /// Define the default (network) [`Interface`] to bind to (`0.0.0.0:0`).
    ///
    /// By default it will use the client's requested bind address,
    /// which is in many cases not what you want.
    pub fn set_default_bind_interface(&mut self) -> &mut Self {
        self.bind_interface = Some(SocketAddress::default_ipv4(0).into());
        self
    }

    /// Define the (network) [`Interface`] to bind to.
    ///
    /// By default it will use the client's requested bind address,
    /// which is in many cases not what you want.
    #[must_use]
    pub fn with_bind_interface(mut self, interface: impl Into<Interface>) -> Self {
        self.bind_interface = Some(interface.into());
        self
    }

    /// Define the default (network) [`Interface`] to bind to (`0.0.0.0:0`).
    ///
    /// By default it will use the client's requested bind address,
    /// which is in many cases not what you want.
    #[must_use]
    pub fn with_default_bind_interface(mut self) -> Self {
        self.bind_interface = Some(SocketAddress::default_ipv4(0).into());
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
            accept_timeout: self.accept_timeout,
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Default [`AcceptorFactory`] used by [`DefaultBinder`].
pub struct DefaultAcceptorFactory;

impl Service<Interface> for DefaultAcceptorFactory {
    type Response = TcpListener;
    type Error = BoxError;

    async fn serve(&self, interface: Interface) -> Result<Self::Response, Self::Error> {
        let acceptor = TcpListener::bind(interface).await?;
        Ok(acceptor)
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

impl Acceptor for TcpListener {
    type Stream = TcpStream;

    fn local_addr(&self) -> io::Result<SocketAddress> {
        Self::local_addr(self).map(Into::into)
    }

    #[inline]
    async fn accept(self) -> Result<(Self::Stream, SocketAddress), Error> {
        let (stream, addr) = Self::accept(&self).await.map_err(Error::io)?;
        tracing::trace!(
            network.peer.port = %addr.port(),
            network.peer.address = %addr.ip_addr(),
            "accepted incoming TCP connection"
        );
        Ok((stream, addr))
    }
}

impl Default for DefaultBinder {
    fn default() -> Self {
        Self::new(
            DefaultTimeout::new(DefaultAcceptorFactory::default(), Duration::from_secs(30)),
            StreamForwardService::default(),
        )
    }
}

impl<S, F, StreamService> Socks5BinderSeal<S> for Binder<F, StreamService>
where
    S: Stream + Unpin,
    F: SocketService<Socket: Acceptor<Stream: Unpin>>,
    StreamService: Service<
            ProxyRequest<S, <F::Socket as Acceptor>::Stream>,
            Response = (),
            Error: Into<BoxError>,
        >,
{
    async fn accept_bind(
        &self,
        mut stream: S,
        requested_bind_address: Authority,
    ) -> Result<(), Error> {
        tracing::trace!("socks5 server: bind: try to create acceptor @ {requested_bind_address}");

        let (requested_host, requested_port) = requested_bind_address.into_parts();
        let requested_addr = match requested_host {
            Host::Name(domain) => {
                tracing::debug!("bind command does not accept domain {domain} as bind address",);
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
        let requested_interface = SocketAddress::new(requested_addr, requested_port);

        let bind_interface = if let Some(bind_interface) = self.bind_interface.clone() {
            tracing::trace!(
                "socks5 server: bind: use server-defined bind interface: {bind_interface}"
            );
            bind_interface
        } else {
            tracing::debug!(
                "socks5 server: bind: no server-defined bind interface: use requested client interface @ {requested_interface}"
            );
            requested_interface.into()
        };

        let acceptor = match self.acceptor.bind(bind_interface.clone()).await {
            Ok(twin) => twin,
            Err(err) => {
                let err = err.into();
                tracing::debug!("make bind listener failed: {err:?}");
                let reply_kind = ReplyKind::GeneralServerFailure;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: make bind listener failed")
                    })?;
                return Err(Error::aborted("make bind listener failed")
                    .with_context(reply_kind)
                    .with_source(err));
            }
        };

        let bind_address = match acceptor.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                tracing::debug!(
                    "retrieve local addr of (tcp) acceptor failed @ {bind_interface}: {err:?}",
                );
                let reply_kind = ReplyKind::GeneralServerFailure;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: make bind listener failed")
                    })?;
                return Err(Error::aborted("make bind listener failed").with_context(reply_kind));
            }
        };

        Reply::new(bind_address)
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
                    tracing::debug!("accept future timed out @ {bind_interface}: {err:?}",);
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
                tracing::debug!("socks5 server: abort: bind failed @ {bind_interface}: {err:?}",);

                let reply_kind = (&err).into();
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: bind failed")
                    })?;
                return Err(Error::aborted("bind failed")
                    .with_context(reply_kind)
                    .with_source(err));
            }
        };

        tracing::trace!(
            "incoming connection {incoming_addr} received on bind interface {bind_interface}",
        );

        Reply::new(incoming_addr)
            .write_to(&mut stream)
            .await
            .map_err(|err| {
                Error::io(err).with_context("write server reply: bind: connection received")
            })?;

        tracing::trace!(
            "socks5 server @ {bind_interface}: bind: ready to serve from {incoming_addr}",
        );

        self.service
            .serve(ProxyRequest {
                source: stream,
                target,
            })
            .instrument(tracing::trace_span!("socks5::bind::serve"))
            .await
            .map_err(|err| Error::service(err).with_context("serve bind pipe"))
    }
}

#[cfg(test)]
pub(crate) use test::MockBinder;

#[cfg(test)]
mod test {
    use super::*;
    use std::{ops::DerefMut, sync::Arc};
    use tokio::sync::Mutex;

    #[derive(Debug)]
    pub(crate) struct MockBinder {
        reply: MockReply,
    }

    #[derive(Debug)]
    enum MockReply {
        Success {
            bind_addr: Authority,
            second_reply: MockSecondReply,
        },
        Error(ReplyKind),
    }

    #[derive(Debug)]
    enum MockSecondReply {
        Success {
            recv_addr: Authority,
            target: Option<Arc<Mutex<tokio_test::io::Mock>>>,
        },
        Error(ReplyKind),
    }

    impl MockBinder {
        pub(crate) fn new(bind_addr: Authority, recv_addr: Authority) -> Self {
            Self {
                reply: MockReply::Success {
                    bind_addr,
                    second_reply: MockSecondReply::Success {
                        recv_addr,
                        target: None,
                    },
                },
            }
        }
        pub(crate) fn new_err(reply: ReplyKind) -> Self {
            Self {
                reply: MockReply::Error(reply),
            }
        }
        pub(crate) fn new_bind_err(bind_addr: Authority, reply: ReplyKind) -> Self {
            Self {
                reply: MockReply::Success {
                    bind_addr,
                    second_reply: MockSecondReply::Error(reply),
                },
            }
        }

        pub(crate) fn with_proxy_data(mut self, target: tokio_test::io::Mock) -> Self {
            self.reply = match self.reply {
                MockReply::Success {
                    bind_addr,
                    second_reply:
                        MockSecondReply::Success {
                            recv_addr,
                            target: None,
                        },
                } => MockReply::Success {
                    bind_addr,
                    second_reply: MockSecondReply::Success {
                        recv_addr,
                        target: Some(Arc::new(Mutex::new(target))),
                    },
                },
                MockReply::Error(_) | MockReply::Success { .. } => unreachable!(),
            };
            self
        }
    }

    impl<S> Socks5BinderSeal<S> for MockBinder
    where
        S: Stream + Unpin,
    {
        async fn accept_bind(
            &self,
            mut stream: S,
            _requested_bind_address: Authority,
        ) -> Result<(), Error> {
            match &self.reply {
                MockReply::Success {
                    bind_addr,
                    second_reply,
                } => {
                    Reply::new(bind_addr.clone())
                        .write_to(&mut stream)
                        .await
                        .map_err(Error::io)?;

                    match second_reply {
                        MockSecondReply::Success { recv_addr, target } => {
                            Reply::new(recv_addr.clone())
                                .write_to(&mut stream)
                                .await
                                .map_err(Error::io)?;

                            if let Some(target) = target.as_ref() {
                                let mut target = target.lock().await;
                                match tokio::io::copy_bidirectional(&mut stream, target.deref_mut())
                                    .await
                                {
                                    Ok((bytes_copied_north, bytes_copied_south)) => {
                                        tracing::trace!(
                                            %bytes_copied_north,
                                            %bytes_copied_south,
                                            "(proxy) I/O stream forwarder finished"
                                        );
                                        Ok(())
                                    }
                                    Err(err) => {
                                        if rama_net::conn::is_connection_error(&err) {
                                            Ok(())
                                        } else {
                                            Err(Error::io(err))
                                        }
                                    }
                                }
                            } else {
                                Ok(())
                            }
                        }
                        MockSecondReply::Error(reply_kind) => {
                            Reply::error_reply(*reply_kind)
                                .write_to(&mut stream)
                                .await
                                .map_err(Error::io)?;
                            Err(Error::aborted("mock abort 2nd reply").with_context(*reply_kind))
                        }
                    }
                }
                MockReply::Error(reply_kind) => {
                    Reply::error_reply(*reply_kind)
                        .write_to(&mut stream)
                        .await
                        .map_err(Error::io)?;
                    Err(Error::aborted("mock abort 1st reply").with_context(*reply_kind))
                }
            }
        }
    }
}
