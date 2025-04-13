use rama_core::{
    Context, Service,
    error::{BoxError, ErrorExt, OpaqueError},
};
use rama_net::{
    address::Authority,
    client::EstablishedClientConnection,
    stream::{Socket, Stream},
};
use rama_tcp::client::{Request as TcpRequest, service::TcpConnector};
use std::fmt;

use super::Error;
use crate::proto::{ReplyKind, server::Reply};

/// Types which can be used as socks5 [`Command::Connect`] drivers on the server side.
///
/// Typically used as a component part of a [`Socks5Acceptor`].
///
/// The actual underlying trait is sealed and not exposed for usage.
/// No custom connectors can be implemented. You can however customise
/// both the connection and actual stream proxy phase by using
/// your own matching [`Service`] implementations as part of the usage
/// of [`Connector`].
///
/// [`Socks5Acceptor`]: crate::server::Socks5Acceptor
/// [`Command::Connect`]: crate::proto::Command::Connect
pub trait Socks5Connector<S, State>: Socks5ConnectorSeal<S, State> {}

impl<S, State, C> Socks5Connector<S, State> for C where C: Socks5ConnectorSeal<S, State> {}

pub trait Socks5ConnectorSeal<S, State>: Send + Sync + 'static {
    fn accept_connect(
        &self,
        ctx: Context<State>,
        stream: S,
        destination: Authority,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_;
}

impl<S, State> Socks5ConnectorSeal<S, State> for ()
where
    S: Stream + Unpin,
    State: Clone + Send + Sync + 'static,
{
    async fn accept_connect(
        &self,
        _ctx: Context<State>,
        mut stream: S,
        destination: Authority,
    ) -> Result<(), Error> {
        tracing::trace!(
            %destination,
            "socks5 server: abort: command not supported: Connect",
        );

        Reply::error_reply(ReplyKind::CommandNotSupported)
            .write_to(&mut stream)
            .await
            .map_err(|err| {
                Error::io(err).with_context("write server reply: command not supported (connect)")
            })?;
        Err(Error::aborted("command not supported: Connect")
            .with_context(ReplyKind::CommandNotSupported))
    }
}

/// Default [`Connector`] type.
pub type DefaultConnector = Connector<TcpConnector, StreamForwardService>;

/// Only "useful" public [`Socks5Connector`] implementation,
/// which actually is able to accept connect requests and process them.
///
/// The [`Default`] implementation establishes a connection for the requested
/// destination [`Authority`] and pipes the incoming [`Stream`] with the established
/// outgoing [`Stream`] by copying the bytes without doing anyting else with them.
///
/// You can customise the [`Connector`] fully by creating it using [`Connector::new`]
/// or overwrite any of the default components using either or both of [`Connector::with_connector`]
/// and [`Connector::with_service`].
pub struct Connector<C, S> {
    connector: C,
    service: S,
}

pub struct ProxyRequest<S, T> {
    pub source: S,
    pub target: T,
}

// ^ TODO: this might be useful to move to somewhere else??

impl<C, S> Connector<C, S> {
    /// Create a new [`Connector`].
    ///
    /// In case you only wish to overwrite one of these components
    /// you can also use a [`Default`] [`Connector`] and overwrite the specific component
    /// using [`Connector::with_connector`] or [`Connector::with_service`].
    pub fn new(connector: C, service: S) -> Self {
        Self { connector, service }
    }
}

impl<C, S> Connector<C, S> {
    /// Overwrite the [`Connector`]'s connector [`Service`]
    /// used to establish a Tcp connection used as the
    /// [`Stream`] in the direction from target to source.
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (Context<State>, TcpRequest)
    ///     -> (EstablishedConnection<T, State, TcpRequest>, Into<BoxError>)
    /// ```
    pub fn with_connector<T>(self, connector: T) -> Connector<T, S> {
        Connector {
            connector,
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
    pub fn with_service<T>(self, service: T) -> Connector<C, T> {
        Connector {
            connector: self.connector,
            service,
        }
    }
}

impl Default for DefaultConnector {
    fn default() -> Self {
        Self {
            connector: TcpConnector::default(),
            service: StreamForwardService::default(),
        }
    }
}

impl<C: fmt::Debug, S: fmt::Debug> fmt::Debug for Connector<C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connector")
            .field("connector", &self.connector)
            .field("service", &self.service)
            .finish()
    }
}

impl<C: Clone, S: Clone> Clone for Connector<C, S> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            service: self.service.clone(),
        }
    }
}

impl<S: fmt::Debug, T: fmt::Debug> fmt::Debug for ProxyRequest<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyRequest")
            .field("source", &self.source)
            .field("target", &self.target)
            .finish()
    }
}

impl<S: Clone, T: Clone> Clone for ProxyRequest<S, T> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            target: self.target.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A proxy [`Service`] which takes a [`ProxyRequest`]
/// and copies the bytes of both the source and target [`Stream`]s
/// bidirectionally.
pub struct StreamForwardService;

// ^ TODO: this might be useful to move to somewhere else??

impl StreamForwardService {
    #[inline]
    /// Create a new [`StreamForwardService`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl<State, S, T> Service<State, ProxyRequest<S, T>> for StreamForwardService
where
    State: Clone + Send + Sync + 'static,
    S: Stream + Unpin,
    T: Stream + Unpin,
{
    type Response = ();
    type Error = OpaqueError;

    async fn serve(
        &self,
        _ctx: Context<State>,
        ProxyRequest {
            mut source,
            mut target,
        }: ProxyRequest<S, T>,
    ) -> Result<Self::Response, Self::Error> {
        match tokio::io::copy_bidirectional(&mut source, &mut target).await {
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
                    Err(err.context("(proxy) I/O stream forwarder"))
                }
            }
        }
    }
}

impl<S, T, State, InnerConnector, StreamService> Socks5ConnectorSeal<S, State>
    for Connector<InnerConnector, StreamService>
where
    S: Stream + Unpin,
    T: Stream + Socket + Unpin,
    State: Clone + Send + Sync + 'static,
    InnerConnector: Service<
            State,
            TcpRequest,
            Response = EstablishedClientConnection<T, State, TcpRequest>,
            Error: Into<BoxError>,
        >,
    StreamService: Service<State, ProxyRequest<S, T>, Response = (), Error: Into<BoxError>>,
{
    async fn accept_connect(
        &self,
        ctx: Context<State>,
        mut stream: S,
        destination: Authority,
    ) -> Result<(), Error> {
        tracing::trace!(
            %destination,
            "socks5 server: connect: try to establish connection",
        );

        let EstablishedClientConnection {
            ctx, conn: target, ..
        } = match self
            .connector
            .serve(ctx, TcpRequest::new(destination.clone()))
            .await
        {
            Ok(ecs) => ecs,
            Err(err) => {
                let err: BoxError = err.into();
                tracing::debug!(
                    %destination,
                    ?err,
                    "socks5 server: abort: connect failed",
                );

                let reply_kind = if let Some(err) = err.downcast_ref::<std::io::Error>() {
                    match err.kind() {
                        std::io::ErrorKind::PermissionDenied => ReplyKind::ConnectionNotAllowed,
                        std::io::ErrorKind::HostUnreachable => ReplyKind::HostUnreachable,
                        std::io::ErrorKind::NetworkUnreachable => ReplyKind::NetworkUnreachable,
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::UnexpectedEof => {
                            ReplyKind::TtlExpired
                        }
                        _ => ReplyKind::ConnectionRefused,
                    }
                } else {
                    ReplyKind::ConnectionRefused
                };

                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: connect failed")
                    })?;
                return Err(Error::aborted("connect failed").with_context(reply_kind));
            }
        };

        let local_addr = target
            .local_addr()
            .map(Into::into)
            .inspect_err(|err| {
                tracing::debug!(
                    %destination,
                    %err,
                    "socks5 server: connect: failed to retrieve local addr from established conn, use default '0.0.0.0:0'",
                );
            })
            .unwrap_or(Authority::default_ipv4(0));
        let peer_addr = target.peer_addr();

        tracing::trace!(
            %destination,
            %local_addr,
            ?peer_addr,
            "socks5 server: connect: connection established, serve pipe",
        );

        Reply::new(local_addr.clone())
            .write_to(&mut stream)
            .await
            .map_err(|err| Error::io(err).with_context("write server reply: connect succeeded"))?;

        tracing::trace!(
            %destination,
            %local_addr,
            ?peer_addr,
            "socks5 server: connect: reply sent, start serving source-target pipe",
        );

        self.service
            .serve(
                ctx,
                ProxyRequest {
                    source: stream,
                    target,
                },
            )
            .await
            .map_err(|err| Error::service(err).with_context("serve connect pipe"))
    }
}

#[cfg(test)]
pub(crate) use test::MockConnector;

#[cfg(test)]
mod test {
    use super::*;
    use std::{ops::DerefMut, sync::Arc};
    use tokio::sync::Mutex;

    #[derive(Debug)]
    pub(crate) struct MockConnector {
        reply: MockReply,
    }

    #[derive(Debug)]
    enum MockReply {
        Success {
            local_addr: Authority,
            target: Option<Arc<Mutex<tokio_test::io::Mock>>>,
        },
        Error(ReplyKind),
    }

    impl MockConnector {
        pub(crate) fn new(local_addr: Authority) -> Self {
            Self {
                reply: MockReply::Success {
                    local_addr,
                    target: None,
                },
            }
        }
        pub(crate) fn new_err(reply: ReplyKind) -> Self {
            Self {
                reply: MockReply::Error(reply),
            }
        }

        pub(crate) fn with_proxy_data(mut self, target: tokio_test::io::Mock) -> Self {
            self.reply = match self.reply {
                MockReply::Success { local_addr, .. } => MockReply::Success {
                    local_addr,
                    target: Some(Arc::new(Mutex::new(target))),
                },
                MockReply::Error(_) => unreachable!(),
            };
            self
        }
    }

    impl<S, State> Socks5ConnectorSeal<S, State> for MockConnector
    where
        S: Stream + Unpin,
        State: Clone + Send + Sync + 'static,
    {
        async fn accept_connect(
            &self,
            _ctx: Context<State>,
            mut stream: S,
            _destination: Authority,
        ) -> Result<(), Error> {
            match &self.reply {
                MockReply::Success { local_addr, target } => {
                    Reply::new(local_addr.clone())
                        .write_to(&mut stream)
                        .await
                        .map_err(Error::io)?;

                    if let Some(target) = target.as_ref() {
                        let mut target = target.lock().await;
                        match tokio::io::copy_bidirectional(&mut stream, target.deref_mut()).await {
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
                MockReply::Error(reply_kind) => {
                    Reply::error_reply(*reply_kind)
                        .write_to(&mut stream)
                        .await
                        .map_err(Error::io)?;
                    Err(Error::aborted("mock abort").with_context(*reply_kind))
                }
            }
        }
    }
}
