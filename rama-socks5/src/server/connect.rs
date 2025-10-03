use rama_core::extensions::ExtensionsMut;
use rama_core::telemetry::tracing::{self, Instrument, trace_span};
use rama_core::{Service, error::BoxError, stream::Stream};
use rama_net::client::ConnectorService;
use rama_net::{
    address::Authority,
    client::EstablishedClientConnection,
    proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
    stream::Socket,
};
use rama_tcp::client::{
    Request as TcpRequest,
    service::{DefaultForwarder, TcpConnector},
};
use rama_utils::macros::generate_field_setters;
use std::{fmt, time::Duration};

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
pub trait Socks5Connector<S>: Socks5ConnectorSeal<S> {}

impl<S, C> Socks5Connector<S> for C where C: Socks5ConnectorSeal<S> {}

pub trait Socks5ConnectorSeal<S>: Send + Sync + 'static {
    fn accept_connect(
        &self,

        stream: S,
        destination: Authority,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_;
}

impl<S> Socks5ConnectorSeal<S> for ()
where
    S: Stream + Unpin,
{
    async fn accept_connect(&self, mut stream: S, destination: Authority) -> Result<(), Error> {
        tracing::trace!(
            "socks5 server w/ destination {destination}: abort: command not supported: Connect",
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

/// Proxy Forward [`Socks5Connector`] implementation,
/// which actually is able to accept connect requests and process them.
///
/// The [`Default`] implementation establishes a connection for the requested
/// destination [`Authority`] and pipes the incoming [`Stream`] with the established
/// outgoing [`Stream`] by copying the bytes without doing anyting else with them.
///
/// You can customise the [`Connector`] fully by creating it using [`Connector::new`]
/// or overwrite any of the default components using either or both of [`Connector::with_connector`]
/// and [`Connector::with_service`].
///
/// ## Lazy Connectors
///
/// Please use [`LazyConnector`] in case you do not want the connctor to establish
/// a connection yet and instead only want to do so once you have the first request,
/// which can be useful for things such as MITM socks5 proxies for http(s) traffic.
pub struct Connector<C, S> {
    connector: C,
    service: S,

    // if true it uses the 0.0.0.0:0 bind address
    // instead of the actual local address used to connect
    hide_local_address: bool,

    // ideally we would not do this and instead rely on the timeout layer...
    // sadly however because of the "state" concept it is a bit impossible to use that here,
    // without also knowing the state.. Another good reason to get rid of that context everywhere,
    // see: <https://github.com/plabayo/rama/issues/462>
    connect_timeout: Option<Duration>,
}

impl<C, S> Connector<C, S> {
    /// Create a new [`Connector`].
    ///
    /// In case you only wish to overwrite one of these components
    /// you can also use a [`Default`] [`Connector`] and overwrite the specific component
    /// using [`Connector::with_connector`] or [`Connector::with_service`].
    pub fn new(connector: C, service: S) -> Self {
        Self {
            connector,
            service,
            hide_local_address: false,
            connect_timeout: None,
        }
    }

    /// Define whether or not the local address is exposed as the bind address in the reply,
    /// by default it is exposed.
    pub fn set_hide_local_address(&mut self, hide: bool) -> &mut Self {
        self.hide_local_address = hide;
        self
    }

    /// Define whether or not the local address is exposed as the bind address in the reply,
    /// by default it is exposed.
    #[must_use]
    pub fn with_hide_local_address(mut self, hide: bool) -> Self {
        self.hide_local_address = hide;
        self
    }

    generate_field_setters!(connect_timeout, Duration);
}

impl<C, S> Connector<C, S> {
    /// Overwrite the [`Connector`]'s connector [`Service`]
    /// used to establish a Tcp connection used as the
    /// [`Stream`] in the direction from target to source.
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (Context, TcpRequest)
    ///     -> (EstablishedConnection<T, TcpRequest>, Into<BoxError>)
    /// ```
    pub fn with_connector<T>(self, connector: T) -> Connector<T, S> {
        Connector {
            connector,
            service: self.service,
            hide_local_address: self.hide_local_address,
            connect_timeout: self.connect_timeout,
        }
    }

    /// Overwrite the [`Connector`]'s [`Service`]
    /// used to actually do the proxy between the source and target [`Stream`].
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (Context, ProxyRequest) -> ((), Into<BoxError>)
    /// ```
    pub fn with_service<T>(self, service: T) -> Connector<C, T> {
        Connector {
            connector: self.connector,
            service,
            hide_local_address: self.hide_local_address,
            connect_timeout: self.connect_timeout,
        }
    }
}

impl Default for DefaultConnector {
    fn default() -> Self {
        Self {
            connector: TcpConnector::default(),
            service: StreamForwardService::default(),
            hide_local_address: false,
            connect_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl<C: fmt::Debug, S: fmt::Debug> fmt::Debug for Connector<C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connector")
            .field("connector", &self.connector)
            .field("service", &self.service)
            .field("hide_local_address", &self.hide_local_address)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl<C: Clone, S: Clone> Clone for Connector<C, S> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            service: self.service.clone(),
            hide_local_address: self.hide_local_address,
            connect_timeout: self.connect_timeout,
        }
    }
}

impl<S, InnerConnector, StreamService> Socks5ConnectorSeal<S>
    for Connector<InnerConnector, StreamService>
where
    S: Stream + Unpin + ExtensionsMut,
    InnerConnector: ConnectorService<TcpRequest, Connection: Stream + Socket + Unpin>,
    StreamService:
        Service<ProxyRequest<S, InnerConnector::Connection>, Response = (), Error: Into<BoxError>>,
{
    async fn accept_connect(&self, mut stream: S, destination: Authority) -> Result<(), Error> {
        tracing::trace!(
            "socks5 server w/ destination {destination}: connect: try to establish connection",
        );

        // TODO: replace with timeout layer once possible

        let connect_future = self.connector.connect(TcpRequest::new(
            destination.clone(),
            stream.take_extensions(),
        ));

        let result = match self.connect_timeout {
            Some(duration) => match tokio::time::timeout(duration, connect_future).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::debug!("connect future timed out: {err:?}",);
                    let reply_kind = ReplyKind::TtlExpired;
                    Reply::error_reply(reply_kind)
                        .write_to(&mut stream)
                        .await
                        .map_err(|err| {
                            Error::io(err).with_context("write server reply: connect failed")
                        })?;
                    return Err(Error::aborted("connect failed").with_context(reply_kind));
                }
            },
            None => connect_future.await,
        };

        let EstablishedClientConnection { conn: target, .. } = match result {
            Ok(ecs) => ecs,
            Err(err) => {
                let err: BoxError = err.into();
                tracing::debug!(
                    "socks5 server w/ destination {destination}: abort: connect failed: {err:?}",
                );

                let reply_kind = (&err).into();
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: connect failed")
                    })?;
                return Err(Error::aborted("connect failed")
                    .with_context(reply_kind)
                    .with_source(err));
            }
        };

        let local_addr = target
            .local_addr()
            .map(Into::into)
            .inspect_err(|err| {
                tracing::debug!(
                    "socks5 server w/ destination: {destination}: connect: failed to retrieve local addr from established conn, use default '0.0.0.0:0': {err}",
                );
            })
            .unwrap_or(Authority::default_ipv4(0));
        let peer_addr = target.peer_addr();

        tracing::trace!(
            "socks5 server w/ destination {destination}: connect: connection established, serve pipe: {local_addr} <-> {peer_addr:?}",
        );

        Reply::new(if self.hide_local_address {
            Authority::default_ipv4(0)
        } else {
            local_addr.clone()
        })
        .write_to(&mut stream)
        .await
        .map_err(|err| Error::io(err).with_context("write server reply: connect succeeded"))?;

        tracing::trace!(
            "socks5 server w/ destination {destination}: connect: reply sent, start serving source-target pipe: {local_addr} <-> {peer_addr:?}",
        );

        self.service
            .serve(ProxyRequest {
                source: stream,
                target,
            })
            .instrument(trace_span!("socks5::connect::proxy::serve"))
            .await
            .map_err(|err| Error::service(err).with_context("serve connect pipe"))
    }
}

/// Lazy [`Socks5Connector`] implementation,
/// which accepts a connection but does delegates all the work
/// on the egress side to the inner (stream) service.
///
/// This connector is useful for use-cases such as MITM proxies,
/// or proxy routers that need more information from the proxied traffic
/// itself to know what to do with it prior to be able to establish a connection.
///
/// ## Default Connectors
///
/// Please use [`Connector`] for a more common use-case for socks5 proxies,
/// where it does establish a connection eagerly, ready for piping
/// between incoming src stream and (established) target stream.
pub struct LazyConnector<S> {
    service: S,
}

impl<S> LazyConnector<S> {
    /// Create a new [`LazyConnector`].
    ///
    /// The [default `LazyConnector`] forwards the stream as-is to the
    /// received proxy target.
    pub fn new(service: S) -> Self {
        Self { service }
    }
}

impl Default for LazyConnector<DefaultForwarder> {
    fn default() -> Self {
        Self {
            service: DefaultForwarder::ctx(),
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for LazyConnector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyConnector")
            .field("service", &self.service)
            .finish()
    }
}

impl<S: Clone> Clone for LazyConnector<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

impl<S, StreamService> Socks5ConnectorSeal<S> for LazyConnector<StreamService>
where
    S: Stream + Unpin + ExtensionsMut,
    StreamService: Service<S, Response = (), Error: Into<BoxError>>,
{
    async fn accept_connect(&self, mut stream: S, destination: Authority) -> Result<(), Error> {
        tracing::trace!(
            "socks5 server w/ destination {destination}: lazy connect: try to establish connection",
        );

        Reply::new(Authority::default_ipv4(0))
            .write_to(&mut stream)
            .await
            .map_err(|err| Error::io(err).with_context("write server reply: connect succeeded"))?;

        tracing::trace!(
            "socks5 server w/ destination {destination}: lazy connect: reply sent, delegate to inner stream service",
        );

        stream.extensions_mut().insert(ProxyTarget(destination));

        self.service
            .serve(stream)
            .instrument(trace_span!("socks5::connect::lazy::serve"))
            .await
            .map_err(|err| Error::service(err).with_context("inner stream (proxy) service"))
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

    impl<S> Socks5ConnectorSeal<S> for MockConnector
    where
        S: Stream + Unpin,
    {
        async fn accept_connect(
            &self,
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
                                    "(proxy) I/O stream forwarder finished: bytes north = {}; bytes south = {}",
                                    bytes_copied_north,
                                    bytes_copied_south,
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
