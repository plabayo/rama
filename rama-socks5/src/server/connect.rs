use rama_core::extensions::ExtensionsRef;
use rama_core::io::BridgeIo;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument, trace_span};
use rama_core::{
    Layer, Service,
    error::BoxError,
    io::Io,
    layer::{TimeoutLayer, timeout::DefaultTimeout},
};
#[cfg(feature = "dns")]
use rama_dns::client::DnsConnector;
use rama_net::address::HostWithPort;
use rama_net::client::{ConnectRequest, ConnectorService, ConnectorTarget};
use rama_net::{client::EstablishedClientConnection, proxy::IoForwardService, stream::SocketInfo};
use rama_tcp::client::service::TcpConnector;
use rama_tcp::proxy::IoToProxyBridgeIo;
use rama_utils::macros::generate_set_and_with;
use std::time::Duration;

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
        destination: HostWithPort,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_;
}

impl<S> Socks5ConnectorSeal<S> for ()
where
    S: Io + Unpin,
{
    async fn accept_connect(&self, mut stream: S, destination: HostWithPort) -> Result<(), Error> {
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
#[cfg(feature = "dns")]
pub type DefaultConnector = Connector<DefaultTimeout<DnsConnector<TcpConnector>>, IoForwardService>;

/// Default [`Connector`] type.
#[cfg(not(feature = "dns"))]
pub type DefaultConnector = Connector<DefaultTimeout<TcpConnector>, IoForwardService>;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Proxy Forward [`Socks5Connector`] implementation,
/// which actually is able to accept connect requests and process them.
///
/// The [`Default`] implementation establishes a connection for the requested
/// destination [`HostWithPort`] and pipes the incoming [`Io`] with the established
/// outgoing [`Io`] by copying the bytes without doing anything else with them.
///
/// You can customise the [`Connector`] fully by creating it using
/// [`Connector::new`] or overwrite any of the default components using either or both of
/// [`Connector::with_connector`] and [`Connector::with_service`].
///
/// ## Lazy Connectors
///
/// Use [`LazyConnector`] only when application bytes are required before the
/// egress target can be selected. MITM proxies with a target from the SOCKS5
/// handshake should normally use this connector and inspect the resulting
/// [`BridgeIo`] with Rama's Relay/Peek services.
///
/// Connection policy belongs in the connector stack. Wrap a custom connector
/// in [`TimeoutLayer`] when its connection attempts should be bounded.
#[derive(Debug, Clone)]
pub struct Connector<C, S> {
    connector: C,
    service: S,

    // if true it uses the 0.0.0.0:0 bind address
    // instead of the actual local address used to connect
    hide_local_address: bool,
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
        }
    }

    generate_set_and_with! {
        /// Define whether or not the local address is exposed as the bind address in the reply,
        /// by default it is exposed.
        pub fn hide_local_address(mut self, hide: bool) -> Self {
            self.hide_local_address = hide;
            self
        }
    }
}

impl<C, S> Connector<C, S> {
    /// Overwrite the [`Connector`]'s connector [`Service`]
    /// used to establish the egress [`Io`] in the direction from target to source.
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (ConnectRequest)
    ///     -> (EstablishedConnection<T, ConnectRequest>, Into<BoxError>)
    /// ```
    ///
    /// Replacing a [`DefaultConnector`]'s connector removes its default
    /// connect timeout. Wrap the new connector in [`TimeoutLayer`] when its
    /// connection attempts should be bounded.
    pub fn with_connector<T>(self, connector: T) -> Connector<T, S> {
        Connector {
            connector,
            service: self.service,
            hide_local_address: self.hide_local_address,
        }
    }

    /// Overwrite the [`Connector`]'s [`Service`]
    /// used to actually do the proxy between the source and target [`Io`].
    ///
    /// Any [`Service`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (BridgeIo) -> ((), Into<BoxError>)
    /// ```
    pub fn with_service<T>(self, service: T) -> Connector<C, T> {
        Connector {
            connector: self.connector,
            service,
            hide_local_address: self.hide_local_address,
        }
    }
}

impl DefaultConnector {
    /// Create a [`DefaultConnector`] whose forward bridge observes graceful
    /// shutdown via the given [`Executor`].
    #[must_use]
    pub fn default_with_exec(exec: Executor) -> Self {
        #[cfg(feature = "dns")]
        let connector = DnsConnector::new(TcpConnector::default());
        #[cfg(not(feature = "dns"))]
        let connector = TcpConnector::default();
        let connector = TimeoutLayer::new(DEFAULT_CONNECT_TIMEOUT).into_layer(connector);

        Self {
            connector,
            service: IoForwardService::new(exec),
            hide_local_address: false,
        }
    }
}

impl Default for DefaultConnector {
    fn default() -> Self {
        Self::default_with_exec(Executor::default())
    }
}

impl<S, InnerConnector, StreamService> Socks5ConnectorSeal<S>
    for Connector<InnerConnector, StreamService>
where
    S: Io + Unpin + ExtensionsRef,
    InnerConnector: ConnectorService<ConnectRequest, Connection: Io + Unpin + ExtensionsRef>,
    StreamService: Service<BridgeIo<S, InnerConnector::Connection>, Error: Into<BoxError>>,
{
    async fn accept_connect(
        &self,
        mut ingress_stream: S,
        destination: HostWithPort,
    ) -> Result<(), Error> {
        tracing::trace!(
            "socks5 server w/ destination {destination}: connect: try to establish connection",
        );

        ingress_stream
            .extensions()
            .insert(ConnectorTarget(destination.clone()));

        // Isolate connector-local routing metadata from the authoritative
        // target exposed by the ingress stream.
        let EstablishedClientConnection {
            conn: egress_stream,
            ..
        } = match self
            .connector
            .connect(ConnectRequest::new_with_extensions(
                destination.clone(),
                ingress_stream.extensions().fork(),
            ))
            .await
        {
            Ok(ecs) => ecs,
            Err(err) => {
                let err: BoxError = err.into();
                tracing::debug!(
                    "socks5 server w/ destination {destination}: abort: connect failed: {err:?}",
                );

                let reply_kind = (&err).into();
                Reply::error_reply(reply_kind)
                    .write_to(&mut ingress_stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: connect failed")
                    })?;
                return Err(Error::aborted("connect failed")
                    .with_context(reply_kind)
                    .with_source(err));
            }
        };

        let socket_info = egress_stream.extensions().get_ref::<SocketInfo>();
        let egress_addr_local = socket_info
            .and_then(SocketInfo::local_addr)
            .map(Into::into)
            .unwrap_or_else(|| {
                tracing::debug!(
                    "socks5 server w/ destination: {destination}: connect: established conn has no local SocketInfo addr, use default '0.0.0.0:0'",
                );
                HostWithPort::default_ipv4(0)
            });
        let egress_addr = socket_info.map(SocketInfo::peer_addr);

        tracing::trace!(
            "socks5 server w/ destination {destination}: connect: connection established, serve pipe: {egress_addr_local} <-> {egress_addr:?}",
        );

        Reply::new(if self.hide_local_address {
            HostWithPort::default_ipv4(0)
        } else {
            egress_addr_local.clone()
        })
        .write_to(&mut ingress_stream)
        .await
        .map_err(|err| Error::io(err).with_context("write server reply: connect succeeded"))?;

        tracing::trace!(
            "socks5 server w/ destination {destination}: connect: reply sent, start serving source-target pipe: {egress_addr_local} <-> {egress_addr:?}",
        );

        self.service
            .serve(BridgeIo(ingress_stream, egress_stream))
            .instrument(trace_span!("socks5::connect::proxy::serve"))
            .await
            .map(drop)
            .map_err(|err| Error::service(err).with_context("serve connect pipe"))
    }
}

/// Lazy [`Socks5Connector`] implementation,
/// which accepts a connection but delegates all the work
/// on the egress side to the inner (stream) service.
///
/// This connector is useful for proxy routers that need application bytes before
/// they can select an egress target. A regular MITM proxy should instead use
/// [`Connector`] and inspect its pre-established [`BridgeIo`].
///
/// ## Default Connectors
///
/// Please use [`Connector`] for the more common SOCKS5 proxy use case. It
/// establishes the destination connection before returning a successful reply,
/// ready for piping between the incoming and established streams.
#[derive(Debug, Clone)]
pub struct LazyConnector<S> {
    service: S,
}

impl<S> LazyConnector<S> {
    /// Create a new [`LazyConnector`].
    ///
    /// The default [`LazyConnector`] forwards the stream as-is to the
    /// received proxy target.
    pub fn new(service: S) -> Self {
        Self { service }
    }
}

impl LazyConnector<IoToProxyBridgeIo<IoForwardService>> {
    /// Create a [`LazyConnector`] whose forward bridge observes graceful
    /// shutdown via the given [`Executor`].
    #[must_use]
    pub fn default_with_exec(exec: Executor) -> Self {
        Self {
            service: IoToProxyBridgeIo::extension_connector_target(IoForwardService::new(exec)),
        }
    }
}

impl Default for LazyConnector<IoToProxyBridgeIo<IoForwardService>> {
    #[inline(always)]
    fn default() -> Self {
        Self::default_with_exec(Executor::default())
    }
}

impl<S, StreamService> Socks5ConnectorSeal<S> for LazyConnector<StreamService>
where
    S: Io + Unpin + ExtensionsRef,
    StreamService: Service<S, Error: Into<BoxError>>,
{
    async fn accept_connect(&self, mut stream: S, destination: HostWithPort) -> Result<(), Error> {
        tracing::trace!(
            "socks5 server w/ destination {destination}: lazy connect: acknowledge without establishing egress connection",
        );

        Reply::new(HostWithPort::default_ipv4(0))
            .write_to(&mut stream)
            .await
            .map_err(|err| Error::io(err).with_context("write server reply: connect succeeded"))?;

        tracing::trace!(
            "socks5 server w/ destination {destination}: lazy connect: reply sent, delegate to inner stream service",
        );

        stream.extensions().insert(ConnectorTarget(destination));

        self.service
            .serve(stream)
            .instrument(trace_span!("socks5::connect::lazy::serve"))
            .await
            .map(drop)
            .map_err(|err| Error::service(err).with_context("inner stream (proxy) service"))
    }
}

#[cfg(test)]
pub(crate) use test::MockConnector;

#[cfg(test)]
mod test {
    #![expect(
        clippy::unreachable,
        reason = "test fixtures: arms gated on the mock variants the test sets up"
    )]

    use super::*;
    use rama_net::address::HostWithPort;
    use std::{ops::DerefMut, sync::Arc};
    use tokio::sync::Mutex;

    #[derive(Debug)]
    pub(crate) struct MockConnector {
        reply: MockReply,
    }

    #[derive(Debug)]
    enum MockReply {
        Success {
            local_addr: HostWithPort,
            target: Option<Arc<Mutex<tokio_test::io::Mock>>>,
        },
        Error(ReplyKind),
    }

    impl MockConnector {
        pub(crate) fn new(local_addr: HostWithPort) -> Self {
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
        S: Io + Unpin,
    {
        async fn accept_connect(
            &self,
            mut stream: S,
            _destination: HostWithPort,
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
