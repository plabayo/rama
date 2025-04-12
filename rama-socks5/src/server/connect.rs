use rama_core::{
    Context, Service,
    error::{BoxError, ErrorExt, OpaqueError},
};
use rama_net::{address::Authority, client::EstablishedClientConnection, stream::Stream};
use rama_tcp::client::{Request as TcpRequest, service::TcpConnector};
use std::fmt;

use super::Error;
use crate::proto::{ReplyKind, server::Reply};

/// Types which can be used as socks5 connect drivers on the server side.
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
        tracing::debug!(
            %destination,
            "socks5 server: abort: command not supported: Connect",
        );

        Reply::error_reply(ReplyKind::CommandNotSupported)
            .write_to(&mut stream)
            .await
            .map_err(|err| {
                Error::io(err).with_context("write server reply: command not supported (connect)")
            })?;
        Err(Error::aborted("command not supported: Connect"))
    }
}

/// Default [`Connector`] type.
pub type DefaultConnector = Connector<TcpConnector, StreamForwardService>;

pub struct Connector<C, S> {
    connector: C,
    service: S,
}

pub struct ProxyRequest<S, T> {
    source: S,
    target: T,
}

// ^ TODO: this might be useful to move to somewhere else??

impl<C, S> Connector<C, S> {
    pub fn new(connector: C, service: S) -> Self {
        Self { connector, service }
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
pub struct StreamForwardService;

// ^ TODO: this might be useful to move to somewhere else??

impl StreamForwardService {
    #[inline]
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
    T: Stream + Unpin,
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
        tracing::debug!(
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

                // TODO: support more granular reply kinds, if possible
                Reply::error_reply(ReplyKind::ConnectionRefused)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: connect failed")
                    })?;
                return Err(Error::aborted("connect failed"));
            }
        };

        tracing::debug!(
            %destination,
            "socks5 server: connect: connection established, serve pipe",
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
