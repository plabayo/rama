use super::TcpConnector;
use crate::client::Request as TcpRequest;
use rama_core::{
    Context, Service,
    error::{BoxError, ErrorExt, OpaqueError},
};
use rama_net::{
    address::Authority,
    client::{ConnectorService, EstablishedClientConnection},
    proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
    stream::Stream,
};
use std::fmt;

#[derive(Debug, Clone)]
enum ForwarderKind {
    Static(Authority),
    Dynamic,
}

/// A TCP forwarder.
pub struct Forwarder<C> {
    kind: ForwarderKind,
    connector: C,
}

impl<C> fmt::Debug for Forwarder<C>
where
    C: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Forwarder")
            .field("kind", &self.kind)
            .field("connector", &self.connector)
            .finish()
    }
}

impl<C> Clone for Forwarder<C>
where
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            kind: self.kind.clone(),
            connector: self.connector.clone(),
        }
    }
}

/// Default [`Forwarder`].
pub type DefaultForwarder = Forwarder<super::TcpConnector>;

impl DefaultForwarder {
    /// Create a new static forwarder for the given target [`Authority`]
    pub fn new(target: impl Into<Authority>) -> Self {
        Self {
            kind: ForwarderKind::Static(target.into()),
            connector: TcpConnector::new(),
        }
    }

    /// Create a new dynamic forwarder, which will fetch the target from the [`Context`]
    pub fn ctx() -> Self {
        Self {
            kind: ForwarderKind::Dynamic,
            connector: TcpConnector::new(),
        }
    }
}

impl Forwarder<super::TcpConnector> {
    /// Set a custom "connector" for this forwarder, overwriting
    /// the default tcp forwarder which simply establishes a TCP connection.
    ///
    /// This can be useful for any custom middleware, but also to enrich with
    /// rama-provided services for tls connections, HAproxy client endoding
    /// or even an entirely custom tcp connector service.
    pub fn connector<T>(self, connector: T) -> Forwarder<T> {
        Forwarder {
            kind: self.kind,
            connector,
        }
    }
}

impl<S, T, C> Service<S, T> for Forwarder<C>
where
    S: Clone + Send + Sync + 'static,
    T: Stream + Unpin,
    C: ConnectorService<
            S,
            crate::client::Request,
            Connection: Stream + Unpin,
            Error: Into<BoxError>,
        >,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, ctx: Context<S>, source: T) -> Result<Self::Response, Self::Error> {
        let authority = match &self.kind {
            ForwarderKind::Static(target) => target.clone(),
            ForwarderKind::Dynamic => {
                ctx.get::<ProxyTarget>()
                    .map(|f| f.0.clone())
                    .ok_or_else(|| {
                        OpaqueError::from_display("missing forward authority").into_boxed()
                    })?
            }
        };

        let req = TcpRequest::new(authority.clone());

        let EstablishedClientConnection {
            ctx, conn: target, ..
        } = self.connector.connect(ctx, req).await.map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .with_context(|| format!("establish tcp connection to {authority}"))
        })?;

        let proxy_req = ProxyRequest { source, target };

        StreamForwardService::default()
            .serve(ctx, proxy_req)
            .await
            .map_err(Into::into)
    }
}
