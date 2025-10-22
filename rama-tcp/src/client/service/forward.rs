use super::TcpConnector;
use crate::client::Request as TcpRequest;
use rama_core::{
    Service,
    error::{BoxError, ErrorExt, OpaqueError},
    extensions::{Extensions, ExtensionsMut},
    stream::Stream,
};
use rama_net::{
    address::Authority,
    client::{ConnectorService, EstablishedClientConnection},
    proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
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
    #[must_use]
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

impl<T, C> Service<T> for Forwarder<C>
where
    T: Stream + Unpin + ExtensionsMut,
    C: ConnectorService<crate::client::Request, Connection: Stream + Unpin>,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, source: T) -> Result<Self::Response, Self::Error> {
        let authority = match &self.kind {
            ForwarderKind::Static(target) => target.clone(),
            ForwarderKind::Dynamic => source
                .extensions()
                .get::<ProxyTarget>()
                .map(|f| f.0.clone())
                .ok_or_else(|| {
                    OpaqueError::from_display("missing forward authority").into_boxed()
                })?,
        };

        // Clone them here so we also have them on source still
        let parent_extensions = source.extensions().clone().into_frozen_extensions();
        let extensions = Extensions::new().with_parent_extensions(parent_extensions);
        let req = TcpRequest::new(authority.clone(), extensions);

        let EstablishedClientConnection { conn: target, .. } =
            self.connector.connect(req).await.map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .with_context(|| format!("establish tcp connection to {authority}"))
            })?;

        let proxy_req = ProxyRequest { source, target };

        StreamForwardService::default()
            .serve(proxy_req)
            .await
            .map_err(Into::into)
    }
}
