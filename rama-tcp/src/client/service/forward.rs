use super::TcpConnector;
use crate::client::Request as TcpRequest;
use rama_core::{
    Service,
    error::{BoxError, ErrorExt, OpaqueError},
    extensions::ExtensionsMut,
    rt::Executor,
    stream::Stream,
};
use rama_net::{
    address::HostWithPort,
    client::{ConnectorService, EstablishedClientConnection},
    proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
};

#[derive(Debug, Clone)]
enum ForwarderKind {
    Static(HostWithPort),
    Dynamic,
}

/// A TCP forwarder.
#[derive(Debug, Clone)]
pub struct Forwarder<C> {
    kind: ForwarderKind,
    connector: C,
}

/// Default [`Forwarder`].
pub type DefaultForwarder = Forwarder<super::TcpConnector>;

impl DefaultForwarder {
    /// Create a new static forwarder for the given target [`HostWithPort`]
    pub fn new(exec: Executor, target: impl Into<HostWithPort>) -> Self {
        Self {
            kind: ForwarderKind::Static(target.into()),
            connector: TcpConnector::new(exec),
        }
    }

    /// Create a new dynamic forwarder, which will fetch the target from the [`Extensions`]
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    #[must_use]
    pub fn ctx(exec: Executor) -> Self {
        Self {
            kind: ForwarderKind::Dynamic,
            connector: TcpConnector::new(exec),
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
    pub fn with_connector<T>(self, connector: T) -> Forwarder<T> {
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
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, source: T) -> Result<Self::Output, Self::Error> {
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
        let extensions = source.extensions().clone();
        let req = TcpRequest::new_with_extensions(authority.clone(), extensions);

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
