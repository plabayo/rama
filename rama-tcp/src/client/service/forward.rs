use super::TcpConnector;
use crate::client::Request as TcpRequest;
use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    io::{BridgeIo, Io},
    rt::Executor,
};
use rama_net::{
    address::HostWithPort,
    client::{ConnectorService, EstablishedClientConnection},
    proxy::{ProxyTarget, StreamForwardService},
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
    T: Io + Unpin + ExtensionsMut,
    C: ConnectorService<crate::client::Request, Connection: Io + Unpin>,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, ingress_stream: T) -> Result<Self::Output, Self::Error> {
        let authority = match &self.kind {
            ForwarderKind::Static(target) => target.clone(),
            ForwarderKind::Dynamic => ingress_stream
                .extensions()
                .get::<ProxyTarget>()
                .map(|f| f.0.clone())
                .context("missing forward authority")?,
        };

        // Clone them here so we also have them on (ingress) stream still
        let extensions = ingress_stream.extensions().clone();
        let req = TcpRequest::new_with_extensions(authority.clone(), extensions);

        let EstablishedClientConnection {
            conn: egress_stream,
            ..
        } = self
            .connector
            .connect(req)
            .await
            .context("establish tcp connection")
            .context_field("authority", authority)?;

        StreamForwardService::default()
            .serve(BridgeIo(ingress_stream, egress_stream))
            .await
    }
}
