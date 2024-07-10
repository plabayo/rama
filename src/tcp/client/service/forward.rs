use super::HttpConnector;
use crate::{
    error::{BoxError, ErrorExt, OpaqueError},
    net::{address::Authority, client::EstablishedClientConnection, stream::Stream},
    service::{Context, Service},
    tcp::client::Request as TcpRequest,
    tcp::utils::is_connection_error,
};

/// [`Forwarder`] using [`Forwarder::ctx`] requires this struct
/// to be present in the [`Context`].
#[derive(Debug, Clone)]
pub struct ForwardAuthority(Authority);

impl ForwardAuthority {
    /// Create a new [`ForwardAuthority`] for the given target [`Authority`].
    pub fn new(authority: impl Into<Authority>) -> Self {
        Self(authority.into())
    }
}

impl<A> From<A> for ForwardAuthority
where
    A: Into<Authority>,
{
    fn from(authority: A) -> Self {
        Self::new(authority)
    }
}

impl AsRef<Authority> for ForwardAuthority {
    fn as_ref(&self) -> &Authority {
        &self.0
    }
}

impl_deref!(ForwardAuthority: Authority);

#[derive(Debug, Clone)]
enum ForwarderKind {
    Static(Authority),
    Dynamic,
}

/// A TCP forwarder.
#[derive(Debug, Clone)]
pub struct Forwarder<C> {
    kind: ForwarderKind,
    connector: C,
}

impl Forwarder<super::HttpConnector> {
    /// Create a new static forwarder for the given target [`Authority`]
    pub fn new(target: impl Into<Authority>) -> Self {
        Self {
            kind: ForwarderKind::Static(target.into()),
            connector: HttpConnector::new(),
        }
    }

    /// Create a new dynamic forwarder, which will fetch the target from the [`Context`]
    pub fn ctx() -> Self {
        Self {
            kind: ForwarderKind::Dynamic,
            connector: HttpConnector::new(),
        }
    }
}

impl<C> Forwarder<C> {
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

impl<S, T, C, I> Service<S, T> for Forwarder<C>
where
    S: Send + Sync + 'static,
    T: Stream + Unpin,
    C: Service<
        S,
        crate::tcp::client::Request,
        Response = EstablishedClientConnection<I, S, TcpRequest>,
    >,
    C::Error: Into<BoxError>,
    I: Stream + Unpin,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, ctx: Context<S>, mut source: T) -> Result<Self::Response, Self::Error> {
        let authority = match &self.kind {
            ForwarderKind::Static(target) => target.clone(),
            ForwarderKind::Dynamic => ctx
                .get::<ForwardAuthority>()
                .map(|f| f.0.clone())
                .ok_or_else(|| {
                    OpaqueError::from_display("missing forward authority").into_boxed()
                })?,
        };

        let req = TcpRequest::new(authority.clone());

        let EstablishedClientConnection {
            conn: mut target, ..
        } = self.connector.serve(ctx, req).await.map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .with_context(|| format!("establish tcp connection to {authority}"))
        })?;

        match tokio::io::copy_bidirectional(&mut source, &mut target).await {
            Ok(_) => Ok(()),
            Err(err) => {
                if is_connection_error(&err) {
                    Ok(())
                } else {
                    Err(err.context("tcp forwarder").into())
                }
            }
        }
    }
}
