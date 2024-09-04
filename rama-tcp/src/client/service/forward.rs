use super::TcpConnector;
use crate::{client::Request as TcpRequest, utils::is_connection_error};
use rama_core::{
    error::{BoxError, ErrorExt, OpaqueError},
    Context, Layer, Service,
};
use rama_net::{
    address::Authority,
    client::{ConnectorService, EstablishedClientConnection},
    stream::Stream,
};
use rama_utils::macros::impl_deref;
use std::{fmt, ops::DerefMut};
use tokio::sync::Mutex;

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
pub struct Forwarder<C, L> {
    kind: ForwarderKind,
    connector: C,
    layer_stack: L,
}

impl<C, L> fmt::Debug for Forwarder<C, L>
where
    C: fmt::Debug,
    L: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Forwarder")
            .field("kind", &self.kind)
            .field("connector", &self.connector)
            .field("layer_stack", &self.layer_stack)
            .finish()
    }
}

impl<C, L> Clone for Forwarder<C, L>
where
    C: Clone,
    L: Clone,
{
    fn clone(&self) -> Self {
        Self {
            kind: self.kind.clone(),
            connector: self.connector.clone(),
            layer_stack: self.layer_stack.clone(),
        }
    }
}

impl Forwarder<super::TcpConnector, ()> {
    /// Create a new static forwarder for the given target [`Authority`]
    pub fn new(target: impl Into<Authority>) -> Self {
        Self {
            kind: ForwarderKind::Static(target.into()),
            connector: TcpConnector::new(),
            layer_stack: (),
        }
    }

    /// Create a new dynamic forwarder, which will fetch the target from the [`Context`]
    pub fn ctx() -> Self {
        Self {
            kind: ForwarderKind::Dynamic,
            connector: TcpConnector::new(),
            layer_stack: (),
        }
    }
}

impl<L> Forwarder<super::TcpConnector, L> {
    /// Set a custom "connector" for this forwarder, overwriting
    /// the default tcp forwarder which simply establishes a TCP connection.
    ///
    /// This can be useful for any custom middleware, but also to enrich with
    /// rama-provided services for tls connections, HAproxy client endoding
    /// or even an entirely custom tcp connector service.
    pub fn connector<T>(self, connector: T) -> Forwarder<T, L> {
        Forwarder {
            kind: self.kind,
            connector,
            layer_stack: self.layer_stack,
        }
    }
}

impl<C> Forwarder<C, ()> {
    /// Define an [`Layer`] (stack) to create a [`Service`] stack
    /// through which the established connection will have to pass
    /// before actually forwarding.
    pub fn layer<L>(self, layer_stack: L) -> Forwarder<C, L> {
        Forwarder {
            kind: self.kind,
            connector: self.connector,
            layer_stack,
        }
    }
}

impl<S, T, C, L> Service<S, T> for Forwarder<C, L>
where
    S: Send + Sync + 'static,
    T: Stream + Unpin,
    C: ConnectorService<
        S,
        crate::client::Request,
        Connection: Stream + Unpin,
        Error: Into<BoxError>,
    >,
    L: Layer<
            ForwarderService<C::Connection>,
            Service: Service<S, T, Response = (), Error: Into<BoxError>>,
        > + Send
        + Sync
        + 'static,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, ctx: Context<S>, source: T) -> Result<Self::Response, Self::Error> {
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
            ctx, conn: target, ..
        } = self.connector.connect(ctx, req).await.map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .with_context(|| format!("establish tcp connection to {authority}"))
        })?;

        let svc = ForwarderService(Mutex::new(target));
        let svc = self.layer_stack.layer(svc);

        svc.serve(ctx, source).await.map_err(Into::into)
    }
}

#[derive(Debug)]
pub struct ForwarderService<S>(Mutex<S>);

impl<State, I, S> Service<State, I> for ForwarderService<S>
where
    State: Send + Sync + 'static,
    I: Stream + Unpin,
    S: Stream + Unpin,
{
    type Response = ();
    type Error = OpaqueError;

    async fn serve(
        &self,
        _ctx: Context<State>,
        mut source: I,
    ) -> Result<Self::Response, Self::Error> {
        let mut target = self.0.lock().await;
        match tokio::io::copy_bidirectional(&mut source, target.deref_mut()).await {
            Ok(_) => Ok(()),
            Err(err) => {
                if is_connection_error(&err) {
                    Ok(())
                } else {
                    Err(err.context("tcp forwarder"))
                }
            }
        }
    }
}
