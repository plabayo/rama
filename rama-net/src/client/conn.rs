use rama_core::{Context, Service, error::BoxError, service::BoxService};
use std::fmt;

/// The established connection to a server returned for the http client to be used.
pub struct EstablishedClientConnection<S, State, Request> {
    /// The [`Context`] of the `Request` for which a connection was established.
    pub ctx: Context<State>,
    /// The `Request` for which a connection was established.
    pub req: Request,
    /// The established connection stream/service/... to the server.
    pub conn: S,
}

impl<S: fmt::Debug, State: fmt::Debug, Request: fmt::Debug> fmt::Debug
    for EstablishedClientConnection<S, State, Request>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedClientConnection")
            .field("ctx", &self.ctx)
            .field("req", &self.req)
            .field("conn", &self.conn)
            .finish()
    }
}

impl<S: Clone, State: Clone, Request: Clone> Clone
    for EstablishedClientConnection<S, State, Request>
{
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            req: self.req.clone(),
            conn: self.conn.clone(),
        }
    }
}

/// Glue trait that is used as the Connector trait bound for
/// clients establishing a connection on one layer or another.
///
/// Can also be manually implemented as an alternative [`Service`] trait,
/// but from a Rama POV it is mostly used for UX trait bounds.
pub trait ConnectorService<State, Request>: Send + Sync + 'static {
    /// Connection returned by the [`ConnectorService`]
    type Connection;
    /// Error returned in case of connection / setup failure
    type Error: Into<BoxError>;

    /// Establish a connection, which often involves some kind of handshake,
    /// or connection revival.
    fn connect(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, State, Request>, Self::Error>,
    > + Send
    + '_;
}

impl<S, State, Request, Connection> ConnectorService<State, Request> for S
where
    S: Service<
            State,
            Request,
            Response = EstablishedClientConnection<Connection, State, Request>,
            Error: Into<BoxError>,
        >,
{
    type Connection = Connection;
    type Error = S::Error;

    fn connect(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, State, Request>, Self::Error>,
    > + Send
    + '_ {
        self.serve(ctx, req)
    }
}

/// A [`ConnectorService`] which only job is to [`Box`]
/// the created [`Service`] by the inner [`ConnectorService`].
pub struct BoxedConnectorService<S>(S);

impl<S> BoxedConnectorService<S> {
    /// Create a new [`BoxedConnector`].
    pub fn new(connector: S) -> Self {
        Self(connector)
    }
}

impl<S: fmt::Debug> fmt::Debug for BoxedConnectorService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BoxedConnectorService")
            .field(&self.0)
            .finish()
    }
}

impl<S: Clone> Clone for BoxedConnectorService<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, State, Request, Svc> Service<State, Request> for BoxedConnectorService<S>
where
    S: Service<
            State,
            Request,
            Response = EstablishedClientConnection<Svc, State, Request>,
            Error: Into<BoxError>,
        >,
    Svc: Service<State, Request>,
    State: Send + 'static,
    Request: Send + 'static,
{
    type Response = EstablishedClientConnection<
        BoxService<State, Request, Svc::Response, Svc::Error>,
        State,
        Request,
    >;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection {
            ctx,
            req,
            conn: svc,
        } = self.0.serve(ctx, req).await?;
        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: svc.boxed(),
        })
    }
}
