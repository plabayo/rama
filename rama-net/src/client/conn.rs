use rama_core::{Service, error::BoxError, extensions::ExtensionsMut, service::BoxService};
use std::fmt;

/// The established connection to a server returned for the http client to be used.
pub struct EstablishedClientConnection<S, Request> {
    /// The `Request` for which a connection was established.
    pub req: Request,
    /// The established connection stream/service/... to the server.
    pub conn: S,
}

impl<S: fmt::Debug, Request: fmt::Debug> fmt::Debug for EstablishedClientConnection<S, Request> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedClientConnection")
            .field("req", &self.req)
            .field("conn", &self.conn)
            .finish()
    }
}

impl<S: Clone, Request: Clone> Clone for EstablishedClientConnection<S, Request> {
    fn clone(&self) -> Self {
        Self {
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
pub trait ConnectorService<Request>: Send + Sync + 'static {
    /// Connection returned by the [`ConnectorService`]
    type Connection: Send + ExtensionsMut;
    /// Error returned in case of connection / setup failure
    type Error: Into<BoxError> + Send + 'static;

    /// Establish a connection, which often involves some kind of handshake,
    /// or connection revival.
    fn connect(
        &self,
        req: Request,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, Request>, Self::Error>,
    > + Send
    + '_;
}

impl<S, Request, Connection> ConnectorService<Request> for S
where
    S: Service<
            Request,
            Response = EstablishedClientConnection<Connection, Request>,
            Error: Into<BoxError>,
        >,
    Connection: Send + ExtensionsMut,
{
    type Connection = Connection;
    type Error = S::Error;

    fn connect(
        &self,

        req: Request,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, Request>, Self::Error>,
    > + Send
    + '_ {
        self.serve(req)
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

impl<S, Request, Svc> Service<Request> for BoxedConnectorService<S>
where
    S: Service<
            Request,
            Response = EstablishedClientConnection<Svc, Request>,
            Error: Into<BoxError>,
        >,
    Svc: Service<Request>,
    Request: Send + 'static,
{
    type Response =
        EstablishedClientConnection<BoxService<Request, Svc::Response, Svc::Error>, Request>;
    type Error = S::Error;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { req, conn: svc } = self.0.serve(req).await?;
        Ok(EstablishedClientConnection {
            req,
            conn: svc.boxed(),
        })
    }
}
