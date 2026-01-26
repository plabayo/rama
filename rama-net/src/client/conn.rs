use rama_core::{Service, error::BoxError, extensions::ExtensionsMut, service::BoxService};
use std::fmt;

#[derive(Clone)]
/// The established connection to a server returned for the http client to be used.
pub struct EstablishedClientConnection<S, Input> {
    /// The `Input` for which a connection was established.
    pub input: Input,
    /// The established connection stream/service/... to the server.
    pub conn: S,
}

impl<S: fmt::Debug, Input: fmt::Debug> fmt::Debug for EstablishedClientConnection<S, Input> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedClientConnection")
            .field("input", &self.input)
            .field("conn", &self.conn)
            .finish()
    }
}

/// Glue trait that is used as the Connector trait bound for
/// clients establishing a connection on one layer or another.
///
/// Can also be manually implemented as an alternative [`Service`] trait,
/// but from a Rama POV it is mostly used for UX trait bounds.
pub trait ConnectorService<Input>: Send + Sync + 'static {
    /// Connection returned by the [`ConnectorService`]
    type Connection: Send + ExtensionsMut;
    /// Error returned in case of connection / setup failure
    type Error: Into<BoxError> + Send + 'static;

    /// Establish a connection, which often involves some kind of handshake,
    /// or connection revival.
    fn connect(
        &self,
        input: Input,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, Input>, Self::Error>,
    > + Send
    + '_;
}

impl<S, Input, Connection> ConnectorService<Input> for S
where
    S: Service<
            Input,
            Output = EstablishedClientConnection<Connection, Input>,
            Error: Into<BoxError>,
        >,
    Connection: Send + ExtensionsMut,
{
    type Connection = Connection;
    type Error = S::Error;

    fn connect(
        &self,
        input: Input,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, Input>, Self::Error>,
    > + Send
    + '_ {
        self.serve(input)
    }
}

/// A [`ConnectorService`] which only job is to [`Box`]
/// the created [`Service`] by the inner [`ConnectorService`].
#[derive(Debug, Clone)]
pub struct BoxedConnectorService<S>(S);

impl<S> BoxedConnectorService<S> {
    /// Create a new [`BoxedConnectorService`].
    pub fn new(connector: S) -> Self {
        Self(connector)
    }
}

impl<S, Input, Svc> Service<Input> for BoxedConnectorService<S>
where
    S: Service<Input, Output = EstablishedClientConnection<Svc, Input>, Error: Into<BoxError>>,
    Svc: Service<Input>,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<BoxService<Input, Svc::Output, Svc::Error>, Input>;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn: svc } = self.0.serve(input).await?;
        Ok(EstablishedClientConnection {
            input,
            conn: svc.boxed(),
        })
    }
}
