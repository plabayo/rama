use core::fmt;

use rama_core::{
    Service,
    extensions::{Extensions, ExtensionsRef},
    service::BoxService,
};

use super::ConnectionError;

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

impl<S, Input: ExtensionsRef> ExtensionsRef for EstablishedClientConnection<S, Input> {
    fn extensions(&self) -> &Extensions {
        self.input.extensions()
    }
}

/// Glue trait that is used as the Connector trait bound for
/// clients establishing a connection on one layer or another.
///
/// Can also be manually implemented as an alternative [`Service`] trait,
/// but from a Rama POV it is mostly used for UX trait bounds.
pub trait ConnectorService<Input>: Send + Sync + 'static {
    /// Connection returned by the [`ConnectorService`]
    type Connection: Send + ExtensionsRef;

    /// Establish a connection, which often involves some kind of handshake,
    /// or connection revival.
    ///
    /// Service-specific errors are normalized into [`ConnectionError`] at this
    /// boundary so connector combinators can reason about connection failures
    /// without knowing every concrete error type in the stack.
    fn connect(
        &self,
        input: Input,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, Input>, ConnectionError>,
    > + Send
    + '_;
}

impl<S, Input, Connection> ConnectorService<Input> for S
where
    S: Service<
            Input,
            Output = EstablishedClientConnection<Connection, Input>,
            Error: Into<ConnectionError>,
        >,
    Connection: Send + ExtensionsRef,
{
    type Connection = Connection;

    fn connect(
        &self,
        input: Input,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, Input>, ConnectionError>,
    > + Send
    + '_ {
        let future = self.serve(input);
        async move { future.await.map_err(Into::into) }
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
    S: ConnectorService<Input, Connection = Svc>,
    Svc: Service<Input>,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<BoxService<Input, Svc::Output, Svc::Error>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn: svc } = self.0.connect(input).await?;
        Ok(EstablishedClientConnection {
            input,
            conn: svc.boxed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use core::{convert::Infallible, fmt};

    use rama_core::{ServiceInput, extensions::Extension};

    use super::*;
    use crate::client::{ConnectionErrorDomain, ConnectionErrorKind};

    #[derive(Debug)]
    struct LegacyError;

    #[derive(Debug, Extension)]
    struct Marker(u32);

    impl fmt::Display for LegacyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("legacy connector error")
        }
    }

    impl core::error::Error for LegacyError {}

    #[derive(Debug)]
    struct LegacyFailingConnector;

    impl Service<()> for LegacyFailingConnector {
        type Output = EstablishedClientConnection<ServiceInput<()>, ()>;
        type Error = rama_core::error::BoxError;

        async fn serve(&self, _input: ()) -> Result<Self::Output, Self::Error> {
            Err(Box::new(LegacyError))
        }
    }

    #[derive(Debug)]
    struct ClassifiedFailingConnector;

    impl Service<()> for ClassifiedFailingConnector {
        type Output = EstablishedClientConnection<ServiceInput<()>, ()>;
        type Error = ConnectionError;

        async fn serve(&self, _input: ()) -> Result<Self::Output, Self::Error> {
            Err(ConnectionError::transport(
                LegacyError,
                ConnectionErrorKind::Unavailable,
            ))
        }
    }

    #[derive(Debug)]
    struct SuccessfulConnector;

    impl Service<usize> for SuccessfulConnector {
        type Output = EstablishedClientConnection<ServiceInput<()>, usize>;
        type Error = Infallible;

        async fn serve(&self, input: usize) -> Result<Self::Output, Self::Error> {
            Ok(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        }
    }

    #[tokio::test]
    async fn connector_service_normalizes_legacy_errors() {
        let error = LegacyFailingConnector.connect(()).await.unwrap_err();

        assert_eq!(error.domain(), ConnectionErrorDomain::Unknown);
        assert_eq!(error.kind(), ConnectionErrorKind::Other);
        assert_eq!(error.to_string(), "legacy connector error");
    }

    #[tokio::test]
    async fn connector_service_preserves_classified_errors() {
        let error = ClassifiedFailingConnector.connect(()).await.unwrap_err();

        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(error.to_string(), "legacy connector error");
    }

    #[tokio::test]
    async fn connector_service_preserves_successful_input() {
        let established = SuccessfulConnector.connect(42).await.unwrap();

        assert_eq!(established.input, 42);
    }

    #[tokio::test]
    async fn established_connection_exposes_input_extensions() {
        let established = EstablishedClientConnection {
            input: ServiceInput::new(()),
            conn: ServiceInput::new(()),
        };
        established.input.extensions().insert(Marker(7));

        assert_eq!(
            established.extensions().get_ref::<Marker>().map(|m| m.0),
            Some(7)
        );
    }
}
