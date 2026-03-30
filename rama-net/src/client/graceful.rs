use rama_core::{
    Service,
    extensions::ExtensionsMut,
    io::{CancelIo, GracefulIo, Io},
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use super::{ConnectorService, EstablishedClientConnection};

/// A [`Service`] that wraps established client connections in [`GracefulIo`]
/// and injects a [`CancelIo`] extension into the connection.
#[derive(Debug, Clone)]
pub struct GracefulConnectorService<S> {
    inner: S,
}

impl<S> GracefulConnectorService<S> {
    /// Create a new [`GracefulConnectorService`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    /// Get a shared reference to the inner connector.
    pub const fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner connector.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume `self`, returning the inner connector.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S, Input> Service<Input> for GracefulConnectorService<S>
where
    S: ConnectorService<Input>,
    S::Connection: Io + ExtensionsMut,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<
        GracefulIo<WaitForCancellationFutureOwned, S::Connection>,
        Input,
    >;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, mut conn } = self.inner.connect(input).await?;
        let token = CancellationToken::new();
        conn.extensions_mut().insert(CancelIo(token.clone()));

        Ok(EstablishedClientConnection {
            input,
            conn: GracefulIo::new(token.cancelled_owned(), conn),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rama_core::{ServiceInput, extensions::ExtensionsRef, io::CancelIo};
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct EchoConnector;

    impl Service<()> for EchoConnector {
        type Output = EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, ()>;
        type Error = Infallible;

        async fn serve(&self, input: ()) -> Result<Self::Output, Self::Error> {
            let (stream, _peer) = tokio::io::duplex(64);
            Ok(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(stream),
            })
        }
    }

    #[tokio::test]
    async fn graceful_connector_injects_cancel_token() {
        let svc = GracefulConnectorService::new(EchoConnector);
        let EstablishedClientConnection { conn, .. } = svc.serve(()).await.unwrap();

        let cancel = conn.extensions().get::<CancelIo>().unwrap().clone();
        cancel.0.cancel();

        let mut conn = std::pin::pin!(conn);
        let err = conn.write_all(b"abc").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
