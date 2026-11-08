use super::{ConnectionError, ConnectorService, EstablishedClientConnection};

use rama_core::{
    Service,
    extensions::ExtensionsRef,
    graceful::{Cause, Scope, enter_scope},
    io::{AbortableIo, Io},
};

/// A [`Service`] that runs every established client connection in its own child [`Scope`]
/// and cuts its I/O once that scope is aborted, see [`AbortableIo`].
///
/// The child is made in the scope the connection runs in (a new root without one, see
/// [`enter_scope`]); the returned connection holds it, and aborting it is how the
/// connection is cut. A connection whose scope is closing gets an aborted one.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct AbortableConnectorService<S> {
    inner: S,
}

impl<S> AbortableConnectorService<S> {
    /// Create a new [`AbortableConnectorService`].
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

impl<S, Input> Service<Input> for AbortableConnectorService<S>
where
    S: ConnectorService<Input>,
    S::Connection: Io + ExtensionsRef,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<AbortableIo<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        let scope = enter_scope(conn.extensions()).unwrap_or_else(|_closed| {
            let scope = Scope::new();
            scope.abort(Cause::Reason("the connection's scope is closed"));
            scope
        });

        Ok(EstablishedClientConnection {
            input,
            conn: AbortableIo::new(&scope, conn),
        })
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;

    use rama_core::{
        ServiceInput,
        extensions::ExtensionsRef,
        graceful::{Cause, WeakScope, scope_context},
    };

    use tokio::io::AsyncWriteExt;

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
    async fn aborting_the_connection_scope_cuts_its_io() {
        let svc = AbortableConnectorService::new(EchoConnector);
        let EstablishedClientConnection { conn, .. } = svc.serve(()).await.unwrap();

        scope_context(conn.extensions())
            .and_then(WeakScope::into_scope)
            .unwrap()
            .abort(Cause::Owner);

        let mut conn = std::pin::pin!(conn);
        let err = conn.write_all(b"abc").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// Only the connection holds its scope: a retained weak context alone holds nothing.
    #[tokio::test]
    async fn the_returned_connection_holds_its_scope() {
        let svc = AbortableConnectorService::new(EchoConnector);
        let EstablishedClientConnection { conn, .. } = svc.serve(()).await.unwrap();
        let context = scope_context(conn.extensions()).unwrap();
        let mut drained = std::pin::pin!(context.drained());
        assert!(rama_core::futures::poll!(drained.as_mut()).is_pending());
        drop(conn);
        tokio::time::timeout(std::time::Duration::from_secs(1), drained)
            .await
            .expect("drained once the connection is gone");
    }
}
