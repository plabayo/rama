use rama_core::{Layer, Service, extensions::ExtensionsRef, futures::TryFutureExt as _};
use rama_utils::macros::define_inner_service_accessors;

use super::{ConnectionError, ConnectorService, EstablishedClientConnection};

/// Apply middleware to each connection returned by a connector.
///
/// The layer wraps the established connection, not the connector or its input.
/// The winning input and connection errors pass through unchanged. Place this
/// outside a pool to wrap each checkout, or inside it to wrap new connections.
#[derive(Debug, Clone)]
pub struct LayeredConnector<S, L> {
    inner: S,
    layer: L,
}

impl<S, L> LayeredConnector<S, L> {
    /// Compose a connector with middleware for its established connections.
    pub const fn new(inner: S, layer: L) -> Self {
        Self { inner, layer }
    }

    define_inner_service_accessors!();

    /// Configure the inner connector before sharing this service.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Borrow the middleware applied to established connections.
    pub const fn layer_ref(&self) -> &L {
        &self.layer
    }

    /// Configure the middleware applied to subsequent established connections.
    pub fn layer_mut(&mut self) -> &mut L {
        &mut self.layer
    }
}

impl<S, L, Input> Service<Input> for LayeredConnector<S, L>
where
    S: ConnectorService<Input>,
    L: Layer<S::Connection, Service: ExtensionsRef + Send + 'static> + Send + Sync + 'static,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<L::Service, Input>;
    type Error = ConnectionError;

    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.inner
            .connect(input)
            .map_ok(
                |EstablishedClientConnection { input, conn }| EstablishedClientConnection {
                    input,
                    conn: self.layer.layer(conn),
                },
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ConnectionErrorDomain, ConnectionErrorKind};
    use rama_core::{
        ServiceInput,
        error::{BoxError, BoxErrorExt as _},
        layer::layer_fn,
        service::service_fn,
    };
    use rama_utils::octets::kib;
    use std::{
        convert::Infallible,
        mem::size_of_val,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn layering_does_not_duplicate_the_connector_future() {
        let inner = service_fn(|input: [u8; kib(4)]| async move {
            std::future::ready(()).await;
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = LayeredConnector::new(inner, layer_fn(|conn| conn));
        let inner = connector.get_ref().connect([0; kib(4)]);
        let layered = connector.connect([0; kib(4)]);
        assert!(size_of_val(&layered) <= size_of_val(&inner) + 2 * size_of::<usize>());
    }

    #[tokio::test]
    async fn wraps_each_connection_and_preserves_the_winning_input() {
        let connector = service_fn(|input: usize| async move {
            Ok::<_, Infallible>(EstablishedClientConnection {
                input: input + 1,
                conn: ServiceInput::new(input),
            })
        });
        let count = AtomicUsize::new(0);
        let layer = layer_fn(move |conn: ServiceInput<usize>| {
            let checkout = count.fetch_add(1, Ordering::Relaxed);
            ServiceInput {
                input: (conn.input, checkout),
                extensions: conn.extensions,
            }
        });
        let connector = LayeredConnector::new(connector, layer);

        for checkout in 0..3 {
            let established = connector.connect(42).await.unwrap();
            assert_eq!(established.input, 43);
            assert_eq!(established.conn.input, (42, checkout));
        }
    }

    #[tokio::test]
    async fn preserves_failures_without_constructing_middleware() {
        let connector = service_fn(|()| async {
            Err::<EstablishedClientConnection<ServiceInput<()>, ()>, _>(ConnectionError::transport(
                BoxError::from_static_str("unavailable"),
                ConnectionErrorKind::Unavailable,
            ))
        });
        let layer = layer_fn(|_: ServiceInput<()>| -> ServiceInput<()> {
            panic!("failed connections must not construct middleware")
        });
        let error = LayeredConnector::new(connector, layer)
            .connect(())
            .await
            .unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(error.to_string(), "unavailable");
    }
}
