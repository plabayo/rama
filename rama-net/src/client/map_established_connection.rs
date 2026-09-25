use rama_core::{Layer, Service, extensions::ExtensionsRef, futures::TryFutureExt as _};
use rama_utils::macros::define_inner_service_accessors;

use super::{ConnectionError, ConnectorService, EstablishedClientConnection};

/// Apply middleware to each connection returned by a connector.
///
/// The layer wraps the established connection, not the connector or its input.
/// The winning input and connection errors pass through unchanged. Place this
/// outside a pool to wrap each checkout, or inside it to wrap new connections.
#[derive(Debug, Clone)]
pub struct MapEstablishedConnection<S, L> {
    inner: S,
    layer: L,
}

/// A [`Layer`] that produces a [`MapEstablishedConnection`] service.
///
/// The supplied layer applies to successful connections, preserving the
/// connector's winning input. Use [`rama_core::layer::layer_fn`] to map a
/// connection with a closure.
#[derive(Debug, Clone)]
pub struct MapEstablishedConnectionLayer<L> {
    layer: L,
}

impl<L> MapEstablishedConnectionLayer<L> {
    /// Wrap connectors with middleware for their established connections.
    pub const fn new(layer: L) -> Self {
        Self { layer }
    }
}

impl<S, L> Layer<S> for MapEstablishedConnectionLayer<L>
where
    L: Clone,
{
    type Service = MapEstablishedConnection<S, L>;

    fn layer(&self, inner: S) -> Self::Service {
        MapEstablishedConnection::new(inner, self.layer.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        MapEstablishedConnection::new(inner, self.layer)
    }
}

impl<S, L> MapEstablishedConnection<S, L> {
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

impl<S, L, Input> Service<Input> for MapEstablishedConnection<S, L>
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
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
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
        let connector = MapEstablishedConnection::new(inner, layer_fn(|conn| conn));
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
        let connector = MapEstablishedConnection::new(connector, layer);

        for checkout in 0..3 {
            let established = connector.connect(42).await.unwrap();
            assert_eq!(established.input, 43);
            assert_eq!(established.conn.input, (42, checkout));
        }
    }

    #[tokio::test]
    async fn reusable_layer_maps_connections_from_each_connector() {
        let count = Arc::new(AtomicUsize::new(0));
        let layer = MapEstablishedConnectionLayer::new(layer_fn({
            let count = count.clone();
            move |conn: ServiceInput<usize>| {
                let checkout = count.fetch_add(1, Ordering::Relaxed);
                ServiceInput {
                    input: (conn.input, checkout),
                    extensions: conn.extensions,
                }
            }
        }));
        let first = layer.layer(service_fn(|input: usize| async move {
            Ok::<_, Infallible>(EstablishedClientConnection {
                input: input + 1,
                conn: ServiceInput::new(input),
            })
        }));
        let second = layer.into_layer(service_fn(|input: usize| async move {
            Ok::<_, Infallible>(EstablishedClientConnection {
                input: input + 2,
                conn: ServiceInput::new(input * 2),
            })
        }));

        // Constructing connector stacks must not construct their connections.
        assert_eq!(count.load(Ordering::Relaxed), 0);

        let established = first.connect(10).await.unwrap();
        assert_eq!(established.input, 11);
        assert_eq!(established.conn.input, (10, 0));

        let established = second.connect(10).await.unwrap();
        assert_eq!(established.input, 12);
        assert_eq!(established.conn.input, (20, 1));
        assert_eq!(count.load(Ordering::Relaxed), 2);
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
        let error = MapEstablishedConnection::new(connector, layer)
            .connect(())
            .await
            .unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(error.to_string(), "unavailable");
    }
}
