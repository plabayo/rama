use crate::{
    Request, Response, StatusCode,
    layer::upgrade::{UpgradeOutput, UpgradeResponse, Upgraded},
    service::web::response::IntoResponse as _,
};
use rama_core::{
    Service,
    error::BoxError,
    extensions::ExtensionsRef as _,
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_net::{
    ConnectorTargetInputExt, Protocol,
    client::{
        ConnectRequest, ConnectionErrorKind, ConnectorService, ConnectorTarget,
        EstablishedClientConnection,
    },
};

/// HTTP proxy CONNECT service which establishes the egress connection before
/// acknowledging the CONNECT request.
///
/// Register it directly with an [`UpgradeLayer`](crate::layer::upgrade::UpgradeLayer):
///
/// ```ignore
/// let connect = EagerHttpProxyConnector::new(connector, relay_service);
/// let layer = UpgradeLayer::new(
///     executor,
///     MethodMatcher::CONNECT,
///     connect,
/// );
/// ```
///
/// A successful response is returned only after `connector` established the
/// requested egress connection. The established connection is carried across
/// the HTTP upgrade and passed to `relay_service` together with the upgraded
/// ingress connection as a [`BridgeIo`].
///
/// Use
/// [`LazyHttpProxyConnectReplyService`](super::LazyHttpProxyConnectReplyService)
/// together with a handler that establishes its own connection when the CONNECT
/// request must be acknowledged before an egress connection can be made.
///
/// Connection policy belongs in the connector stack. For example, wrap the
/// connector in a [`TimeoutLayer`](rama_core::layer::TimeoutLayer) to bound the
/// time spent establishing egress.
#[derive(Debug, Clone)]
pub struct EagerHttpProxyConnector<C, S> {
    connector: C,
    relay_service: S,
}

impl<C, S> EagerHttpProxyConnector<C, S> {
    /// Create an HTTP proxy CONNECT service that establishes egress before replying.
    #[must_use]
    pub fn new(connector: C, relay_service: S) -> Self {
        Self {
            connector,
            relay_service,
        }
    }
}

impl<C, S, Body> Service<Request<Body>> for EagerHttpProxyConnector<C, S>
where
    C: ConnectorService<ConnectRequest, Connection: Io + Unpin>,
    S: Service<BridgeIo<Upgraded, C::Connection>, Error: Into<BoxError>> + Clone,
    Body: Send + 'static,
{
    type Output = UpgradeOutput<Request<Body>, Response>;
    type Error = Response;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let Some(authority) = req.connector_target_with_default_port(Protocol::HTTP_DEFAULT_PORT)
        else {
            tracing::error!("http proxy, error extracting connector target");
            return Err(StatusCode::BAD_REQUEST.into_response());
        };

        tracing::info!(
            server.address = %authority.host,
            server.port = authority.port,
            "accept CONNECT: establish egress connection",
        );

        let EstablishedClientConnection {
            input: _,
            conn: egress,
        } = match self
            .connector
            .connect(ConnectRequest::new_with_extensions(
                authority.clone(),
                req.extensions().fork(),
            ))
            .await
        {
            Ok(established) => established,
            Err(err) => return Err(connect_error_response(&authority, &err)),
        };

        let relay_service = self.relay_service.clone();
        Ok(UpgradeResponse::new(req, StatusCode::OK.into_response())
            .with_extension(ConnectorTarget(authority))
            .with_handler(move |upgraded| async move {
                relay_service
                    .serve(BridgeIo(upgraded, egress))
                    .await
                    .map(drop)
                    .map_err(|err| -> BoxError { err.into() })
            }))
    }
}

fn connect_error_response(
    authority: &rama_net::address::HostWithPort,
    err: &rama_net::client::ConnectionError,
) -> Response {
    tracing::debug!(
        server.address = %authority.host,
        server.port = authority.port,
        error = ?err,
        "HTTP proxy CONNECT egress connection failed",
    );

    if err.kind() == ConnectionErrorKind::Timeout {
        StatusCode::GATEWAY_TIMEOUT.into_response()
    } else {
        StatusCode::BAD_GATEWAY.into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use rama_core::{
        Layer, ServiceInput,
        error::BoxErrorExt as _,
        extensions::{Extensions, ExtensionsRef},
        layer::TimeoutLayer,
        service::service_fn,
    };
    use rama_http_types::Body;
    use rama_net::client::{ConnectionError, EstablishedClientConnection};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    fn connect_request() -> Request<()> {
        Request::builder()
            .method("CONNECT")
            .uri(rama_net::uri::Uri::parse_authority_form("example.com:443").unwrap())
            .body(())
            .unwrap()
    }

    fn test_io() -> ServiceInput<tokio_test::io::Mock> {
        ServiceInput::new(tokio_test::io::Builder::new().build())
    }

    struct DropTrackedIo {
        inner: ServiceInput<tokio_test::io::Mock>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for DropTrackedIo {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl ExtensionsRef for DropTrackedIo {
        fn extensions(&self) -> &Extensions {
            self.inner.extensions()
        }
    }

    impl AsyncRead for DropTrackedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DropTrackedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn missing_connector_target_is_rejected_before_connecting() {
        let connected = Arc::new(AtomicBool::new(false));
        let connector = service_fn({
            let connected = connected.clone();
            move |_req: ConnectRequest| {
                connected.store(true, Ordering::SeqCst);
                std::future::ready(Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input: _req,
                    conn: test_io(),
                }))
            }
        });
        let service = EagerHttpProxyConnector::new(connector, ());
        let request = Request::builder()
            .method("CONNECT")
            .uri("/")
            .body(())
            .unwrap();

        let response = service.serve(request).await.unwrap_err();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!connected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn connection_failure_is_returned_instead_of_connect_success() {
        let connector = service_fn(|_req: ConnectRequest| async move {
            Err::<EstablishedClientConnection<ServiceInput<tokio_test::io::Mock>, ConnectRequest>, _>(
                ConnectionError::unknown(BoxError::from_static_str("egress unavailable")),
            )
        });
        let service = EagerHttpProxyConnector::new(connector, ());

        let response = Service::<Request<()>>::serve(&service, connect_request())
            .await
            .unwrap_err();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn connection_timeout_is_reported_as_gateway_timeout() {
        let connector = service_fn(|_req: ConnectRequest| async move {
            Err::<EstablishedClientConnection<ServiceInput<tokio_test::io::Mock>, ConnectRequest>, _>(
                ConnectionError::transport(
                    BoxError::from_static_str("egress timed out"),
                    ConnectionErrorKind::Timeout,
                ),
            )
        });
        let service = EagerHttpProxyConnector::new(connector, ());

        let response = Service::<Request<()>>::serve(&service, connect_request())
            .await
            .unwrap_err();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn connector_timeout_layer_is_reported_as_gateway_timeout() {
        let connector = service_fn(|_req: ConnectRequest| async move {
            std::future::pending::<
                Result<
                    EstablishedClientConnection<ServiceInput<tokio_test::io::Mock>, ConnectRequest>,
                    ConnectionError,
                >,
            >()
            .await
        });
        let connector = TimeoutLayer::new(Duration::ZERO).into_layer(connector);
        let service = EagerHttpProxyConnector::new(connector, ());

        let response = Service::<Request<()>>::serve(&service, connect_request())
            .await
            .unwrap_err();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn established_connection_is_reused_by_upgrade_handler() {
        let connected = Arc::new(AtomicBool::new(false));
        let relayed = Arc::new(AtomicBool::new(false));

        let connector = service_fn({
            let connected = connected.clone();
            move |input: ConnectRequest| {
                connected.store(true, Ordering::SeqCst);
                async move {
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: test_io(),
                    })
                }
            }
        });
        let relay = service_fn({
            let connected = connected.clone();
            let relayed = relayed.clone();
            move |bridge: BridgeIo<Upgraded, ServiceInput<tokio_test::io::Mock>>| {
                assert!(
                    connected.load(Ordering::SeqCst),
                    "egress must be connected before the relay starts"
                );
                assert_eq!(
                    bridge.0.extensions().get_ref::<ConnectorTarget>(),
                    Some(&ConnectorTarget("example.com:443".parse().unwrap())),
                );
                relayed.store(true, Ordering::SeqCst);
                std::future::ready(Ok::<_, BoxError>(()))
            }
        });
        let connect = EagerHttpProxyConnector::new(connector, relay);
        let inner = service_fn(|_req: Request| async move {
            Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
        });
        let service = crate::layer::upgrade::UpgradeLayer::new(
            rama_core::rt::Executor::default(),
            true,
            connect,
        )
        .into_layer(inner);
        let (pending_upgrade, on_upgrade) = crate::io::upgrade::pending();
        let request = connect_request().map(|()| Body::empty());
        request.extensions().insert(on_upgrade);

        let response = service.serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(connected.load(Ordering::SeqCst));
        assert!(!relayed.load(Ordering::SeqCst));

        pending_upgrade.fulfill(Upgraded::new(test_io(), Default::default()));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !relayed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("relay should receive the established egress connection");
    }

    #[tokio::test]
    async fn established_egress_is_dropped_when_upgrade_is_abandoned() {
        let dropped = Arc::new(AtomicBool::new(false));
        let connector = service_fn({
            let dropped = dropped.clone();
            move |input: ConnectRequest| {
                let dropped = dropped.clone();
                async move {
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: DropTrackedIo {
                            inner: test_io(),
                            dropped,
                        },
                    })
                }
            }
        });
        let connect = EagerHttpProxyConnector::new(connector, ());
        let inner = service_fn(|_req: Request| async move {
            Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
        });
        let service = crate::layer::upgrade::UpgradeLayer::new(
            rama_core::rt::Executor::default(),
            true,
            connect,
        )
        .into_layer(inner);
        let (pending_upgrade, on_upgrade) = crate::io::upgrade::pending();
        let request = connect_request().map(|()| Body::empty());
        request.extensions().insert(on_upgrade);

        let response = service.serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!dropped.load(Ordering::SeqCst));

        drop(pending_upgrade);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abandoned upgrade should release established egress");
    }
}
