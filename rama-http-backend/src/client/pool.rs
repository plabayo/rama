//! HTTP connection pool: connection identity and connector assembly.

use std::time::Duration;

use rama_core::Layer;
use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_core::extensions::ExtensionsRef;
use rama_http_types::Request;
use rama_net::address::{HostWithOptPort, ProxyAddress};
use rama_net::client::pool::{ConnID, MultiplexPool, MuxSelection, PooledConnector, ReqToConnID};
use rama_net::client::{ConnectorService, ConnectorTarget};
use rama_net::{AuthorityInputExt, Protocol, ProtocolInputExt};

use super::{BindBodyToConnLayer, BindBodyToConnector};

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
/// [`BasicHttpConnIdentifier`] can be used together with a [`Pool`](rama_net::client::pool::Pool)
/// to create a basic http connection pool.
pub struct BasicHttpConnIdentifier;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Connection Identifier which will match inputs that have the exact same
/// protocol, authority, proxy address and connector target
pub struct BasicHttpConId {
    pub protocol: Option<Protocol>,
    pub authority: HostWithOptPort,
    pub proxy_address: Option<ProxyAddress>,
    pub connector_target: Option<ConnectorTarget>,
}

impl ConnID for BasicHttpConId {
    #[cfg(feature = "opentelemetry")]
    fn attributes(&self) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> {
        self.protocol
            .as_ref()
            .map(|protocol| {
                rama_core::telemetry::opentelemetry::KeyValue::new("protocol", protocol.to_string())
            })
            .into_iter()
            .chain([rama_core::telemetry::opentelemetry::KeyValue::new(
                "authority",
                self.authority.to_string(),
            )])
    }
}

impl<Body> ReqToConnID<Request<Body>> for BasicHttpConnIdentifier {
    type ID = BasicHttpConId;

    fn id(&self, req: &Request<Body>) -> Result<Self::ID, BoxError> {
        let authority = req
            .authority()
            .ok_or_else(|| BoxError::from_static_str("no authority found in http request"))?;
        let protocol = req.protocol().cloned();

        Ok(BasicHttpConId {
            protocol,
            authority,
            proxy_address: req.extensions().get_ref().cloned(),
            connector_target: req.extensions().get_ref().cloned(),
        })
    }
}

#[derive(Debug, Clone)]
/// Config used to create a multiplexing http connection pool ([`MultiplexPool`]).
///
/// The per-connection concurrency comes from the connection's
/// [`MaxConcurrency`](rama_net::conn::MaxConcurrency) extension (set by the http
/// connectors: 1 for http/1, the stream capacity for http/2), clamped to
/// `max_concurrent_streams` as an upper bound.
pub struct HttpPooledConnectorConfig {
    /// Set the max amount of connections that this connection pool will contain
    ///
    /// This is the sum of active connections and idle connections. When this limit
    /// is hit idle connections will be replaced with new ones.
    pub max_total: usize,
    /// Upper bound on the concurrent requests a single connection may serve.
    ///
    /// Acts as a ceiling for each connection, each connection also figures
    /// it's own max concurrency out by itself
    pub max_concurrent_streams: usize,
    /// How a connection is chosen among several that can serve a request.
    pub selection: MuxSelection,
    /// If connections have been idle (no active streams) for longer than this
    /// timeout they are dropped. Only checked when a connection is requested.
    pub idle_timeout: Option<Duration>,
    /// How long to wait for the pool to hand out a connection before timing out.
    pub wait_for_pool_timeout: Option<Duration>,
}

impl Default for HttpPooledConnectorConfig {
    fn default() -> Self {
        Self {
            max_total: 50,
            max_concurrent_streams: 100,
            selection: MuxSelection::default(),
            idle_timeout: Some(Duration::from_secs(300)),
            wait_for_pool_timeout: Some(Duration::from_secs(120)),
        }
    }
}

impl HttpPooledConnectorConfig {
    /// Build a pooled http connector around `inner`.
    ///
    /// The returned connector wraps each pooled connection in
    /// [`BindBodyToConn`](super::BindBodyToConn), so the pool only frees/reuses a
    /// connection once its response body has been consumed, not at response
    /// headers.
    ///
    /// Warning: the connection returned by this pool should only be used for a single
    /// request. Every request should go through the connector stack again, and will
    /// receive a new or resused connection (maybe multiplexed) of its own from.
    pub fn build_connector<S>(
        self,
        inner: S,
    ) -> Result<
        BindBodyToConnector<
            PooledConnector<
                S,
                MultiplexPool<S::Connection, BasicHttpConId>,
                BasicHttpConnIdentifier,
            >,
        >,
        BoxError,
    >
    where
        S: ConnectorService<Request>,
    {
        let pool = MultiplexPool::try_new(self.max_concurrent_streams, self.max_total)?
            .with_selection(self.selection)
            .maybe_with_idle_timeout(self.idle_timeout);

        let connector = PooledConnector::new(inner, pool, BasicHttpConnIdentifier)
            .maybe_with_wait_for_pool_timeout(self.wait_for_pool_timeout);

        Ok(BindBodyToConnLayer::new().into_layer(connector))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rama_core::error::BoxError;
    use rama_core::extensions::ExtensionsRef;
    use rama_core::rt::Executor;
    use rama_core::service::service_fn;
    use rama_core::{Layer, Service};
    use rama_http_types::body::util::BodyExt as _;
    use rama_http_types::{Body, HeaderValue, Request, Response, Version};
    use rama_net::client::ConnectorService;
    use rama_net::test_utils::client::MockConnectorService;
    use rama_utils::octets::kib;
    use tokio::time::sleep;

    use super::HttpPooledConnectorConfig;
    use crate::client::HttpConnectorLayer;
    use crate::server::HttpServer;

    fn create_test_request(version: Version) -> Request {
        Request::builder()
            .uri("https://www.example.com")
            .version(version)
            .body(Body::from("a random request body"))
            .unwrap()
    }

    /// A mock connector whose every backend connection runs an `HttpServer` that
    /// tags each response with `x-conn-id` (which backend connection served it) and
    /// `x-resp-id` (how many requests that connection has served so far). The
    /// per-connection id is read from a header, so it can be asserted without
    /// draining the (possibly still in-flight) response body.
    fn tagging_mock_connector() -> impl ConnectorService<
        Request,
        Connection: Service<Request, Output = Response, Error = BoxError> + ExtensionsRef,
    > {
        let conns = Arc::new(AtomicUsize::new(0));
        HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
            let conn_id = conns.fetch_add(1, Ordering::Relaxed);
            let resps = Arc::new(AtomicUsize::new(0));
            HttpServer::auto(Executor::default()).service(service_fn(move |_req: Request| {
                let resps = resps.clone();
                async move {
                    let resp_id = resps.fetch_add(1, Ordering::Relaxed);
                    let mut resp = Response::new(Body::from("ok"));
                    let headers = resp.headers_mut();
                    headers.insert("x-conn-id", HeaderValue::from(conn_id as u64));
                    headers.insert("x-resp-id", HeaderValue::from(resp_id as u64));
                    Ok::<_, Infallible>(resp)
                }
            }))
        }))
    }

    fn conn_id(resp: &Response) -> u64 {
        resp.headers()
            .get("x-conn-id")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn pool_keeps_h2_connection_in_use_until_response_body_consumed() {
        let connector = HttpPooledConnectorConfig {
            max_concurrent_streams: 1,
            max_total: 4,
            ..Default::default()
        }
        .build_connector(tagging_mock_connector())
        .unwrap();

        let req = || create_test_request(Version::HTTP_2);

        // Serve req1 but hold its (still-streaming) response body: the connection is
        // moved into that body, so it is logically still in use.
        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);

        // req2 must therefore land on a NEW connection (cap = 1, conn 0 busy).
        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(
            conn_id(&resp2),
            1,
            "second request must not reuse a connection whose response body is still in flight"
        );
    }

    #[tokio::test]
    async fn pool_keeps_h1_connection_in_use_until_response_body_consumed() {
        let connector = HttpPooledConnectorConfig {
            max_concurrent_streams: 1,
            max_total: 4,
            ..Default::default()
        }
        .build_connector(tagging_mock_connector())
        .unwrap();

        let req = || create_test_request(Version::HTTP_11);

        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(
            conn_id(&resp2),
            1,
            "h1: second request must not reuse a connection whose response body is still in flight"
        );
    }

    /// An h1 connection the server closed (`Connection: close`) must not be handed
    /// back out by the pool. Multiplex storage keeps the connection after a handout
    /// drops, so this relies on `ConnectionHealthWatcher` being marked broken and
    /// swept, the multiplex equivalent of the exclusive pool's `drop_connection_if_no_response`.
    #[tokio::test(start_paused = true)]
    async fn pool_does_not_reuse_h1_connection_after_server_close() {
        let conns = Arc::new(AtomicUsize::new(0));
        let inner =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                let conn_id = conns.fetch_add(1, Ordering::Relaxed);
                HttpServer::auto(Executor::default()).service(service_fn(
                    move |_req: Request| async move {
                        let mut resp = Response::new(Body::from("ok"));
                        let headers = resp.headers_mut();
                        headers.insert("x-conn-id", HeaderValue::from(conn_id as u64));
                        headers.insert("connection", HeaderValue::from_static("close"));
                        Ok::<_, Infallible>(resp)
                    },
                ))
            }));
        let connector = HttpPooledConnectorConfig {
            max_total: 4,
            ..Default::default()
        }
        .build_connector(inner)
        .unwrap();

        let req = || create_test_request(Version::HTTP_11);

        // Serve and fully drain req1 so the h1 connection processes the close and
        // (should) get marked broken before it could be reused.
        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);
        let id1 = conn_id(&resp1);
        resp1.into_body().collect().await.unwrap();

        // Let the connection task observe the close and update health.
        sleep(Duration::from_millis(50)).await;

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(id1, 0);
        assert_ne!(
            conn_id(&resp2),
            id1,
            "must not reuse an h1 connection the server closed"
        );
    }

    /// An h1 response body abandoned before end-of-stream leaves the connection
    /// mid-message, the pool must not reuse it. Uses a large body so the response is
    /// genuinely still on the wire when dropped (a tiny fully-buffered body could be
    /// drained and legitimately reused).
    #[tokio::test(start_paused = true)]
    async fn pool_does_not_reuse_h1_connection_after_body_dropped_early() {
        let conns = Arc::new(AtomicUsize::new(0));
        let inner =
            HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
                let conn_id = conns.fetch_add(1, Ordering::Relaxed);
                HttpServer::auto(Executor::default()).service(service_fn(
                    move |_req: Request| async move {
                        let mut resp = Response::new(Body::from(vec![0u8; kib(1024)]));
                        resp.headers_mut()
                            .insert("x-conn-id", HeaderValue::from(conn_id as u64));
                        Ok::<_, Infallible>(resp)
                    },
                ))
            }));
        let connector = HttpPooledConnectorConfig {
            max_total: 4,
            ..Default::default()
        }
        .build_connector(inner)
        .unwrap();

        let req = || create_test_request(Version::HTTP_11);

        // Take the response (headers) but drop it without reading the body.
        let est1 = connector.serve(req()).await.unwrap();
        let resp1 = est1.conn.serve(req()).await.unwrap();
        drop(est1);
        let id1 = conn_id(&resp1);
        drop(resp1);

        // Let the connection task observe the abandoned read and update health.
        sleep(Duration::from_millis(50)).await;

        let est2 = connector.serve(req()).await.unwrap();
        let resp2 = est2.conn.serve(req()).await.unwrap();

        assert_eq!(id1, 0);
        assert_ne!(
            conn_id(&resp2),
            id1,
            "must not reuse an h1 connection whose response body was abandoned mid-stream"
        );
    }

    #[tokio::test]
    async fn pool_reuses_connection_after_body_consumed() {
        let connector = HttpPooledConnectorConfig {
            max_concurrent_streams: 1,
            max_total: 4,
            ..Default::default()
        }
        .build_connector(tagging_mock_connector())
        .unwrap();

        let req = || create_test_request(Version::HTTP_2);

        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        assert_eq!(conn_id(&resp1), 0);
        // Drain to end-of-stream: releases connection 0 back to the pool.
        resp1.into_body().collect().await.unwrap();

        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        assert_eq!(
            conn_id(&resp2),
            0,
            "connection must be reused once its response body is consumed"
        );
    }

    #[tokio::test]
    async fn pool_multiplexes_on_h2() {
        let connector = HttpPooledConnectorConfig::default()
            .build_connector(tagging_mock_connector())
            .unwrap();

        let req = || create_test_request(Version::HTTP_2);

        // Hold resp1 (body unconsumed) so connection 0 stays in use.
        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(
            conn_id(&resp2),
            0,
            "h2: a second in-flight request multiplexes onto the same connection"
        );
    }

    #[tokio::test]
    async fn pool_does_not_multiplex_on_h1() {
        let connector = HttpPooledConnectorConfig::default()
            .build_connector(tagging_mock_connector())
            .unwrap();

        let req = || create_test_request(Version::HTTP_11);

        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(
            conn_id(&resp2),
            1,
            "h1 does not multiplex: a second in-flight request needs a new connection"
        );
    }

    #[tokio::test]
    async fn pool_respects_max_concurrent_streams() {
        let connector = HttpPooledConnectorConfig {
            max_concurrent_streams: 2,
            max_total: 4,
            ..Default::default()
        }
        .build_connector(tagging_mock_connector())
        .unwrap();

        let req = || create_test_request(Version::HTTP_2);

        // Three in-flight (bodies unconsumed) requests: two fit on connection 0.
        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let resp3 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();

        assert_eq!(conn_id(&resp1), 0);
        assert_eq!(conn_id(&resp2), 0, "second request fits on connection 0");
        assert_eq!(
            conn_id(&resp3),
            1,
            "third request exceeds the per-connection limit, needs a new connection"
        );
    }

    /// Like [`tagging_mock_connector`] but each response carries a large body, so
    /// it genuinely streams over multiple frames rather than a single buffered one.
    fn large_body_mock_connector() -> impl ConnectorService<
        Request,
        Connection: Service<Request, Output = Response, Error = BoxError> + ExtensionsRef,
    > {
        let conns = Arc::new(AtomicUsize::new(0));
        HttpConnectorLayer::default().into_layer(MockConnectorService::new(move || {
            let conn_id = conns.fetch_add(1, Ordering::Relaxed);
            HttpServer::auto(Executor::default()).service(service_fn(
                move |_req: Request| async move {
                    let mut resp = Response::new(Body::from(vec![0u8; kib(1024)]));
                    resp.headers_mut()
                        .insert("x-conn-id", HeaderValue::from(conn_id as u64));
                    Ok::<_, Infallible>(resp)
                },
            ))
        }))
    }

    /// A connection stays bound for the whole of a *streaming* response body: it
    /// is not reusable while frames are still arriving, and is released precisely
    /// at end-of-stream (exercising `GuardedBody`'s `poll_frame -> Ready(None)`
    /// over real multi-frame h2 streaming).
    #[tokio::test]
    async fn pool_binds_connection_across_streaming_body() {
        let connector = HttpPooledConnectorConfig {
            max_concurrent_streams: 1,
            max_total: 4,
            ..Default::default()
        }
        .build_connector(large_body_mock_connector())
        .unwrap();

        let req = || create_test_request(Version::HTTP_2);

        // Read the headers and a single body frame: the stream is not yet at
        // end-of-stream, so connection 0 is still in use.
        let resp1 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        let id1 = conn_id(&resp1);
        let mut body1 = resp1.into_body();
        assert!(
            body1.frame().await.is_some(),
            "streaming body should yield at least one frame"
        );

        // Mid-stream: connection 0 must not be reused.
        let resp2 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        assert_eq!(id1, 0);
        assert_ne!(
            conn_id(&resp2),
            id1,
            "a connection still streaming its response body must not be reused"
        );

        // Drain body 1 to end-of-stream. `GuardedBody` releases the connection
        // right here (at `poll_frame -> Ready(None)`), not on drop.
        while let Some(frame) = body1.frame().await {
            frame.unwrap();
        }

        // `body1` is still in scope (not dropped), yet connection 0 is reused.
        // Proving the release happens at end-of-stream, not when the body drops.
        let resp3 = connector
            .serve(req())
            .await
            .unwrap()
            .conn
            .serve(req())
            .await
            .unwrap();
        assert_eq!(
            conn_id(&resp3),
            id1,
            "a connection is reused once its streaming body reaches end-of-stream"
        );
    }
}
