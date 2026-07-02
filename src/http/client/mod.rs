//! rama http client support
//!
//! Contains re-exports from `rama-http-backend::client`
//! and adds `EasyHttpWebClient`, an opiniated http web client which
//! supports most common use cases and provides sensible defaults.
use std::fmt;

use crate::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsRef,
    http::{Request, Response, StreamingBody},
    net::client::EstablishedClientConnection,
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
};

#[doc(inline)]
pub use ::rama_http_backend::client::*;
use rama_core::{
    error::{ErrorContext, ErrorExt as _, extra::OpaqueError},
    extensions::Egress,
    layer::MapErr,
};

pub mod builder;
#[doc(inline)]
pub use builder::EasyHttpConnectorBuilder;

#[cfg(feature = "socks5")]
mod proxy_connector;
#[cfg(feature = "socks5")]
#[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
#[doc(inline)]
pub use proxy_connector::{MaybeProxiedConnection, ProxyConnector, ProxyConnectorLayer};

/// An opiniated http client that can be used to serve HTTP requests.
///
/// Use [`EasyHttpWebClient::connector_builder()`] to easily create a client with
/// a common Http connector setup (tcp + proxy + tls + http) or bring your
/// own http connector.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct EasyHttpWebClient<BodyIn, ConnResponse, L> {
    connector: BoxService<Request<BodyIn>, ConnResponse, OpaqueError>,
    jit_layers: L,
}

impl<BodyIn, ConnResponse, L> fmt::Debug for EasyHttpWebClient<BodyIn, ConnResponse, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient").finish()
    }
}

impl<BodyIn, ConnResponse, L: Clone> Clone for EasyHttpWebClient<BodyIn, ConnResponse, L> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            jit_layers: self.jit_layers.clone(),
        }
    }
}

impl EasyHttpWebClient<(), (), ()> {
    /// Create a [`EasyHttpConnectorBuilder`] to easily create a [`EasyHttpWebClient`] with a custom connector
    #[must_use]
    pub fn connector_builder() -> EasyHttpConnectorBuilder {
        EasyHttpConnectorBuilder::new()
    }
}

impl<Body> Default
    for EasyHttpWebClient<
        Body,
        EstablishedClientConnection<HttpClientService<Body>, Request<Body>>,
        (),
    >
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    #[inline(always)]
    fn default() -> Self {
        Self::default_with_executor(Executor::default())
    }
}

impl<Body>
    EasyHttpWebClient<Body, EstablishedClientConnection<HttpClientService<Body>, Request<Body>>, ()>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    core::cfg_select! {
        feature = "boring" => {
            pub fn default_with_executor(exec: Executor) -> Self {
                let tls_config = crate::tls::client::TlsClientConfig::default_http();

                EasyHttpConnectorBuilder::new()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_tls_proxy_support_using_boringssl()
                    .with_proxy_support()
                    .with_tls_support_using_boringssl(tls_config)
                    .with_default_http_connector(exec)
                    .build_client()
            }
        }
        feature = "rustls" => {
            pub fn default_with_executor(exec: Executor) -> Self {
                let tls_config = crate::tls::client::TlsClientConfig::default_http();

                EasyHttpConnectorBuilder::new()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_tls_proxy_support_using_rustls()
                    .with_proxy_support()
                    .with_tls_support_using_rustls(tls_config)
                    .with_default_http_connector(exec)
                    .build_client()
            }
        }
        _ => {
            pub fn default_with_executor(exec: Executor) -> Self {
                EasyHttpConnectorBuilder::new()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .without_tls_proxy_support()
                    .with_proxy_support()
                    .without_tls_support()
                    .with_default_http_connector(exec)
                    .build_client()
            }
        }
    }
}

impl<BodyIn, ConnResponse> EasyHttpWebClient<BodyIn, ConnResponse, ()>
where
    BodyIn: Send + 'static,
{
    /// Create a new [`EasyHttpWebClient`] using the provided connector
    #[must_use]
    pub fn new<S>(connector: S) -> Self
    where
        S: Service<Request<BodyIn>, Output = ConnResponse, Error: Into<BoxError>>,
    {
        Self {
            connector: MapErr::into_opaque_error(connector).boxed(),
            jit_layers: (),
        }
    }
}

impl<BodyIn, ConnResponse, L> EasyHttpWebClient<BodyIn, ConnResponse, L> {
    /// Set the connector that this [`EasyHttpWebClient`] will use
    #[must_use]
    pub fn with_connector<S, BodyInNew, ConnResponseNew>(
        self,
        connector: S,
    ) -> EasyHttpWebClient<BodyInNew, ConnResponseNew, L>
    where
        S: Service<Request<BodyInNew>, Output = ConnResponseNew, Error: Into<BoxError>>,
        BodyInNew: Send + 'static,
    {
        EasyHttpWebClient {
            connector: MapErr::into_opaque_error(connector).boxed(),
            jit_layers: self.jit_layers,
        }
    }

    /// [`Layer`] which will be applied just in time (JIT) before the request is send, but after
    /// the connection has been established.
    ///
    /// Simplified flow of how the [`EasyHttpWebClient`] works:
    /// 1. External: let response = client.serve(request)
    /// 2. Internal: let http_connection = self.connector.serve(request)
    /// 3. Internal: let response = jit_layers.layer(http_connection).serve(request)
    pub fn with_jit_layer<T>(self, jit_layers: T) -> EasyHttpWebClient<BodyIn, ConnResponse, T> {
        EasyHttpWebClient {
            connector: self.connector,
            jit_layers,
        }
    }
}

impl<Body, ConnectionBody, Connection, L> Service<Request<Body>>
    for EasyHttpWebClient<Body, EstablishedClientConnection<Connection, Request<ConnectionBody>>, L>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    Connection:
        Service<Request<ConnectionBody>, Output = Response, Error = BoxError> + ExtensionsRef,
    // Body type this connection will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    ConnectionBody:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    L: Layer<
            Connection,
            Service: Service<Request<ConnectionBody>, Output = Response, Error = BoxError>,
        > + Send
        + Sync
        + 'static,
{
    type Output = Response;
    type Error = OpaqueError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let uri = req.uri().clone();

        let EstablishedClientConnection {
            input: req,
            conn: http_connection,
        } = self.connector.serve(req).await.into_opaque_error()?;

        req.extensions()
            .insert(Egress(http_connection.extensions().clone()));

        let http_connection = self.jit_layers.layer(http_connection);

        // NOTE: stack might change request version based on connector data,
        tracing::trace!(url.full = %uri, "send http req to connector stack");

        let result = http_connection.serve(req).await;

        match result {
            Ok(resp) => {
                tracing::trace!(url.full = %uri, "response received from connector stack");
                Ok(resp)
            }
            Err(err) => Err(err
                .context("http request failure")
                .context_field("uri", uri)
                .into_opaque_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use rama_core::service::service_fn;
    use rama_http::{Body, BodyExtractExt, Version};
    use rama_http_backend::server::HttpServer;
    use rama_net::test_utils::client::{MockConnectorService, MockSocket};
    use serde::{Deserialize, Serialize};
    use tokio::time::sleep;

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Output {
        conn: usize,
        resp: usize,
    }

    fn dummy_server<Input: Send + 'static>()
    -> impl Service<Input, Output = EstablishedClientConnection<MockSocket, Input>, Error = Infallible>
    {
        let created_connections = Arc::new(AtomicUsize::new(0));
        MockConnectorService::new(move || {
            let created_connections = created_connections.clone();
            let conn = created_connections.fetch_add(1, Ordering::Relaxed);

            // count responses created on this specific connection
            let created_response = Arc::new(AtomicUsize::new(0));

            HttpServer::auto(Executor::default()).service(service_fn(move |_req: Request| {
                let created_response = created_response.clone();
                let resp = created_response.fetch_add(1, Ordering::Relaxed);
                async move {
                    sleep(Duration::from_millis(5)).await;
                    let out = Output { conn, resp };
                    let resp = Response::new(Body::from(serde_json::to_vec(&out).unwrap()));
                    Ok::<_, Infallible>(resp)
                }
            }))
        })
    }

    #[tokio::test]
    async fn connection_is_in_use_until_response_body_is_consumed() {
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .try_with_connection_pool(HttpPooledConnectorConfig {
                max_concurrent_streams: 1,
                max_total: 4,
                ..Default::default()
            })
            .unwrap()
            .build_client();

        let req = || {
            Request::builder()
                .uri("http://example.com")
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap()
        };

        // Get the first response but DO NOT consume its body yet: the connection
        // is logically still in use until the body is drained. Then issue a second
        // request before draining the first.
        let res1 = client.serve(req()).await.unwrap();
        let res2 = client.serve(req()).await.unwrap();

        // Drain in reverse so `res1`'s body is still outstanding when `req2` runs.
        let out2 = res2.try_into_json::<Output>().await.unwrap();
        let out1 = res1.try_into_json::<Output>().await.unwrap();

        assert_eq!(out1.conn, 0, "first request uses the first connection");
        // With `max_concurrent_streams = 1`, connection 0's response body is still
        // in flight, so the second request must NOT reuse it.
        assert_eq!(
            out2.conn, 1,
            "second request must not reuse a connection whose response body is still in flight"
        );
    }

    // These things are already tested inside the pool itself, but here we add some high level tests
    // in case we ever swap the underlying pool implementation.

    #[tokio::test]
    async fn default_pool_multiplexes_on_h2() {
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .try_with_default_connection_pool()
            .unwrap()
            .build_client();

        let req = || {
            Request::builder()
                .uri("http://example.com")
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap()
        };
        let (res1, res2, res3) = tokio::join!(
            client.serve(req()),
            client.serve(req()),
            client.serve(req()),
        );

        // Should only create single connection and send all requests over the same one
        for (i, res) in [res1, res2, res3].into_iter().enumerate() {
            let out = res.unwrap().try_into_json::<Output>().await.unwrap();
            assert_eq!(out.conn, 0);
            assert_eq!(out.resp, i);
        }
    }

    #[tokio::test]
    async fn default_pool_does_not_multiplexes_on_h1() {
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .try_with_default_connection_pool()
            .unwrap()
            .build_client();

        let req = || {
            Request::builder()
                .uri("http://example.com")
                .version(Version::HTTP_11)
                .body(Body::empty())
                .unwrap()
        };
        let (res1, res2, res3) = tokio::join!(
            client.serve(req()),
            client.serve(req()),
            client.serve(req()),
        );

        // Should create a new connection for each request since they are all inprogress at the same
        // time and h1 does not support multiplexing
        for (i, res) in [res1, res2, res3].into_iter().enumerate() {
            let out = res.unwrap().try_into_json::<Output>().await.unwrap();
            assert_eq!(out.conn, i);
            assert_eq!(out.resp, 0);
        }
    }

    #[tokio::test]
    async fn multiplex_on_h2_respects_limits() {
        let client = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(dummy_server())
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .try_with_connection_pool(HttpPooledConnectorConfig {
                max_concurrent_streams: 2,
                ..Default::default()
            })
            .unwrap()
            .build_client();

        let req = || {
            Request::builder()
                .uri("http://example.com")
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap()
        };
        let (res1, res2, res3, res4) = tokio::join!(
            client.serve(req()),
            client.serve(req()),
            client.serve(req()),
            client.serve(req()),
        );

        // Should create a connection for every two request
        for (i, res) in [res1, res2, res3, res4].into_iter().enumerate() {
            let out = res.unwrap().try_into_json::<Output>().await.unwrap();
            assert_eq!(out.conn, i / 2);
            assert_eq!(out.resp, i % 2);
        }
    }
}
