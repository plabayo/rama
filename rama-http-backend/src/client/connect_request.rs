use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
};
use rama_http_types::Request;
use rama_net::{
    AuthorityInputExt, ProtocolInputExt, TransportProtocolInputExt,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
        EstablishedClientConnection,
    },
    http::HttpRequestVersion,
};
use rama_utils::macros::define_inner_service_accessors;

fn try_from_http_request<Body>(request: &Request<Body>) -> Result<ConnectRequest, ConnectionError> {
    let application_protocol = request.protocol().cloned();
    let authority = request
        .authority()
        .and_then(|authority| {
            authority.into_host_with_port(
                application_protocol
                    .as_ref()
                    .and_then(|protocol| protocol.default_port()),
            )
        })
        .ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("HTTP request authority is missing a host or port"),
                ConnectionErrorKind::InvalidInput,
            )
            .context("HTTP connect request adapter: derive authority")
        })?;

    // The adapter and the original request are different logical inputs. Keep
    // connector mutations isolated until an attempt succeeds, then install the
    // successful extension chain back on the original request.
    let extensions = request.extensions().fork();
    // This is only a plain-connection fallback for HttpConnector. It must not
    // be a TargetHttpVersion: that would pin TLS ALPN merely because an HTTP
    // request has an initial version.
    extensions.insert(HttpRequestVersion(request.version()));

    Ok(ConnectRequest::new_with_extensions(authority, extensions)
        .maybe_with_application_protocol(application_protocol)
        .maybe_with_transport_protocol(request.transport_protocol()))
}

/// Adapt an HTTP [`Request`] to a protocol-independent [`ConnectRequest`].
///
/// The original request, including its body, remains owned by this adapter
/// while the inner connector establishes a connection. The successful
/// connector input's extension chain is then installed on the original request
/// so selected routes and other connection metadata remain observable without
/// requiring the body to be cloned.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpConnectRequestAdapter<S> {
    inner: S,
}

impl<S> HttpConnectRequestAdapter<S> {
    /// Create a new [`HttpConnectRequestAdapter`].
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, Body> Service<Request<Body>> for HttpConnectRequestAdapter<S>
where
    S: ConnectorService<ConnectRequest>,
    Body: Send + 'static,
{
    type Output = EstablishedClientConnection<S::Connection, Request<Body>>;
    type Error = ConnectionError;

    async fn serve(&self, request: Request<Body>) -> Result<Self::Output, Self::Error> {
        let connect_request = try_from_http_request(&request)?;
        let EstablishedClientConnection {
            conn,
            input: connect_request,
        } = self.inner.connect(connect_request).await?;

        let (mut parts, body) = request.into_parts();
        parts.extensions = connect_request.extensions;

        Ok(EstablishedClientConnection {
            conn,
            input: Request::from_parts(parts, body),
        })
    }
}

/// Layer that adapts HTTP requests to protocol-independent connection inputs.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct HttpConnectRequestAdapterLayer;

impl HttpConnectRequestAdapterLayer {
    /// Create a new [`HttpConnectRequestAdapterLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for HttpConnectRequestAdapterLayer {
    type Service = HttpConnectRequestAdapter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpConnectRequestAdapter::new(inner)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rama_core::{
        ServiceInput,
        extensions::{Extension, ExtensionsRef},
        service::service_fn,
    };
    use rama_http_types::{Method, Request, Version};
    use rama_net::{
        Protocol, ProtocolInputExt, TransportProtocolInputExt,
        client::{ConnectRequest, EstablishedClientConnection},
        transport::TransportProtocol,
    };

    use super::*;

    #[derive(Debug)]
    struct NonCloneBody;

    #[derive(Debug, Extension)]
    struct RequestMarker;

    #[derive(Debug, Extension)]
    struct SelectedAttemptMarker;

    #[tokio::test]
    async fn adapts_without_cloning_body_and_restores_selected_extensions() {
        let inner = service_fn(async |input: ConnectRequest| {
            assert_eq!(input.authority.to_string(), "example.com:443");
            assert_eq!(input.protocol(), Some(&Protocol::HTTPS));
            assert_eq!(input.transport_protocol(), Some(TransportProtocol::Tcp));
            assert_eq!(
                input
                    .extensions
                    .get_ref::<HttpRequestVersion>()
                    .map(|v| v.0),
                Some(Version::HTTP_2)
            );
            assert!(input.extensions.contains::<RequestMarker>());
            assert!(!input.extensions.self_contains::<RequestMarker>());

            input.extensions.insert(SelectedAttemptMarker);
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let adapter = HttpConnectRequestAdapter::new(inner);

        let request = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload")
            .version(Version::HTTP_2)
            .body(NonCloneBody)
            .unwrap();
        request.extensions().insert(RequestMarker);

        let established = adapter.serve(request).await.unwrap();
        assert_eq!(established.input.method(), Method::POST);
        assert_eq!(established.input.uri().path_or_root().as_ref(), "/upload");
        assert!(established.input.extensions().contains::<RequestMarker>());
        assert!(
            established
                .input
                .extensions()
                .contains::<SelectedAttemptMarker>()
        );
    }

    #[tokio::test]
    async fn rejects_request_without_resolvable_authority() {
        let inner = service_fn(async |input: ConnectRequest| {
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let adapter = HttpConnectRequestAdapter::new(inner);
        let request = Request::builder().uri("/").body(NonCloneBody).unwrap();

        let error = adapter.serve(request).await.unwrap_err();
        assert_eq!(
            error.domain(),
            rama_net::client::ConnectionErrorDomain::Local
        );
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    }
}
