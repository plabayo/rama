use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
};
use rama_http::utils::{request_adaptable_upgrade, request_signals_upgrade};
use rama_http_types::{Request, Version, proto::ext::Protocol as ConnectProtocol};
use rama_net::{
    AuthorityInputExt, ProtocolInputExt, TransportProtocolInputExt,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
        EstablishedClientConnection,
    },
    http::{HttpRequestVersion, TargetHttpVersion},
};
use rama_utils::macros::define_inner_service_accessors;

fn try_from_http_request<Body>(request: &Request<Body>) -> Result<ConnectRequest, ConnectionError> {
    let application_protocol = request.target_protocol().cloned();
    let authority = request
        .target_authority()
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
    if !extensions.contains::<TargetHttpVersion>() && request_signals_upgrade(request) {
        match request_adaptable_upgrade(request).filter(|_| request.version() <= Version::HTTP_11) {
            // Selection keys on the protocol to keep this upgrade off unannounced HTTP/3.
            Some(protocol) => {
                if !extensions.contains::<ConnectProtocol>() {
                    extensions.insert(protocol);
                }
            }
            // A handshake the version adapter cannot translate must stay on its version.
            None => {
                extensions.insert(TargetHttpVersion(request.version()));
            }
        }
    }

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
#[derive(Debug, Clone, ExtensionsRef)]
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

    /// Configure the wrapped connector before sharing the adapter.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
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
        } = Box::pin(self.inner.connect(connect_request)).await?;

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
    use rama_http_types::{
        Method, Request, Version, header, proto::ext::Protocol as ConnectProtocol,
    };
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

    #[test]
    fn egress_version_selects_transport_before_request_adaptation() {
        for ingress in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            for egress in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                let request = Request::builder()
                    .uri("https://example.com/")
                    .version(ingress)
                    .body(())
                    .unwrap();
                request.extensions().insert(TargetHttpVersion(egress));
                let input = try_from_http_request(&request).unwrap();
                assert_eq!(
                    input.transport_protocol(),
                    Some(if egress == Version::HTTP_3 {
                        TransportProtocol::Udp
                    } else {
                        TransportProtocol::Tcp
                    })
                );
                assert_eq!(request.version(), ingress);
            }
        }
    }

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

    #[test]
    fn upgrades_stay_on_their_version_unless_adaptable() {
        let request = |version: Version, method: Method, headers: &[(&str, &str)]| {
            let mut builder = Request::builder()
                .uri("https://example.com/socket")
                .version(version)
                .method(method);
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            builder.body(()).unwrap()
        };
        let upgrade = |value| [("connection", "upgrade"), ("upgrade", value)];
        let with_protocol = |request: Request<()>, protocol| {
            request
                .extensions()
                .insert(ConnectProtocol::from_static(protocol));
            request
        };
        // (case, request, target the connect request carries, protocol it carries)
        let cases = [
            (
                "websocket upgrade",
                request(Version::HTTP_11, Method::GET, &upgrade("websocket")),
                None,
                Some("websocket"),
            ),
            (
                "websocket upgrade on HTTP/1.0",
                request(Version::HTTP_10, Method::GET, &upgrade("websocket")),
                None,
                Some("websocket"),
            ),
            (
                "websocket upgrade that is not a GET",
                request(Version::HTTP_11, Method::POST, &upgrade("websocket")),
                Some(Version::HTTP_11),
                None,
            ),
            (
                "connect-udp upgrade",
                request(Version::HTTP_11, Method::GET, &upgrade("connect-udp")),
                None,
                Some("connect-udp"),
            ),
            (
                "h2c upgrade",
                request(Version::HTTP_11, Method::GET, &upgrade("h2c")),
                Some(Version::HTTP_11),
                None,
            ),
            (
                "multi-token upgrade",
                request(Version::HTTP_11, Method::GET, &upgrade("h2c, websocket")),
                Some(Version::HTTP_11),
                None,
            ),
            (
                "connection upgrade without upgrade",
                request(
                    Version::HTTP_11,
                    Method::GET,
                    &[("connection", "keep-alive, Upgrade")],
                ),
                Some(Version::HTTP_11),
                None,
            ),
            (
                "upgrade without connection",
                request(Version::HTTP_11, Method::GET, &[("upgrade", "connect-udp")]),
                Some(Version::HTTP_11),
                None,
            ),
            (
                "protocol on a GET",
                with_protocol(request(Version::HTTP_11, Method::GET, &[]), "connect-udp"),
                Some(Version::HTTP_11),
                Some("connect-udp"),
            ),
            (
                "h2 extended CONNECT",
                with_protocol(request(Version::HTTP_2, Method::CONNECT, &[]), "websocket"),
                Some(Version::HTTP_2),
                Some("websocket"),
            ),
            (
                "h3 extended CONNECT",
                with_protocol(
                    request(Version::HTTP_3, Method::CONNECT, &[]),
                    "connect-udp",
                ),
                Some(Version::HTTP_3),
                Some("connect-udp"),
            ),
            (
                "ordinary request",
                request(Version::HTTP_11, Method::GET, &[]),
                None,
                None,
            ),
        ];
        for (case, request, target, protocol) in cases {
            let input = try_from_http_request(&request).unwrap();
            assert_eq!(
                input
                    .extensions()
                    .get_ref::<TargetHttpVersion>()
                    .map(|target| target.0),
                target,
                "{case}"
            );
            assert_eq!(
                input
                    .extensions()
                    .get_ref::<ConnectProtocol>()
                    .map(|protocol| protocol.as_str()),
                protocol,
                "{case}"
            );
            // An explicit target is kept.
            request
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
            let input = try_from_http_request(&request).unwrap();
            assert_eq!(
                input.extensions().get_ref::<TargetHttpVersion>(),
                Some(&TargetHttpVersion(Version::HTTP_2)),
                "{case}"
            );
        }
    }

    /// Retries and redirects fork each attempt from the caller's store, so the protocol
    /// written back on one attempt never reaches the next.
    #[tokio::test]
    async fn a_written_back_protocol_stays_on_its_attempt() {
        let inner = service_fn(async |input: ConnectRequest| {
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let adapter = HttpConnectRequestAdapter::new(inner);
        let mut request = Request::builder()
            .uri("https://example.com/socket")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .body(NonCloneBody)
            .unwrap();
        let caller = request.fork_extensions_in_place();
        let established = adapter.serve(request).await.unwrap();
        assert!(established.input.extensions().contains::<ConnectProtocol>());
        assert!(!caller.contains::<ConnectProtocol>());
        assert!(!caller.fork().contains::<ConnectProtocol>());
    }

    #[test]
    fn failed_attempt_metadata_does_not_pin_a_retry() {
        let request = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();
        let failed = try_from_http_request(&request).unwrap();
        failed.extensions.insert(TargetHttpVersion(Version::HTTP_3));
        let retry = try_from_http_request(&request).unwrap();
        assert!(!retry.extensions.contains::<TargetHttpVersion>());
        assert_eq!(retry.transport_protocol(), Some(TransportProtocol::Tcp));
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
