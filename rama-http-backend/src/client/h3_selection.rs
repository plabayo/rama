//! Select a connection before dispatching the request body exactly once.

use rama_core::{
    Fork as _, Layer as _, Service, error::BoxErrorExt as _, error::error_chain,
    extensions::ExtensionsRef,
};
use rama_http::layer::alt_svc::{AltSvc, AltSvcCache, AltSvcLayer};
use rama_http_types::Version;
use rama_net::{
    ProtocolInputExt as _,
    address::HostWithPort,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService, ConnectorTarget,
        EstablishedClientConnection, ProxyRoute,
    },
};
use std::time::Duration;

/// How a client chooses HTTP/3 before dispatching a request.
///
/// An explicit HTTP/3 version requirement takes precedence over this policy:
/// it attempts H3 without requiring an Alt-Svc advertisement and fails if H3
/// cannot be established, rather than falling back to TCP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Http3Selection {
    /// Use H3 exclusively; fail if the route or peer cannot provide it.
    Only,
    /// Try an advertised alternative, or H3 at the origin, within the attempt budget.
    Prefer,
    /// Try H3 only when an authenticated, fresh Alt-Svc hint exists.
    #[default]
    AlternativeServices,
}

/// Route between independently pooled HTTP/3 and TCP HTTP connectors.
///
/// Put [`super::Http3Policy`] outside the H3 pool and [`super::TlsPoolPolicy`]
/// outside the TCP pool so request TLS overrides cannot reuse an incompatible
/// connection. Connection establishment is
/// bounded, but requests themselves are never raced or replayed across protocols.
#[derive(Clone, Debug)]
pub struct Http3SelectionConnector<H, T> {
    h3: H,
    tcp: T,
    cache: Option<AltSvcCache>,
    selection: Http3Selection,
    attempt_budget: Duration,
}

impl<H, T> Http3SelectionConnector<H, T> {
    /// Compose prepared H3 and TCP connector stacks.
    ///
    /// Pass no cache to disable advertised alternatives and response learning.
    pub fn new(
        h3: H,
        tcp: T,
        cache: Option<AltSvcCache>,
        selection: Http3Selection,
        attempt_budget: Duration,
    ) -> Self {
        Self {
            h3,
            tcp,
            cache,
            selection,
            attempt_budget,
        }
    }
}

impl<H, T> Service<ConnectRequest> for Http3SelectionConnector<H, T>
where
    H: ConnectorService<ConnectRequest>,
    T: ConnectorService<ConnectRequest, Connection = H::Connection>,
{
    type Output = EstablishedClientConnection<AltSvc<H::Connection>, ConnectRequest>;
    type Error = ConnectionError;
    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let origin = input.authority.clone();
        let secure = input
            .protocol()
            .is_some_and(|protocol| protocol == &rama_net::Protocol::HTTPS);
        let direct = input
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .is_none();
        let required = super::pool::connection_version_requirement(&input);
        let only = self.selection == Http3Selection::Only || required == Some(Version::HTTP_3);
        let alternate = (secure && direct && !input.extensions().contains::<ConnectorTarget>())
            .then(|| self.cache.as_ref().and_then(|cache| cache.lookup(&origin)))
            .flatten();
        let attempt = only
            || (secure
                && direct
                && required.is_none()
                && (alternate.is_some() || self.selection == Http3Selection::Prefer));
        if attempt {
            let candidate = input.fork();
            let attempt_state = AttemptState::default();
            candidate.extensions().insert(attempt_state.clone());
            if let Some(target) = &alternate {
                candidate
                    .extensions()
                    .insert(ConnectorTarget(target.clone()));
            }
            let result =
                tokio::time::timeout(self.attempt_budget, self.h3.connect(candidate)).await;
            match result {
                Ok(Ok(EstablishedClientConnection { input, conn })) => {
                    return Ok(EstablishedClientConnection {
                        input,
                        conn: wrap_connection(conn, self.cache.clone(), origin, alternate, secure),
                    });
                }
                Ok(Err(error)) if only || attempt_state.failed() || !fallback_allowed(&error) => {
                    return Err(error);
                }
                Err(_) if attempt_state.failed() => {
                    return Err(ConnectionError::application(
                        rama_core::error::BoxError::from_static_str(
                            "HTTP/3 authentication or protocol failure during address race",
                        ),
                        ConnectionErrorKind::Authentication,
                    ));
                }
                Err(error) if only => {
                    return Err(ConnectionError::transport(
                        error,
                        ConnectionErrorKind::Timeout,
                    ));
                }
                _ => {
                    if let Some(target) = &alternate
                        && let Some(cache) = &self.cache
                    {
                        cache.failed(&origin, target);
                    }
                }
            }
        }
        let EstablishedClientConnection { input, conn } = self.tcp.connect(input).await?;
        Ok(EstablishedClientConnection {
            input,
            conn: wrap_connection(conn, self.cache.clone(), origin, None, secure),
        })
    }
}

fn fallback_allowed(error: &ConnectionError) -> bool {
    if error.kind() == ConnectionErrorKind::Timeout {
        return true;
    }
    // TLS alerts, certificate/pin failures and local policy failures never downgrade.
    availability_error(error)
}

pub(crate) fn availability_error(error: &(dyn std::error::Error + 'static)) -> bool {
    error_chain(error, 32).any(|error| {
        error
            .downcast_ref::<rama_quic::ConnectionError>()
            .is_some_and(|error| {
                matches!(
                    error,
                    rama_quic::ConnectionError::TimedOut
                        | rama_quic::ConnectionError::VersionMismatch { .. }
                )
            })
            || error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::NetworkUnreachable
                        | std::io::ErrorKind::HostUnreachable
                )
            })
    })
}

#[derive(Debug, Clone, Default, rama_core::extensions::Extension)]
pub(crate) struct AttemptState(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl AttemptState {
    pub(crate) fn failed(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn reject(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Carry verified transport provenance into the transport-independent middleware.
fn wrap_connection<C: ExtensionsRef>(
    conn: C,
    cache: Option<AltSvcCache>,
    origin: HostWithPort,
    alternate: Option<HostWithPort>,
    secure: bool,
) -> AltSvc<C> {
    let authenticated = secure
        && conn
            .extensions()
            .get_ref::<rama_tls::client::TlsServerAuthentication>()
            .and_then(|auth| auth.0.as_ref())
            .is_some_and(|identity| {
                identity.clone().canonicalize() == origin.host.clone().canonicalize()
            });
    AltSvcLayer::new(cache, origin)
        .with_authenticated(authenticated)
        .with_alternative(alternate)
        .layer(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{error::BoxError, extensions::Extensions};
    use rama_core::{extensions::Extension, service::service_fn};
    use rama_http_types::{Body, Request, Response, StatusCode};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Connection {
        extensions: Extensions,
        status: StatusCode,
        dispatched: Arc<AtomicUsize>,
    }
    impl ExtensionsRef for Connection {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }
    impl Service<Request<Body>> for Connection {
        type Output = Response;
        type Error = BoxError;
        async fn serve(&self, request: Request<Body>) -> Result<Response, BoxError> {
            use rama_http_types::body::util::BodyExt as _;
            self.dispatched.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.into_body().collect().await?.to_bytes(), "one body");
            Ok(Response::builder()
                .status(self.status)
                .header("alt-svc", "h3=\":8443\"")
                .body(Body::empty())?)
        }
    }

    fn input() -> ConnectRequest {
        ConnectRequest::new("example.com:443".parse().unwrap())
            .with_application_protocol(rama_net::Protocol::HTTPS)
    }

    fn connection(
        dispatched: Arc<AtomicUsize>,
        authenticated: bool,
        status: StatusCode,
    ) -> Connection {
        let extensions = Extensions::new();
        extensions.insert(rama_tls::client::TlsServerAuthentication(
            authenticated.then(|| "example.com".parse().unwrap()),
        ));
        Connection {
            extensions,
            status,
            dispatched,
        }
    }

    #[derive(Debug, Clone, Extension)]
    struct Sentinel;

    #[tokio::test]
    async fn fallback_establishes_once_without_polluting_original_route() {
        let dispatched = Arc::new(AtomicUsize::new(0));
        let h3 = service_fn(async |input: ConnectRequest| {
            input.extensions().insert(Sentinel);
            Err::<EstablishedClientConnection<Connection, ConnectRequest>, _>(
                ConnectionError::transport(
                    std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                    ConnectionErrorKind::Unavailable,
                ),
            )
        });
        let tcp = service_fn({
            let dispatched = dispatched.clone();
            move |input: ConnectRequest| {
                let dispatched = dispatched.clone();
                async move {
                    assert!(!input.extensions().contains::<Sentinel>());
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: connection(dispatched, true, StatusCode::OK),
                    })
                }
            }
        });
        let cache = AltSvcCache::default();
        let connector = Http3SelectionConnector::new(
            h3,
            tcp,
            Some(cache.clone()),
            Http3Selection::Prefer,
            Duration::from_secs(1),
        );
        let established = connector.serve(input()).await.unwrap();
        established
            .conn
            .serve(Request::new(Body::from("one body")))
            .await
            .unwrap();
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
        assert_eq!(cache.lookup(&input().authority).unwrap().port, 8443);
    }

    #[tokio::test]
    async fn timeout_fallback_does_not_reuse_tcp_with_new_certificate_pins() {
        use crate::client::{HttpPooledConnectorConfig, TlsPoolPolicy};
        use rama_http_types::body::util::BodyExt as _;
        let connections = Arc::new(AtomicUsize::new(0));
        let tcp = service_fn({
            let connections = connections.clone();
            move |input: ConnectRequest| {
                let connections = connections.clone();
                async move {
                    connections.fetch_add(1, Ordering::SeqCst);
                    if input
                        .extensions()
                        .contains::<rama_tls::client::TlsServerCertPins>()
                    {
                        return Err(ConnectionError::application(
                            BoxError::from_static_str(
                                "test certificate does not match requested pin",
                            ),
                            ConnectionErrorKind::Authentication,
                        ));
                    }
                    Ok(EstablishedClientConnection {
                        input,
                        conn: connection(Arc::default(), true, StatusCode::OK),
                    })
                }
            }
        });
        let tcp = TlsPoolPolicy::new(
            HttpPooledConnectorConfig::build_default_connector(tcp),
            rama_tls::client::TlsClientConfig::new(),
            rama_tls::TlsBackend::Auto,
        );
        let h3 = service_fn(async |_input: ConnectRequest| {
            std::future::pending::<
                Result<EstablishedClientConnection<_, ConnectRequest>, ConnectionError>,
            >()
            .await
        });
        let connector = Http3SelectionConnector::new(
            h3,
            tcp,
            Some(AltSvcCache::default()),
            Http3Selection::Prefer,
            Duration::from_millis(1),
        );
        for _ in 0..2 {
            connector
                .serve(input())
                .await
                .unwrap()
                .conn
                .serve(Request::new(Body::from("one body")))
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap();
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        let pinned = input();
        pinned
            .extensions()
            .insert(rama_tls::client::TlsServerCertPins::new(
                rama_tls::client::TlsServerCertPin::SpkiSha256([1; 32]),
            ));
        let Err(error) = connector.serve(pinned).await else {
            panic!("fallback bypassed the new certificate pins");
        };
        assert_eq!(error.kind(), ConnectionErrorKind::Authentication);
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn authentication_failure_survives_attempt_timeout() {
        let h3 = service_fn(async |input: ConnectRequest| {
            input
                .extensions()
                .get_ref::<AttemptState>()
                .unwrap()
                .reject();
            std::future::pending::<
                Result<EstablishedClientConnection<Connection, ConnectRequest>, ConnectionError>,
            >()
            .await
        });
        let tcp = service_fn(
            async |_input: ConnectRequest| -> Result<
                EstablishedClientConnection<Connection, ConnectRequest>,
                ConnectionError,
            > { panic!("must not downgrade") },
        );
        let connector = Http3SelectionConnector::new(
            h3,
            tcp,
            Some(AltSvcCache::default()),
            Http3Selection::Prefer,
            Duration::from_millis(1),
        );
        assert_eq!(
            connector.serve(input()).await.unwrap_err().kind(),
            ConnectionErrorKind::Authentication
        );
    }

    #[tokio::test]
    async fn explicit_h3_and_physical_route_are_preserved() {
        let h3 = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                input
                    .extensions()
                    .get_ref::<ConnectorTarget>()
                    .unwrap()
                    .0
                    .port,
                9443
            );
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: connection(Arc::default(), true, StatusCode::OK),
            })
        });
        let tcp = service_fn(
            async |_input: ConnectRequest| -> Result<
                EstablishedClientConnection<Connection, ConnectRequest>,
                ConnectionError,
            > { panic!("H3 explicitly required") },
        );
        let cache = AltSvcCache::default();
        let mut headers = rama_http_types::HeaderMap::new();
        headers.insert("alt-svc", "h3=\":8443\"".parse().unwrap());
        cache.record_authenticated(&input().authority, &headers, Duration::ZERO);
        let connector = Http3SelectionConnector::new(
            h3,
            tcp,
            Some(cache),
            Http3Selection::AlternativeServices,
            Duration::from_secs(1),
        );
        let input = input();
        input
            .extensions()
            .insert(rama_net::http::HttpRequestVersion(Version::HTTP_3));
        input
            .extensions()
            .insert(ConnectorTarget("forced.example:9443".parse().unwrap()));
        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn unverified_and_misdirected_responses_do_not_teach_alternatives() {
        for (authenticated, status) in [
            (false, StatusCode::OK),
            (true, StatusCode::MISDIRECTED_REQUEST),
        ] {
            let cache = AltSvcCache::default();
            let conn = wrap_connection(
                connection(Arc::default(), authenticated, status),
                Some(cache.clone()),
                input().authority,
                Some("example.com:8443".parse().unwrap()),
                true,
            );
            conn.serve(Request::new(Body::from("one body")))
                .await
                .unwrap();
            assert!(cache.lookup(&input().authority).is_none());
        }
    }
}
