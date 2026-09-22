//! Select an HTTP service before establishing a connection.
//!
//! Place this connector outside proxy-route selection and connection pools. Each
//! candidate receives an isolated connection request; the logical origin remains
//! unchanged while `ConnectorTarget` selects the endpoint to reach through the
//! configured route. No HTTP request body enters this selection loop.
//!
//! Automatic alternative discovery currently applies to HTTPS origins. Plain
//! HTTP advertisements can be cached, but using them requires the separate
//! opportunistic-security authorization described by RFC 8164.
//! Retries must fork the original connection request; returned input includes
//! the operational state of the established connection.

use crate::layer::alt_svc::{AltSvc, AltSvcCache, AltSvcLayer};
use rama_core::{
    Fork as _, Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, ExtensionsRef},
    telemetry::tracing,
};
use rama_http_types::{
    Version,
    conn::{
        EstablishedHttpService, HttpOrigin, HttpServiceCandidate, HttpServiceCandidates,
        HttpServiceSource, SelectedHttpService,
    },
    proto::h2::alt_svc::AltSvcObserverExtension,
};
use rama_net::{
    Protocol,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorDomain, ConnectionErrorKind,
        ConnectorService, ConnectorTarget, EstablishedClientConnection, ProxyRoute, ProxyRoutes,
    },
    conn::ConnectionHealthWatcher,
    http::{HttpRequestVersion, TargetHttpVersion},
    tls::ApplicationProtocol,
};
#[cfg(feature = "tls")]
use rama_tls::client::{NegotiatedTlsParameters, TlsServerAuthentication};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::time::Instant;

// Speculation is sequential: cap its cost before trying the next service. Slow
// networks can increase this budget; it includes DNS and transport/TLS setup.
const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(300);
const DEFAULT_MAX_ATTEMPTS: usize = 8;

/// Preserve a terminal failure observed by an address race across cancellation.
///
/// A transport calls [`Self::reject`] after an authentication, protocol or policy
/// failure. An outer timeout then cannot disguise that failure as unavailability
/// and cause fallback to another service.
#[derive(Debug, Default, Extension)]
pub struct HttpServiceAttempt(OnceLock<ConnectionErrorKind>);

impl HttpServiceAttempt {
    pub fn reject(&self) {
        self.reject_with_kind(ConnectionErrorKind::Authentication);
    }

    /// Preserve the first terminal failure observed during an address race.
    pub fn reject_with_kind(&self, kind: ConnectionErrorKind) {
        self.0.get_or_init(|| kind);
    }

    #[must_use]
    pub fn failed(&self) -> bool {
        self.0.get().is_some()
    }
}

/// HTTP service discovery and bounded connection-selection policy.
#[derive(Clone, Debug)]
pub struct HttpServiceLayer {
    cache: Option<AltSvcCache>,
    protocols: Arc<[ApplicationProtocol]>,
    attempt_timeout: Duration,
    timeout: Option<Duration>,
    max_attempts: usize,
}

impl Default for HttpServiceLayer {
    fn default() -> Self {
        Self {
            cache: None,
            protocols: Arc::from([]),
            attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
            timeout: None,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }
}

impl HttpServiceLayer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Share an Alt-Svc cache. `None` disables learning and cached discovery.
        pub fn cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.cache = cache;
            self
        }
    }

    generate_set_and_with! {
        /// Declare the advertised protocols supported by the inner connector.
        pub fn protocols(mut self, protocols: impl IntoIterator<Item = ApplicationProtocol>) -> Self {
            self.protocols = protocols.into_iter().collect();
            self
        }
    }

    generate_set_and_with! {
        /// Bound one alternative connection attempt, including DNS and handshakes.
        ///
        /// Defaults to 300 ms to bound sequential speculation before origin fallback.
        /// Increase this for high-latency paths; this connector does not race the origin.
        pub fn attempt_timeout(mut self, timeout: Duration) -> Self {
            self.attempt_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Bound the entire connection-selection operation, including fallback.
        /// Disabled by default; the caller's transport deadlines remain authoritative.
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Bound connection attempts, reserving one for ordinary origin fallback.
        /// Zero rejects the operation without invoking the inner connector.
        pub fn max_attempts(mut self, count: usize) -> Self {
            self.max_attempts = count;
            self
        }
    }
}

impl<S> Layer<S> for HttpServiceLayer {
    type Service = HttpServiceConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpServiceConnector {
            inner,
            policy: self.clone(),
        }
    }
}

/// Discover and select an HTTP service before invoking an inner route connector.
#[derive(Clone, Debug)]
pub struct HttpServiceConnector<S> {
    inner: S,
    policy: HttpServiceLayer,
}

impl<S> HttpServiceConnector<S> {
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            policy: HttpServiceLayer::default(),
        }
    }

    define_inner_service_accessors!();

    generate_set_and_with! {
        /// Share an Alt-Svc cache; `None` disables cached discovery and learning.
        pub fn cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.policy.cache = cache;
            self
        }
    }

    generate_set_and_with! {
        /// Declare the advertised protocols supported by the inner connector.
        pub fn protocols(mut self, protocols: impl IntoIterator<Item = ApplicationProtocol>) -> Self {
            self.policy.protocols = protocols.into_iter().collect();
            self
        }
    }

    generate_set_and_with! {
        /// Bound one alternative connection attempt, including DNS and handshakes.
        ///
        /// Defaults to 300 ms to bound sequential speculation before origin fallback.
        /// Increase this for high-latency paths; this connector does not race the origin.
        pub fn attempt_timeout(mut self, timeout: Duration) -> Self {
            self.policy.attempt_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Bound the complete selection operation, including origin fallback.
        /// Disabled by default; the caller's transport deadlines remain authoritative.
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.policy.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Bound attempts, including the reserved origin fallback attempt.
        pub fn max_attempts(mut self, count: usize) -> Self {
            self.policy.max_attempts = count;
            self
        }
    }
}

fn invalid(message: &'static str) -> ConnectionError {
    ConnectionError::local(
        BoxError::from_static_str(message),
        ConnectionErrorKind::InvalidInput,
    )
}

fn availability(error: &ConnectionError) -> bool {
    error.domain() == ConnectionErrorDomain::Transport
        && matches!(
            error.kind(),
            ConnectionErrorKind::Unavailable | ConnectionErrorKind::Timeout
        )
}

fn origin(input: &ConnectRequest) -> Option<HttpOrigin> {
    let protocol = match input.application_protocol.as_ref()? {
        protocol if protocol == &Protocol::HTTP || protocol == &Protocol::HTTPS => protocol.clone(),
        protocol if protocol == &Protocol::WS => Protocol::HTTP,
        protocol if protocol == &Protocol::WSS => Protocol::HTTPS,
        _ => return None,
    };
    HttpOrigin::new(protocol, input.authority.clone()).ok()
}

fn required_version(input: &ConnectRequest) -> Option<Version> {
    input
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .map(|value| value.0)
        .or_else(|| {
            input
                .extensions()
                .get_ref::<HttpRequestVersion>()
                .map(|value| value.0)
                .filter(|version| *version == Version::HTTP_3)
        })
}

#[cfg(feature = "tls")]
pub(super) fn authenticates<C: ExtensionsRef>(connection: &C, origin: &HttpOrigin) -> bool {
    connection
        .extensions()
        .get_ref::<TlsServerAuthentication>()
        .and_then(|identity| identity.0.as_ref())
        .is_some_and(|identity| identity.clone().canonicalize() == origin.authority().host)
}

#[cfg(not(feature = "tls"))]
pub(super) fn authenticates<C: ExtensionsRef>(_connection: &C, _origin: &HttpOrigin) -> bool {
    false
}

fn discard_connection(connection: &impl ExtensionsRef) {
    if let Some(health) = connection.extensions().get_ref::<ConnectionHealthWatcher>() {
        health.mark_broken();
    }
}

fn verify_alternative<C: ExtensionsRef>(
    connection: &C,
    origin: &HttpOrigin,
    candidate: &HttpServiceCandidate,
) -> Result<(), ConnectionError> {
    if !authenticates(connection, origin) {
        return Err(ConnectionError::application(
            BoxError::from_static_str(
                "alternative service did not authenticate the logical origin",
            ),
            ConnectionErrorKind::Authentication,
        ));
    }
    #[cfg(feature = "tls")]
    if connection
        .extensions()
        .get_ref::<NegotiatedTlsParameters>()
        .and_then(|parameters| parameters.application_layer_protocol.as_ref())
        != Some(&candidate.protocol)
    {
        return Err(ConnectionError::application(
            BoxError::from_static_str(
                "alternative service did not negotiate its advertised protocol",
            ),
            ConnectionErrorKind::Protocol,
        ));
    }
    let expected = Version::try_from(&candidate.protocol).map_err(|error| {
        ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
            .context("unsupported advertised HTTP protocol")
    })?;
    verify_version(connection, expected)
}

fn verify_version<C: ExtensionsRef>(
    connection: &C,
    expected: Version,
) -> Result<(), ConnectionError> {
    if connection
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .map(|version| version.0)
        != Some(expected)
    {
        return Err(ConnectionError::application(
            BoxError::from_static_str("connection did not establish the required HTTP version"),
            ConnectionErrorKind::Protocol,
        ));
    }
    Ok(())
}

impl<S> HttpServiceConnector<S>
where
    S: ConnectorService<ConnectRequest>,
    S::Connection: ExtensionsRef,
{
    fn candidates(
        &self,
        input: &ConnectRequest,
        origin: Option<&HttpOrigin>,
        proxy_context: bool,
    ) -> (Option<Arc<HttpServiceCandidates>>, bool) {
        if !cfg!(feature = "tls")
            || input.application_protocol.as_ref() != Some(&Protocol::HTTPS)
            || input.extensions().contains::<ConnectorTarget>()
        {
            return (None, false);
        }

        if let Some(candidates) = input.extensions().get_arc::<HttpServiceCandidates>()
            && Some(candidates.origin()) == origin
        {
            return (Some(candidates), false);
        }

        let candidates = origin.and_then(|origin| {
            let cache = self.policy.cache.as_ref()?;
            if proxy_context {
                cache.lookup_fresh(origin)
            } else {
                cache.lookup(origin)
            }
        });
        (candidates, true)
    }

    fn candidate_version(
        &self,
        candidate: &HttpServiceCandidate,
        required: Option<Version>,
    ) -> Option<Version> {
        if !self.policy.protocols.contains(&candidate.protocol) {
            return None;
        }

        let version = Version::try_from(&candidate.protocol).ok()?;
        (!required.is_some_and(|required| required != version)).then_some(version)
    }

    async fn attempt(
        &self,
        input: ConnectRequest,
        deadline: Option<Instant>,
        speculative: bool,
    ) -> Result<EstablishedClientConnection<S::Connection, ConnectRequest>, ConnectionError> {
        let state = speculative.then(|| Arc::new(HttpServiceAttempt::default()));
        if let Some(state) = &state {
            input.extensions().insert_arc(state.clone());
        }
        let attempt_deadline = if speculative {
            let speculative_deadline = Instant::now()
                .checked_add(self.policy.attempt_timeout)
                .ok_or_else(|| invalid("HTTP service attempt timeout is too large"))?;
            Some(deadline.map_or(speculative_deadline, |deadline| {
                deadline.min(speculative_deadline)
            }))
        } else {
            deadline
        };
        let Some(attempt_deadline) = attempt_deadline else {
            return self.inner.connect(input).await;
        };
        if Instant::now() >= attempt_deadline {
            let error = BoxError::from_static_str("HTTP service connection budget exhausted");
            return Err(if Some(attempt_deadline) == deadline {
                ConnectionError::local(error, ConnectionErrorKind::Timeout)
            } else {
                ConnectionError::transport(error, ConnectionErrorKind::Timeout)
            });
        }

        let result = tokio::time::timeout_at(attempt_deadline, self.inner.connect(input)).await;
        let rejected = state.as_ref().and_then(|state| state.0.get().copied());
        match (result, rejected) {
            (Ok(Err(error)), Some(kind)) if availability(&error) => {
                Err(ConnectionError::application(error, kind)
                    .context("terminal failure during service address race"))
            }
            (Ok(result), _) => result,
            (Err(_), Some(kind)) => Err(ConnectionError::application(
                BoxError::from_static_str(
                    "terminal connection failure preceded service attempt timeout",
                ),
                kind,
            )),
            (Err(error), None) if Some(attempt_deadline) == deadline => {
                Err(ConnectionError::local(error, ConnectionErrorKind::Timeout)
                    .context("HTTP service selection deadline"))
            }
            (Err(error), None) => Err(ConnectionError::transport(
                error,
                ConnectionErrorKind::Timeout,
            )
            .context("HTTP service candidate deadline")),
        }
    }

    fn wrap(
        &self,
        established: EstablishedClientConnection<S::Connection, ConnectRequest>,
        origin: Option<HttpOrigin>,
        selection: Option<(Arc<HttpServiceCandidates>, usize)>,
    ) -> EstablishedClientConnection<AltSvc<S::Connection>, ConnectRequest> {
        let EstablishedClientConnection { conn, input } = established;
        let conn = match origin {
            Some(origin) => {
                let authenticated = authenticates(&conn, &origin);
                let established_alternative = conn
                    .extensions()
                    .get_ref::<EstablishedHttpService>()
                    .filter(|service| {
                        service.origin == origin
                            && service.candidate.source == HttpServiceSource::AltSvc
                    })
                    .map(|service| service.candidate.target.clone());
                let mut layer = AltSvcLayer::new(origin)
                    .maybe_with_cache(self.policy.cache.clone())
                    .with_authenticated(authenticated)
                    .maybe_with_alternative(established_alternative);
                if let Some((snapshot, index)) = selection {
                    layer = layer.with_selection(snapshot, index);
                }
                layer.layer(conn)
            }
            None => AltSvc::passthrough(conn),
        };
        EstablishedClientConnection { conn, input }
    }
}

impl<S> Service<ConnectRequest> for HttpServiceConnector<S>
where
    S: ConnectorService<ConnectRequest>,
    S::Connection: ExtensionsRef,
{
    type Output = EstablishedClientConnection<AltSvc<S::Connection>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        if self.policy.max_attempts == 0 {
            return Err(invalid(
                "HTTP service selection requires at least one attempt",
            ));
        }

        let deadline = self
            .policy
            .timeout
            .map(|timeout| {
                Instant::now()
                    .checked_add(timeout)
                    .ok_or_else(|| invalid("HTTP service timeout is too large"))
            })
            .transpose()?;
        let origin = origin(&input);
        if let (Some(cache), Some(origin)) = (&self.policy.cache, &origin)
            && !input.extensions().contains::<AltSvcObserverExtension>()
        {
            input
                .extensions()
                .insert(cache.frame_observer(origin.clone()));
        }
        let required = required_version(&input);
        let proxy_context = input.extensions().get_ref::<ProxyRoutes>().map_or_else(
            || {
                input
                    .extensions()
                    .get_ref::<ProxyRoute>()
                    .is_some_and(|route| route.proxy_address().is_some())
            },
            |routes| routes.iter().any(|route| route.proxy_address().is_some()),
        );
        let (snapshot, from_cache) = self.candidates(&input, origin.as_ref(), proxy_context);
        let mut attempts = 0;

        if let (Some(origin), Some(snapshot)) = (origin.as_ref(), snapshot.as_ref())
            && snapshot.origin() == origin
        {
            for (index, candidate) in snapshot.iter().enumerate() {
                if attempts >= self.policy.max_attempts.saturating_sub(1) {
                    break;
                }
                let Some(version) = self.candidate_version(candidate, required) else {
                    continue;
                };

                if from_cache
                    && let Some(cache) = &self.policy.cache
                    && !(if proxy_context {
                        cache.is_fresh(snapshot, index)
                    } else {
                        cache.is_usable(snapshot, index)
                    })
                {
                    continue;
                }

                let attempt = input.fork();
                attempt.extensions().insert_arc(snapshot.clone());
                attempt
                    .extensions()
                    .insert(ConnectorTarget(candidate.target.clone()));
                attempt.extensions().insert(TargetHttpVersion(version));
                attempt
                    .extensions()
                    .insert(SelectedHttpService::new(origin.clone(), candidate.clone()));
                attempts += 1;
                let failure_context = self
                    .policy
                    .cache
                    .as_ref()
                    .map(|cache| (cache, cache.network_epoch()));
                match self.attempt(attempt, deadline, true).await {
                    Ok(established) => {
                        verify_alternative(&established.conn, origin, candidate).inspect_err(
                            |_| {
                                discard_connection(&established.conn);
                                if candidate.source == HttpServiceSource::AltSvc
                                    && let Some((cache, network)) = failure_context
                                {
                                    cache.failed_attempt(snapshot, index, network, true);
                                }
                            },
                        )?;
                        let extensions = established.conn.extensions();
                        if let Some(current) = extensions.get_ref::<EstablishedHttpService>() {
                            if current.origin != *origin
                                || current.candidate.protocol != candidate.protocol
                                || current.candidate.target != candidate.target
                            {
                                discard_connection(&established.conn);
                                return Err(ConnectionError::application(
                                    BoxError::from_static_str(
                                        "pooled connection does not match selected service",
                                    ),
                                    ConnectionErrorKind::Protocol,
                                ));
                            }
                        } else {
                            extensions.insert(EstablishedHttpService::new(
                                origin.clone(),
                                candidate.clone(),
                            ));
                        }
                        return Ok(self.wrap(
                            established,
                            Some(origin.clone()),
                            Some((snapshot.clone(), index)),
                        ));
                    }
                    Err(error)
                        if error.domain() == ConnectionErrorDomain::Local
                            && error.kind() == ConnectionErrorKind::Unavailable =>
                    {
                        tracing::debug!(
                            ?error,
                            ?candidate,
                            "connector cannot reach this service; trying next service"
                        );
                    }
                    Err(error) if availability(&error) => {
                        if !proxy_context
                            && candidate.source == HttpServiceSource::AltSvc
                            && let Some((cache, network)) = failure_context
                        {
                            cache.failed_attempt(snapshot, index, network, false);
                        }
                        tracing::debug!(
                            ?error,
                            ?candidate,
                            "HTTP alternative unavailable; trying next service"
                        );
                    }
                    Err(error) => {
                        let endpoint_failed = match error.domain() {
                            ConnectionErrorDomain::Application => matches!(
                                error.kind(),
                                ConnectionErrorKind::Authentication
                                    | ConnectionErrorKind::Protocol
                                    | ConnectionErrorKind::Rejected
                            ),
                            ConnectionErrorDomain::Transport if !proxy_context => matches!(
                                error.kind(),
                                ConnectionErrorKind::Authentication | ConnectionErrorKind::Protocol
                            ),
                            _ => false,
                        };
                        if endpoint_failed
                            && candidate.source == HttpServiceSource::AltSvc
                            && let Some((cache, network)) = failure_context
                        {
                            cache.failed_attempt(
                                snapshot,
                                index,
                                network,
                                error.domain() == ConnectionErrorDomain::Application,
                            );
                        }
                        return Err(error);
                    }
                }
            }
        }

        let attempt = input.fork();
        if let Some(snapshot) = &snapshot {
            attempt.extensions().insert_arc(snapshot.clone());
        }
        if let Some(version) = required {
            attempt.extensions().insert(TargetHttpVersion(version));
        }
        let established = self.attempt(attempt, deadline, false).await?;
        if let Some(version) = required {
            verify_version(&established.conn, version)
                .inspect_err(|_| discard_connection(&established.conn))?;
        }
        Ok(self.wrap(established, origin, None))
    }
}

#[cfg(test)]
mod tests;
