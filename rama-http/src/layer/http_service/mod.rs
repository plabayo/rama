//! Select a physical endpoint and HTTP protocol without changing the logical origin.
//!
//! An alternative is another way to reach the same origin, not an HTTP redirect
//! ([RFC 7838 §2]). Its address goes in [`ConnectorTarget`]; the request authority,
//! TLS server name and verification policy still belong to the origin. Selection
//! happens before dispatch: this connector never consumes or replays an HTTP body.
//! The connection type is unchanged. [`HttpServiceSelection`] is published on the
//! winning input; [`EstablishedHttpService`] belongs to the connection. An HTTP
//! observer can use these public contracts without coupling this selector to its
//! service type. Compose response middleware separately, after selection.
//!
//! ```text
//! ConnectRequest: logical origin + optional required HTTP version
//!     |
//!     v
//! Request-supplied candidates, otherwise Alt-Svc cache
//!     |
//!     v
//! Filter known HTTP protocols, required version and backoff
//!     |
//!     v
//! Try alternative ----------------------> Verify origin + protocol
//!     | failure                                  | valid
//!     v                                          v
//! Next alternative (repeat)               Return connection + winning input
//!     | none usable                              ^
//!     v                                          |
//! Original endpoint -------- success ------------+
//!
//! Every attempt: proxy-route selection -> pool -> transport/TLS/HTTP
//! The actual connector enforces peer requirements using its effective policy.
//! Learning: response headers + H2 ALTSVC observer -> shared cache
//! ```
//!
//! Place [`HttpServiceConnector`] **outside** proxy-route selection and pooling:
//! each candidate is reached through the configured routes, with a pool key that
//! includes its physical target. Attempts fork the original connection input so
//! failed attempts cannot leave routing state behind; the winner returns its own
//! established input. One attempt is reserved for the original endpoint when
//! the discovery snapshot permits origin fallback.
//!
//! [RFC 7838 §2.4] permits fallback. Rama tries alternatives sequentially, with a
//! per-alternative deadline and an optional overall deadline. Remote failures
//! allow fallback while preserving any required version. Candidate-specific local
//! failures also fall back; the original endpoint still enforces the unchanged
//! policy. Only exhaustion of the overall deadline stops selection early.
//! Unsupported protocols and routes are local refusals, not broken alternatives;
//! they consume the candidate limit but leave the connection-attempt budget intact.
//! A request-specific TLS failure does not mark an
//! alternative broken for clients using the default policy. Connectors report
//! [`ConnectionPolicyScope`] during setup and on pooled connections; an unknown
//! scope permits use of a verified connection but never shares policy failures.
//!
//! Discovery and use are separate: HTTP advertisements can be cached, but this
//! selector currently uses alternatives only for HTTPS. It verifies the origin's
//! authenticated identity ([RFC 7838 §2.1]), protocol policy and established HTTP
//! version even on pool hits. HTTPS records select a transport, leaving stream
//! ALPN negotiation open (RFC 9460 §7.1.2); Alt-Svc remains protocol-specific.
//! Serving `http` origins over TLS additionally needs
//! the opt-in checks of [RFC 8164 §2], which are not implemented here. WebSocket
//! handshakes can learn hints but do not select alternative endpoints here.
//!
//! Separately composed [`crate::layer::alt_svc::AltSvc`] handles response
//! headers ([RFC 7838 §3]), `Alt-Used` (§5) and 421
//! invalidation (§6). The H2 observer learns connection-level advertisements
//! ([RFC 7838 §4]); both feed the same cache in receive order.
//!
//! [RFC 7838 §2]: https://www.rfc-editor.org/rfc/rfc7838.html#section-2
//! [RFC 7838 §2.1]: https://www.rfc-editor.org/rfc/rfc7838.html#section-2.1
//! [RFC 7838 §2.4]: https://www.rfc-editor.org/rfc/rfc7838.html#section-2.4
//! [RFC 7838 §3]: https://www.rfc-editor.org/rfc/rfc7838.html#section-3
//! [RFC 7838 §4]: https://www.rfc-editor.org/rfc/rfc7838.html#section-4
//! [RFC 8164 §2]: https://www.rfc-editor.org/rfc/rfc8164.html#section-2

use crate::layer::alt_svc::AltSvcCache;
use rama_core::{
    Fork as _, Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_http_types::{
    Version,
    conn::{
        EstablishedHttpService, FallbackHttpVersion, HttpOrigin, HttpServiceCandidate,
        HttpServiceCandidates, HttpServiceSelection, HttpServiceSource, SelectedHttpService,
    },
    proto::h2::alt_svc::AltSvcObserverExtension,
};
#[cfg(feature = "tls")]
use rama_net::address::HostRef;
use rama_net::{
    Protocol,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorDomain, ConnectionErrorKind,
        ConnectionPolicyScope, ConnectorService, ConnectorTarget, ConnectorTransportProtocol,
        EstablishedClientConnection, ProxyRouteContext,
    },
    conn::ConnectionHealthWatcher,
    http::{HttpRequestVersion, TargetHttpVersion},
    tls::{ApplicationProtocol, ServerName},
    transport::TransportProtocol,
};
#[cfg(feature = "tls")]
use rama_tls::client::{
    EchDiscoveryComplete, NegotiatedTlsParameters, TlsServerAuthenticatedAliases,
    TlsServerAuthentication,
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{
    sync::Arc,
    time::{Duration, Instant as StdInstant},
};
use tokio::time::Instant;

// Speculation is sequential: cap its cost before trying the next service. Slow
// networks can increase this budget; it includes DNS and transport/TLS setup.
const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(300);
const DEFAULT_MAX_ATTEMPTS: usize = 8;
// Matches the cache's default retained advertisement size. Caller-supplied lists
// also need a bound when locally unsupported protocols do not use dial attempts.
const DEFAULT_MAX_CANDIDATES: usize = 16;

/// Connection-attempt observations used by service selection and address races.
///
/// Kept as an HTTP-facing name for the protocol-independent connector contract.
/// Actual connectors report policy scope; the selector never inspects TLS config.
pub use rama_net::client::ConnectionAttempt as HttpServiceAttempt;

/// HTTP service discovery and bounded connection-selection policy.
#[derive(Clone, Debug)]
pub struct HttpServiceLayer {
    cache: Option<AltSvcCache>,
    attempt_timeout: Duration,
    timeout: Option<Duration>,
    max_attempts: usize,
    max_candidates: usize,
}

impl Default for HttpServiceLayer {
    fn default() -> Self {
        Self {
            cache: None,
            attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
            timeout: None,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            max_candidates: DEFAULT_MAX_CANDIDATES,
        }
    }
}

impl HttpServiceLayer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Share cached candidates and HTTP/2 frame learning; `None` disables both.
        /// Response observation is composed separately with `AltSvcLayer`.
        pub fn cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.cache = cache;
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
        /// Bound inspected candidates, including unknown or unsupported protocols.
        ///
        /// Defaults to 16, matching the cache's default advertisement capacity.
        /// Zero bypasses alternatives. Local capability refusals do not consume
        /// `max_attempts`, so this separately bounds caller-supplied candidate lists.
        pub fn max_candidates(mut self, count: usize) -> Self {
            self.max_candidates = count;
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
///
/// The inner connector honors [`TargetHttpVersion`] or rejects unsupported
/// protocols and routes before network I/O with [`ConnectionErrorDomain::Local`]
/// and [`ConnectionErrorKind::Unavailable`]. Such refusals leave cached endpoint
/// health and the network-attempt budget unchanged; no capability list is needed.
#[derive(Clone, Debug, ExtensionsRef)]
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
        /// Share cached candidates and HTTP/2 frame learning; `None` disables both.
        /// Response observation is composed separately with `AltSvcLayer`.
        pub fn cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.policy.cache = cache;
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
        /// Bound inspected candidates, including unknown or unsupported protocols.
        ///
        /// Defaults to 16, matching the cache's default advertisement capacity.
        /// Zero bypasses alternatives. Local capability refusals do not consume
        /// `max_attempts`, so this separately bounds caller-supplied candidate lists.
        pub fn max_candidates(mut self, count: usize) -> Self {
            self.policy.max_candidates = count;
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

/// WebSocket handshakes use HTTP: map WS/WSS to HTTP/HTTPS for learning,
/// preserving the original security scheme.
/// Whether a [`ConnectorTarget`] sends `input` to an endpoint other than its own authority,
/// which rules out alternatives and discovery.
pub(crate) fn dials_another_endpoint(input: &ConnectRequest) -> bool {
    input
        .extensions()
        .get_ref::<ConnectorTarget>()
        .is_some_and(|target| target.0 != input.authority)
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

/// Explicit targets constrain every HTTP version; H3 request metadata also means
/// prior knowledge in Rama. Ordinary H1/H2 metadata leaves negotiation open.
/// `FallbackHttpVersion` is a connection default, not a constraint on discovery.
/// When one is set, the request's version is no longer prior knowledge.
/// This is client policy, not a version-selection rule imposed by RFC 7838.
pub(super) fn required_version(input: &ConnectRequest) -> Option<Version> {
    let extensions = input.extensions();
    if let Some(target) = extensions.get_ref::<TargetHttpVersion>() {
        return Some(target.0);
    }
    if extensions.contains::<FallbackHttpVersion>() {
        return None;
    }
    extensions
        .get_ref::<HttpRequestVersion>()
        .map(|value| value.0)
        .filter(|version| *version == Version::HTTP_3)
}

/// Require the authenticated TLS name to match the origin, not the dial target.
/// `Host` equality already compares canonical identities without cloning them.
#[cfg(feature = "tls")]
pub(super) fn authenticates<C: ExtensionsRef>(connection: &C, origin: &HttpOrigin) -> bool {
    connection
        .extensions()
        .get_ref::<TlsServerAuthentication>()
        .and_then(|identity| identity.0.as_ref())
        .is_some_and(|identity| HostRef::from(identity) == HostRef::from(&origin.authority().host))
        || authenticates_alias(connection, origin)
}

#[cfg(not(feature = "tls"))]
pub(super) fn authenticates<C: ExtensionsRef>(_connection: &C, _origin: &HttpOrigin) -> bool {
    false
}

/// Whether a coalescing connector verified `origin` on this connection's certificate.
#[cfg(feature = "tls")]
fn authenticates_alias<C: ExtensionsRef>(connection: &C, origin: &HttpOrigin) -> bool {
    let extensions = connection.extensions();
    extensions
        .get_ref::<TlsServerAuthentication>()
        .zip(extensions.get_ref::<TlsServerAuthenticatedAliases>())
        .is_some_and(|(current, aliases)| {
            ServerName::try_from(&origin.authority().host)
                .is_ok_and(|origin| aliases.authenticates(current, &origin))
        })
}

#[cfg(not(feature = "tls"))]
fn authenticates_alias<C: ExtensionsRef>(_connection: &C, _origin: &HttpOrigin) -> bool {
    false
}

/// Keep a connection rejected by post-connect validation out of its pool.
fn discard_connection(connection: &impl ExtensionsRef) {
    if let Some(health) = connection.extensions().get_ref::<ConnectionHealthWatcher>() {
        health.mark_broken();
    }
}

/// HTTPS records choose TCP versus QUIC, but do not pin TCP ALPN (RFC 9460 §7.1.2).
/// Alt-Svc and configured candidates retain their exact protocol contract.
fn negotiates_http_stream(candidate: &HttpServiceCandidate) -> bool {
    candidate.source == HttpServiceSource::Https
        && matches!(
            candidate.protocol,
            ApplicationProtocol::HTTP_2 | ApplicationProtocol::HTTP_11
        )
}

/// Validate the established peer, including pool hits: origin authentication
/// (RFC 7838 §2.1), source-specific ALPN policy, and actual HTTP version.
fn verify_alternative<C: ExtensionsRef>(
    connection: &C,
    origin: &HttpOrigin,
    candidate: &HttpServiceCandidate,
) -> Result<ApplicationProtocol, ConnectionError> {
    if !authenticates(connection, origin) {
        // A pooled connection may have been opened explicitly under a policy
        // that cannot authenticate this origin. It remains valid for that use,
        // but cannot serve an advertisement. This is not an endpoint failure.
        return Err(ConnectionError::local(
            BoxError::from_static_str(
                "connection policy does not authenticate the alternative's origin",
            ),
            ConnectionErrorKind::Unavailable,
        ));
    }
    #[cfg(feature = "tls")]
    let protocol = {
        let negotiated = connection
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .and_then(|parameters| {
                parameters.application_layer_protocol.as_ref().or_else(|| {
                    // A completed TCP TLS handshake without ALPN means HTTP/1.1.
                    negotiates_http_stream(candidate).then_some(&ApplicationProtocol::HTTP_11)
                })
            });
        match negotiated {
            Some(protocol)
                if protocol == &candidate.protocol
                    || (negotiates_http_stream(candidate)
                        && matches!(
                            protocol,
                            ApplicationProtocol::HTTP_2 | ApplicationProtocol::HTTP_11
                        )) =>
            {
                protocol
            }
            _ => {
                return Err(ConnectionError::application(
                    BoxError::from_static_str(
                        "alternative service did not negotiate its advertised protocol",
                    ),
                    ConnectionErrorKind::Protocol,
                ));
            }
        }
    };
    #[cfg(not(feature = "tls"))]
    let protocol = &candidate.protocol;
    let expected = Version::try_from(protocol).map_err(|error| {
        ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
            .context("unsupported advertised HTTP protocol")
    })?;
    verify_version(connection, expected)?;
    Ok(protocol.clone())
}

/// Check the connection's negotiated version rather than trusting request intent.
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
    /// Prefer caller-supplied discovery; otherwise consult the shared cache.
    /// The boolean marks cache-owned candidates whose backoff we must check.
    /// Explicit dial targets win; plaintext and WebSocket routing stay unchanged.
    fn candidates(
        &self,
        input: &ConnectRequest,
        origin: Option<&HttpOrigin>,
        proxy_context: bool,
    ) -> (Option<Arc<HttpServiceCandidates>>, bool) {
        if !cfg!(feature = "tls")
            || input.application_protocol.as_ref() != Some(&Protocol::HTTPS)
            || dials_another_endpoint(input)
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
                // Direct-path backoff says nothing about proxy reachability.
                // Filter this fresh snapshot using route-specific backoff below.
                cache.lookup_fresh(origin)
            } else {
                cache.lookup(origin)
            }
        });
        (candidates, true)
    }

    /// Install learning before an H2 handshake can receive ALTSVC frames
    /// (RFC 7838 §4). Preserve caller observers; other pinned versions cannot use it.
    fn observe_frames(&self, input: &ConnectRequest, origin: Option<&HttpOrigin>) {
        if required_version(input).is_some_and(|version| version != Version::HTTP_2) {
            return;
        }
        if let (Some(cache), Some(origin)) = (&self.policy.cache, origin)
            && !input.extensions().contains::<AltSvcObserverExtension>()
        {
            input
                .extensions()
                .insert_arc(cache.frame_observer(origin.clone()));
        }
    }

    /// Recognize advertised HTTP protocols while preserving the caller's version.
    /// The actual connector decides support, without a second capability list.
    fn candidate_version(
        candidate: &HttpServiceCandidate,
        required: Option<Version>,
    ) -> Option<Version> {
        let version = Version::try_from(&candidate.protocol).ok()?;
        // H1/H2 HTTPS candidates share TCP: either can satisfy an explicit
        // H1/H2 requirement. H3 needs QUIC; Alt-Svc requires an exact match.
        required
            .is_none_or(|required| {
                required == version
                    || (negotiates_http_stream(candidate)
                        && matches!(required, Version::HTTP_11 | Version::HTTP_2))
            })
            .then_some(version)
    }

    /// Bound connection setup, preserving terminal address-race failures if the
    /// attempt times out. Only alternatives consume the speculative time budget;
    /// origin fallback shares the optional overall deadline.
    async fn attempt(
        &self,
        input: ConnectRequest,
        deadline: Option<Instant>,
        speculative: bool,
    ) -> Result<EstablishedClientConnection<S::Connection, ConnectRequest>, ConnectionError> {
        let state = if speculative {
            input.extensions().get_arc::<HttpServiceAttempt>()
        } else {
            None
        };
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
        // An address race may still be pending after one address rejected TLS.
        // Cancellation must not turn that rejection into an availability failure.
        let rejected = state.as_ref().and_then(|state| state.failure_kind());
        match (result, rejected) {
            (Ok(Err(error)), Some(kind))
                if availability(&error)
                    || (kind == ConnectionErrorKind::Authentication
                        && error.kind() != ConnectionErrorKind::Authentication) =>
            {
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
}

impl<S> Service<ConnectRequest> for HttpServiceConnector<S>
where
    S: ConnectorService<ConnectRequest>,
    S::Connection: ExtensionsRef,
{
    type Output = EstablishedClientConnection<S::Connection, ConnectRequest>;
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
        let required = required_version(&input);
        // No discovery: move the input directly, avoiding a fork or origin
        // allocation unless a pooled alternative needs Alt-Used bookkeeping.
        if self.policy.cache.is_none() && !input.extensions().contains::<HttpServiceCandidates>() {
            if let Some(version) = required {
                input.extensions().insert(TargetHttpVersion(version));
            }
            let established = self.attempt(input, deadline, false).await?;
            if let Some(version) = required {
                verify_version(&established.conn, version)
                    .inspect_err(|_| discard_connection(&established.conn))?;
            }
            return Ok(established);
        }
        #[cfg(feature = "tls")]
        input.extensions().insert(EchDiscoveryComplete);
        // Snapshot discovery once; freshness and route backoff are rechecked
        // before each attempt because other requests can update the shared cache.
        let origin = origin(&input);
        let route = ProxyRouteContext::for_request(input.extensions());
        let (snapshot, from_cache) = self.candidates(&input, origin.as_ref(), route.is_some());
        let mut attempts = 0;
        let fallback = snapshot.as_ref().is_none_or(|snapshot| {
            Some(snapshot.origin()) != origin.as_ref() || snapshot.allows_origin_fallback()
        });
        let mut last_error = None;

        if let (Some(origin), Some(snapshot)) = (origin.as_ref(), snapshot.as_ref())
            && snapshot.origin() == origin
        {
            for (index, candidate) in snapshot.iter().enumerate().take(self.policy.max_candidates) {
                // Reserve an origin attempt only when discovery permits one.
                if attempts
                    >= self
                        .policy
                        .max_attempts
                        .saturating_sub(usize::from(fallback))
                {
                    break;
                }
                let Some(version) = Self::candidate_version(candidate, required) else {
                    continue;
                };

                let advertisement = snapshot
                    .candidate_extensions(index)
                    .and_then(|ext| ext.get_ref::<HttpServiceSelection>())
                    .filter(|selection| {
                        selection.candidates.origin() == origin
                            && selection.candidates.get(selection.index) == Some(candidate)
                            && candidate.source == HttpServiceSource::AltSvc
                    });
                let (source_snapshot, source_index) = advertisement
                    .map_or((snapshot, index), |selection| {
                        (&selection.candidates, selection.index)
                    });
                if (from_cache || advertisement.is_some())
                    && let Some(cache) = &self.policy.cache
                    && !(if let Some(route) = &route {
                        cache.route_usable(source_snapshot, source_index, route)
                    } else {
                        cache.is_usable(source_snapshot, source_index)
                    })
                {
                    continue;
                }

                // Change the route and required protocol, never the logical
                // authority or TLS policy (RFC 7838 §§2, 2.3).
                // A certificate can only authenticate an origin named by a server name.
                let Ok(origin_server_name) = ServerName::try_from(&origin.authority().host) else {
                    continue;
                };
                let state =
                    Arc::new(HttpServiceAttempt::new().with_authenticated_peer(origin_server_name));
                let attempt = input.fork();
                attempt
                    .extensions()
                    .insert(ConnectorTarget(candidate.target.clone()));
                if let Some(extensions) = snapshot.candidate_extensions(index) {
                    attempt.extensions().extend(extensions);
                }
                // Candidate settings may refine the physical endpoint, but
                // cannot replace this attempt's observer or transport policy.
                attempt.extensions().insert_arc(state.clone());
                if negotiates_http_stream(candidate) && required.is_none() {
                    // HTTPS records select a transport, not its ALPN offer (RFC 9460 §7.1.2).
                    // Override an H3 connection default without constraining TLS negotiation.
                    attempt
                        .extensions()
                        .insert(FallbackHttpVersion(Version::HTTP_11));
                    attempt
                        .extensions()
                        .insert(ConnectorTransportProtocol(TransportProtocol::Tcp));
                } else {
                    attempt
                        .extensions()
                        .insert(TargetHttpVersion(required.unwrap_or(version)));
                }
                attempt
                    .extensions()
                    .insert(SelectedHttpService::new(origin.clone(), candidate.clone()));
                self.observe_frames(&attempt, Some(origin));
                attempts += 1;
                // Outcomes must not update availability after a network change.
                let failure_context = self
                    .policy
                    .cache
                    .as_ref()
                    .map(|cache| (cache, cache.network_epoch(), StdInstant::now()));
                // DNS-selected services (including refined Alt-Svc targets) use
                // normal connector deadlines. A short speculative timeout could
                // abandon the endpoint needed to satisfy ECH discovery policy.
                let speculative = candidate.source != HttpServiceSource::Https
                    && !snapshot
                        .candidate_extensions(index)
                        .is_some_and(|extensions| {
                            extensions.contains::<ConnectorTarget>()
                                || extensions.contains::<rama_net::tls::TargetEchConfig>()
                        });
                match self.attempt(attempt, deadline, speculative).await {
                    Ok(established) => {
                        // Pool hits carry the original connector's policy scope.
                        // Unknown custom policies never change shared backoff.
                        let shared_policy = state.policy_scope() != ConnectionPolicyScope::Request
                            && established
                                .conn
                                .extensions()
                                .get_ref::<ConnectionPolicyScope>()
                                .copied()
                                .unwrap_or_else(|| state.policy_scope())
                                == ConnectionPolicyScope::Connector;
                        let mut negotiated_candidate = candidate.clone();
                        if let Err(error) = verify_alternative(&established.conn, origin, candidate)
                            .and_then(|protocol| {
                                if let Some(version) = required {
                                    verify_version(&established.conn, version)?;
                                }
                                negotiated_candidate.protocol = protocol;
                                Ok(())
                            })
                        {
                            if error.domain() == ConnectionErrorDomain::Local
                                && error.kind() == ConnectionErrorKind::Unavailable
                            {
                                tracing::debug!(
                                    ?error,
                                    ?candidate,
                                    "pooled policy cannot serve alternative"
                                );
                                continue;
                            }
                            discard_connection(&established.conn);
                            if shared_policy
                                && candidate.source == HttpServiceSource::AltSvc
                                && let Some((cache, network, started)) = failure_context
                            {
                                if let Some(route) = &route {
                                    cache.failed_route(
                                        source_snapshot,
                                        source_index,
                                        network,
                                        started,
                                        route,
                                    );
                                } else {
                                    cache.failed_attempt(
                                        source_snapshot,
                                        source_index,
                                        network,
                                        started,
                                        true,
                                    );
                                }
                            }
                            tracing::debug!(
                                ?error,
                                ?candidate,
                                "alternative validation failed; trying next service"
                            );
                            last_error = Some(error);
                            continue;
                        }
                        // A pool hit must describe this same service. Insert
                        // provenance only once; Extensions are append-only.
                        let extensions = established.conn.extensions();
                        if let Some(current) = extensions.get_ref::<EstablishedHttpService>() {
                            // Verified configured origins may coalesce; Alt-Svc ones never do.
                            let coalesced = current.candidate.source
                                == HttpServiceSource::Configured
                                && candidate.source == HttpServiceSource::Configured
                                && authenticates_alias(&established.conn, origin);
                            if (current.origin != *origin && !coalesced)
                                || current.candidate.protocol != negotiated_candidate.protocol
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
                                negotiated_candidate,
                            ));
                        }
                        established.input.extensions().insert(HttpServiceSelection {
                            candidates: source_snapshot.clone(),
                            index: source_index,
                            route: route.clone(),
                        });
                        return Ok(established);
                    }
                    Err(error)
                        if error.domain() == ConnectionErrorDomain::Local
                            && error.kind() == ConnectionErrorKind::Unavailable =>
                    {
                        // An unsupported protocol or route has not consumed a
                        // network attempt and says nothing about endpoint health.
                        attempts -= 1;
                        tracing::debug!(
                            ?error,
                            ?candidate,
                            "connector cannot reach this service; trying next service"
                        );
                    }
                    Err(error) => {
                        // The origin keeps exactly the same request TLS policy.
                        // Failure of a speculative endpoint does not authorize a
                        // weaker connection, nor dispatch or replay a request.
                        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                            return Err(error);
                        }
                        if error.domain() != ConnectionErrorDomain::Local
                            && state.policy_scope() != ConnectionPolicyScope::Request
                            && (state.policy_scope() == ConnectionPolicyScope::Connector
                                || availability(&error))
                            && candidate.source == HttpServiceSource::AltSvc
                            && let Some((cache, network, started)) = failure_context
                        {
                            if let Some(route) = &route {
                                cache.failed_route(
                                    source_snapshot,
                                    source_index,
                                    network,
                                    started,
                                    route,
                                );
                            } else {
                                cache.failed_attempt(
                                    source_snapshot,
                                    source_index,
                                    network,
                                    started,
                                    !availability(&error),
                                );
                            }
                        }
                        tracing::debug!(
                            ?error,
                            ?candidate,
                            "HTTP alternative failed; trying next service"
                        );
                        last_error = Some(error);
                    }
                }
            }
        }

        if !fallback {
            return Err(last_error.unwrap_or_else(|| {
                invalid("HTTP discovery requires an advertised service but none is usable")
            }));
        }

        // Alternatives were absent, filtered out, or failed. Try the original
        // endpoint with the original policy, preserving any explicit version.
        let attempt = input;
        if let Some(version) = required {
            attempt.extensions().insert(TargetHttpVersion(version));
        }
        self.observe_frames(&attempt, origin.as_ref());
        let established = self.attempt(attempt, deadline, false).await?;
        if let Some(version) = required {
            verify_version(&established.conn, version)
                .inspect_err(|_| discard_connection(&established.conn))?;
        }
        Ok(established)
    }
}

#[cfg(test)]
mod tests;
