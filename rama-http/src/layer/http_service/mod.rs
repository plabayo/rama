//! Select an HTTP service before establishing a connection.
//!
//! Place this connector outside proxy-route selection and connection pools. Each
//! candidate receives an isolated connection request; the logical origin remains
//! unchanged while `ConnectorTarget` selects the endpoint to reach through the
//! configured route. No HTTP request body enters this selection loop.
//!
//! Automatic alternative discovery currently applies to HTTPS origins. Plain
//! HTTP advertisements can be cached, but using them requires the separate
//! opportunistic-security authorization described by RFC 8164. Setting
//! `RequireTls` alone does not provide that authorization.

use crate::layer::alt_svc::{AltSvc, AltSvcCache, AltSvcLayer};
use rama_core::{
    Fork as _, Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
};
use rama_http_types::{
    Version,
    conn::{
        EstablishedHttpService, HttpOrigin, HttpServiceCandidate, HttpServiceCandidates,
        HttpServiceSource, SelectedHttpService,
    },
};
use rama_net::{
    Protocol,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorDomain, ConnectionErrorKind,
        ConnectorService, ConnectorTarget, EstablishedClientConnection,
    },
    http::{HttpRequestVersion, TargetHttpVersion},
    tls::{ApplicationProtocol, RequireTls},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

mod input;
use self::input::GeneratedServiceInput;

/// Preserve a terminal failure observed by an address race across cancellation.
///
/// A transport calls [`Self::reject`] after an authentication, protocol or policy
/// failure. An outer timeout then cannot disguise that failure as unavailability
/// and cause fallback to another service.
#[derive(Clone, Debug, Default, rama_core::extensions::Extension)]
pub struct HttpServiceAttempt(Arc<AtomicBool>);

// A returned connection input may be reused by a redirect/retry layer. Cached
// snapshots remain observable there but must be refreshed on the next selection.
#[derive(Clone, Debug, rama_core::extensions::Extension)]
struct CachedServiceCandidates(HttpServiceCandidates);

impl HttpServiceAttempt {
    pub fn reject(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn failed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// HTTP service discovery and bounded connection-selection policy.
#[derive(Clone, Debug)]
pub struct HttpServiceLayer {
    cache: Option<AltSvcCache>,
    protocols: Arc<[ApplicationProtocol]>,
    preferred_protocol: Option<ApplicationProtocol>,
    required_protocol: Option<ApplicationProtocol>,
    attempt_timeout: Duration,
    timeout: Duration,
    max_attempts: usize,
}

impl Default for HttpServiceLayer {
    fn default() -> Self {
        Self {
            cache: None,
            protocols: Arc::from([]),
            preferred_protocol: None,
            required_protocol: None,
            attempt_timeout: Duration::from_millis(300),
            timeout: Duration::from_secs(30),
            max_attempts: 8,
        }
    }
}

impl HttpServiceLayer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Share an Alt-Svc cache. `None` disables learning and cached discovery.
        pub fn cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.cache = cache;
            self
        }
    }

    /// Declare exactly which advertised protocols the inner connector supports.
    #[must_use]
    pub fn with_protocols(
        mut self,
        protocols: impl IntoIterator<Item = ApplicationProtocol>,
    ) -> Self {
        self.set_protocols(protocols);
        self
    }

    pub fn set_protocols(
        &mut self,
        protocols: impl IntoIterator<Item = ApplicationProtocol>,
    ) -> &mut Self {
        self.protocols = protocols.into_iter().collect();
        self
    }

    rama_utils::macros::generate_set_and_with! {
        /// Attempt this protocol at the origin after advertised alternatives.
        /// Availability failures may fall back to ordinary origin establishment.
        pub fn preferred_protocol(mut self, protocol: Option<ApplicationProtocol>) -> Self {
            self.preferred_protocol = protocol;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Require this protocol, including when no advertisement is available.
        /// Conflicting per-request requirements are rejected before connecting.
        pub fn required_protocol(mut self, protocol: Option<ApplicationProtocol>) -> Self {
            self.required_protocol = protocol;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound one speculative alternative or preferred-origin attempt.
        pub fn attempt_timeout(mut self, timeout: Duration) -> Self {
            self.attempt_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound the entire connection-selection operation, including fallback.
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
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

macro_rules! connector_option {
    ($set:ident, $with:ident, $policy_set:ident, $ty:ty, $doc:literal) => {
        #[doc = $doc]
        #[must_use]
        pub fn $with(mut self, value: $ty) -> Self {
            self.policy.$policy_set(value);
            self
        }

        #[doc = $doc]
        pub fn $set(&mut self, value: $ty) -> &mut Self {
            self.policy.$policy_set(value);
            self
        }
    };
}

impl<S> HttpServiceConnector<S> {
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            policy: HttpServiceLayer::default(),
        }
    }

    rama_utils::macros::define_inner_service_accessors!();

    /// Set the shared advertisement cache; `None` disables cached discovery and learning.
    #[must_use]
    pub fn with_cache(mut self, cache: impl Into<Option<AltSvcCache>>) -> Self {
        self.set_cache(cache);
        self
    }

    pub fn set_cache(&mut self, cache: impl Into<Option<AltSvcCache>>) -> &mut Self {
        self.policy.maybe_set_cache(cache.into());
        self
    }

    #[must_use]
    pub fn without_cache(mut self) -> Self {
        self.policy.maybe_set_cache(None);
        self
    }
    connector_option!(
        set_preferred_protocol,
        with_preferred_protocol,
        maybe_set_preferred_protocol,
        Option<ApplicationProtocol>,
        "Attempt this protocol at the origin before ordinary fallback."
    );
    connector_option!(
        set_required_protocol,
        with_required_protocol,
        maybe_set_required_protocol,
        Option<ApplicationProtocol>,
        "Require this protocol, without silently falling back to another one."
    );
    connector_option!(
        set_attempt_timeout,
        with_attempt_timeout,
        set_attempt_timeout,
        Duration,
        "Bound a speculative connection attempt."
    );
    connector_option!(
        set_timeout,
        with_timeout,
        set_timeout,
        Duration,
        "Bound the complete selection operation."
    );
    connector_option!(
        set_max_attempts,
        with_max_attempts,
        set_max_attempts,
        usize,
        "Bound attempts, including the reserved origin fallback attempt."
    );

    #[must_use]
    pub fn with_protocols(
        mut self,
        protocols: impl IntoIterator<Item = ApplicationProtocol>,
    ) -> Self {
        self.policy.set_protocols(protocols);
        self
    }

    pub fn set_protocols(
        &mut self,
        protocols: impl IntoIterator<Item = ApplicationProtocol>,
    ) -> &mut Self {
        self.policy.set_protocols(protocols);
        self
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
fn authenticates<C: ExtensionsRef>(connection: &C, origin: &HttpOrigin) -> bool {
    connection
        .extensions()
        .get_ref::<rama_tls::client::TlsServerAuthentication>()
        .and_then(|identity| identity.0.as_ref())
        .is_some_and(|identity| identity.clone().canonicalize() == origin.authority().host)
}

#[cfg(not(feature = "tls"))]
fn authenticates<C: ExtensionsRef>(_connection: &C, _origin: &HttpOrigin) -> bool {
    false
}

fn discard_connection(connection: &impl ExtensionsRef) {
    if let Some(health) = connection
        .extensions()
        .get_ref::<rama_net::conn::ConnectionHealthWatcher>()
    {
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
        .get_ref::<rama_tls::client::NegotiatedTlsParameters>()
        .and_then(|parameters| parameters.application_layer_protocol.as_ref())
        != Some(candidate.protocol())
    {
        return Err(ConnectionError::application(
            BoxError::from_static_str(
                "alternative service did not negotiate its advertised protocol",
            ),
            ConnectionErrorKind::Protocol,
        ));
    }
    let expected = Version::try_from(candidate.protocol()).map_err(|error| {
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
    async fn attempt(
        &self,
        input: ConnectRequest,
        deadline: Instant,
        speculative: bool,
    ) -> Result<EstablishedClientConnection<S::Connection, ConnectRequest>, ConnectionError> {
        let state = speculative.then(HttpServiceAttempt::default);
        if let Some(state) = &state {
            input.extensions().insert(state.clone());
        }
        let attempt_deadline = if speculative {
            Instant::now()
                .checked_add(self.policy.attempt_timeout)
                .unwrap_or(deadline)
                .min(deadline)
        } else {
            deadline
        };
        if Instant::now() >= attempt_deadline {
            let error = BoxError::from_static_str("HTTP service connection budget exhausted");
            return Err(if attempt_deadline == deadline {
                ConnectionError::local(error, ConnectionErrorKind::Timeout)
            } else {
                ConnectionError::transport(error, ConnectionErrorKind::Timeout)
            });
        }
        match tokio::time::timeout_at(attempt_deadline, self.inner.connect(input)).await {
            Ok(Err(error))
                if state.as_ref().is_some_and(HttpServiceAttempt::failed)
                    && availability(&error) =>
            {
                Err(
                    ConnectionError::application(error, ConnectionErrorKind::Authentication)
                        .context("terminal failure during service address race"),
                )
            }
            Ok(result) => result,
            Err(_) if state.as_ref().is_some_and(HttpServiceAttempt::failed) => {
                Err(ConnectionError::application(
                    BoxError::from_static_str(
                        "terminal connection failure preceded service attempt timeout",
                    ),
                    ConnectionErrorKind::Authentication,
                ))
            }
            Err(error) if attempt_deadline == deadline => {
                Err(ConnectionError::local(error, ConnectionErrorKind::Timeout)
                    .context("HTTP service selection deadline"))
            }
            Err(error) => Err(
                ConnectionError::transport(error, ConnectionErrorKind::Timeout)
                    .context("HTTP service candidate deadline"),
            ),
        }
    }

    fn wrap(
        &self,
        established: EstablishedClientConnection<S::Connection, ConnectRequest>,
        origin: Option<HttpOrigin>,
        selection: Option<(HttpServiceCandidates, usize)>,
        original: Option<&ConnectRequest>,
    ) -> EstablishedClientConnection<AltSvc<S::Connection>, ConnectRequest> {
        let EstablishedClientConnection { conn, input } = established;
        if let Some(original) = original {
            GeneratedServiceInput::capture(original.extensions(), input.extensions());
        }
        let conn = match origin {
            Some(origin) => {
                let authenticated = authenticates(&conn, &origin);
                let established_alternative = conn
                    .extensions()
                    .get_ref::<EstablishedHttpService>()
                    .filter(|service| {
                        service.origin() == &origin
                            && service.candidate().source() == HttpServiceSource::AltSvc
                    })
                    .map(|service| service.candidate().target().clone());
                let mut layer = AltSvcLayer::new(self.policy.cache.clone(), origin)
                    .with_authenticated(authenticated)
                    .with_alternative(established_alternative);
                if let Some((snapshot, index)) = selection
                    && snapshot
                        .get(index)
                        .is_some_and(|candidate| candidate.source() == HttpServiceSource::AltSvc)
                {
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

    async fn serve(&self, mut input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        GeneratedServiceInput::restore(&mut input);
        if self.policy.max_attempts == 0 {
            return Err(invalid(
                "HTTP service selection requires at least one attempt",
            ));
        }
        let deadline = Instant::now()
            .checked_add(self.policy.timeout)
            .ok_or_else(|| invalid("HTTP service timeout is too large"))?;
        let origin = origin(&input);
        let required = required_version(&input);
        let configured = self
            .policy
            .required_protocol
            .as_ref()
            .map(Version::try_from)
            .transpose()
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("required protocol is not HTTP")
            })?;
        if required
            .zip(configured)
            .is_some_and(|(request, config)| request != config)
        {
            return Err(invalid(
                "request HTTP version conflicts with required service protocol",
            ));
        }
        let required = required.or(configured);
        let proxy_context = input
            .extensions()
            .contains::<rama_net::client::ProxyRoutes>()
            || input
                .extensions()
                .get_ref::<rama_net::client::ProxyRoute>()
                .is_some_and(|route| route.proxy_address().is_some());
        let discovery = input.application_protocol.as_ref() == Some(&Protocol::HTTPS)
            && !input.extensions().contains::<ConnectorTarget>();
        let injected = input
            .extensions()
            .get_ref::<HttpServiceCandidates>()
            .filter(|snapshot| Some(snapshot.origin()) == origin.as_ref())
            .filter(|snapshot| {
                !input
                    .extensions()
                    .get_ref::<CachedServiceCandidates>()
                    .is_some_and(|cached| cached.0.same_advertisement(snapshot))
            })
            .cloned();
        let from_cache = injected.is_none();
        let snapshot = discovery
            .then(|| {
                injected.or_else(|| {
                    origin.as_ref().and_then(|origin| {
                        let cache = self.policy.cache.as_ref()?;
                        if proxy_context {
                            cache.lookup_fresh(origin)
                        } else {
                            cache.lookup(origin)
                        }
                    })
                })
            })
            .flatten();
        let mut attempts = 0;

        if cfg!(feature = "tls")
            && let (Some(origin), Some(snapshot)) = (origin.as_ref(), snapshot.as_ref())
            && snapshot.origin() == origin
        {
            for (index, candidate) in snapshot.iter().enumerate() {
                if attempts >= self.policy.max_attempts.saturating_sub(1) {
                    break;
                }
                let Ok(version) = Version::try_from(candidate.protocol()) else {
                    continue;
                };
                if !self.policy.protocols.contains(candidate.protocol())
                    || required.is_some_and(|required| required != version)
                    || (from_cache
                        && self.policy.cache.as_ref().is_some_and(|cache| {
                            if proxy_context {
                                !cache.is_fresh(snapshot, index)
                            } else {
                                !cache.is_usable(snapshot, index)
                            }
                        }))
                {
                    continue;
                }
                let attempt = input.fork();
                attempt.extensions().insert(snapshot.clone());
                if from_cache {
                    attempt
                        .extensions()
                        .insert(CachedServiceCandidates(snapshot.clone()));
                }
                attempt
                    .extensions()
                    .insert(ConnectorTarget(candidate.target().clone()));
                attempt.extensions().insert(TargetHttpVersion(version));
                attempt.extensions().insert(RequireTls);
                attempt
                    .extensions()
                    .insert(SelectedHttpService::new(origin.clone(), candidate.clone()));
                attempts += 1;
                match self.attempt(attempt, deadline, true).await {
                    Ok(established) => {
                        verify_alternative(&established.conn, origin, candidate)
                            .inspect_err(|_| discard_connection(&established.conn))?;
                        established
                            .conn
                            .extensions()
                            .insert(EstablishedHttpService::new(
                                origin.clone(),
                                candidate.clone(),
                            ));
                        return Ok(self.wrap(
                            established,
                            Some(origin.clone()),
                            Some((snapshot.clone(), index)),
                            Some(&input),
                        ));
                    }
                    Err(error) if availability(&error) => {
                        if !proxy_context
                            && candidate.source() == HttpServiceSource::AltSvc
                            && let Some(cache) = &self.policy.cache
                        {
                            cache.failed(snapshot, index);
                        }
                        rama_core::telemetry::tracing::debug!(
                            ?error,
                            ?candidate,
                            "HTTP alternative unavailable; trying next service"
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        if discovery
            && required.is_none()
            && attempts < self.policy.max_attempts.saturating_sub(1)
            && let Some(protocol) = &self.policy.preferred_protocol
            && self.policy.protocols.contains(protocol)
        {
            let version = Version::try_from(protocol).map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("preferred protocol is not HTTP")
            })?;
            let attempt = input.fork();
            if let Some(snapshot) = &snapshot {
                attempt.extensions().insert(snapshot.clone());
            }
            if from_cache && let Some(snapshot) = &snapshot {
                attempt
                    .extensions()
                    .insert(CachedServiceCandidates(snapshot.clone()));
            }
            attempt.extensions().insert(TargetHttpVersion(version));
            attempt.extensions().insert(RequireTls);
            match self.attempt(attempt, deadline, true).await {
                Ok(established) => {
                    verify_version(&established.conn, version)
                        .inspect_err(|_| discard_connection(&established.conn))?;
                    return Ok(self.wrap(established, origin, None, Some(&input)));
                }
                Err(error) if availability(&error) => {}
                Err(error) => return Err(error),
            }
        }

        let attempt = input.fork();
        if let Some(snapshot) = &snapshot {
            attempt.extensions().insert(snapshot.clone());
        }
        if from_cache && let Some(snapshot) = &snapshot {
            attempt
                .extensions()
                .insert(CachedServiceCandidates(snapshot.clone()));
        }
        if let Some(version) = required {
            attempt.extensions().insert(TargetHttpVersion(version));
        }
        let established = self.attempt(attempt, deadline, false).await?;
        if let Some(version) = required {
            verify_version(&established.conn, version)
                .inspect_err(|_| discard_connection(&established.conn))?;
        }
        Ok(self.wrap(established, origin, None, None))
    }
}

#[cfg(test)]
mod tests;
