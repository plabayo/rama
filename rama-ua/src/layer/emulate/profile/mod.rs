use std::sync::Arc;

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::{Extension, Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_http::{
    HeaderMap, HeaderName, HeaderValue, Request, Version,
    conn::TargetHttpVersion,
    header::USER_AGENT,
    proto::h3::qpack::{FieldSectionBase, encoding::HeaderPreferences},
};
use rama_net::{
    ProtocolInputExt as _, TargetHttpVersionInputExt as _,
    tls::{ApplicationProtocol, TlsAlpn, default_tls_alpn},
};
use rama_utils::macros::define_inner_service_accessors;
use rand::RngExt as _;

use crate::{
    UserAgent,
    profile::{
        model::{
            identity::{ConnectionContext, FetchContext, FlowKey},
            runtime_hints::RequestInitiator,
        },
        replay::{
            connection::PreparedConnectionComponents,
            request::{
                LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport,
            },
        },
        selection::{
            DrawKey, ProfileSeed,
            capabilities::{CapabilitySet, SelectionTransport},
            database::UserAgentDatabase,
            variants::{
                ConnectionSelection, EmulationContext, ProfileSelector, SelectionRequest,
                VariantPins, bootstrap::ConnectionBootstrapRequest,
            },
        },
    },
};

use super::{
    SelectedUserAgentProfile,
    source::{ProfileSelectFallback, ProfileSource, is_no_match},
};

const MAXIMUM_FETCH_CONTEXT_BYTES: usize = rama_utils::octets::kib(16);

/// Select a captured profile and publish its immutable emulation context.
///
/// Requests without an explicit [`RequestInitiator`] select a top-level
/// navigation flow. Missing `Sec-Fetch-*` headers do not constrain selection;
/// the chosen captured navigation supplies its profile-owned Fetch metadata.
///
/// The selected identity follows the configured [`ProfileSelector`], completed by a
/// [`UserAgent`] request extension or, with auto-detection, the request's own
/// `User-Agent` header.
#[derive(Debug, Clone)]
pub struct ProfileEmulateLayer<P = Arc<UserAgentDatabase>> {
    source: P,
    config: EmulateConfig,
}

#[derive(Debug, Clone, Default)]
struct EmulateConfig {
    selector: ProfileSelector,
    seed: Option<ProfileSeed>,
    connection_key: Option<DrawKey>,
    request_key: Option<DrawKey>,
    pins: VariantPins,
    optional: bool,
    try_auto_detect_user_agent: bool,
    select_fallback: ProfileSelectFallback,
    input_header_order: Option<HeaderName>,
}

impl<P> ProfileEmulateLayer<P> {
    #[must_use]
    pub fn new(source: P) -> Self {
        Self {
            source,
            config: EmulateConfig::default(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Restrict captured profile selection.
        pub fn selector(mut self, selector: ProfileSelector) -> Self {
            self.config.selector = selector;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Fix the profile seed for reproducible selection.
        pub fn seed(mut self, seed: Option<ProfileSeed>) -> Self {
            self.config.seed = seed;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Fix the logical connection draw key.
        pub fn connection_key(mut self, key: Option<DrawKey>) -> Self {
            self.config.connection_key = key;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Fix the logical request draw key.
        pub fn request_key(mut self, key: Option<DrawKey>) -> Self {
            self.config.request_key = key;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Pin stored connection and request variants.
        pub fn pins(mut self, pins: VariantPins) -> Self {
            self.config.pins = pins;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Pass requests through unchanged, with a debug trace, when they cannot be
        /// emulated instead of failing them.
        pub fn is_optional(mut self, optional: bool) -> Self {
            self.config.optional = optional;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Derive the [`UserAgent`] from the request's `User-Agent` header when no
        /// [`UserAgent`] extension is present, so a client is emulated as itself.
        pub fn try_auto_detect_user_agent(mut self, detect: bool) -> Self {
            self.config.try_auto_detect_user_agent = detect;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Choose how to relax the selector when no profile matches it.
        pub fn select_fallback(mut self, fallback: ProfileSelectFallback) -> Self {
            self.config.select_fallback = fallback;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Name a request header holding a comma-separated list of header names.
        ///
        /// Caller headers the profile does not own are emitted in that order, ahead
        /// of other caller headers. The header itself is removed from the request.
        pub fn input_header_order(mut self, name: Option<HeaderName>) -> Self {
            self.config.input_header_order = name;
            self
        }
    }
}

impl<S, P: Clone> Layer<S> for ProfileEmulateLayer<P> {
    type Service = ProfileEmulateService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        ProfileEmulateService {
            inner,
            source: self.source.clone(),
            config: self.config.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProfileEmulateService {
            inner,
            source: self.source,
            config: self.config,
        }
    }
}

/// Request service produced by [`ProfileEmulateLayer`].
#[derive(Debug, Clone)]
pub struct ProfileEmulateService<S, P = Arc<UserAgentDatabase>> {
    inner: S,
    source: P,
    config: EmulateConfig,
}

impl<S, P> ProfileEmulateService<S, P> {
    define_inner_service_accessors!();
}

impl<S, P, Body> Service<Request<Body>> for ProfileEmulateService<S, P>
where
    S: Service<Request<Body>, Error: Into<BoxError>>,
    P: ProfileSource,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Output, Self::Error> {
        if self.config.try_auto_detect_user_agent && !req.extensions().contains::<UserAgent>() {
            if let Some(header) = req
                .headers()
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
            {
                let agent = UserAgent::new(header.to_owned());
                tracing::trace!(user_agent.original = %header, "user agent auto-detected from request");
                req.extensions().insert(agent);
            } else {
                tracing::debug!(
                    "user agent auto-detection not possible: no usable user agent header"
                );
            }
        }
        if let Some(name) = &self.config.input_header_order
            && let Some(value) = req.headers_mut().remove(name)
        {
            match parse_header_order(&value) {
                Ok(order) => {
                    req.extensions().insert(InputHeaderOrder(order));
                }
                Err(error) => {
                    tracing::debug!("ignore invalid input header order: {error}");
                }
            }
        }
        match self.select(&req) {
            Ok(()) => {
                if self.config.optional {
                    req.extensions().insert(OptionalEmulation);
                }
            }
            Err(error) if self.config.optional => {
                tracing::debug!("profile emulation skipped, request passed through: {error}");
            }
            Err(error) => return Err(error),
        }
        self.inner.serve(req).await.into_box_error()
    }
}

impl<S, P: ProfileSource> ProfileEmulateService<S, P> {
    fn select<Body>(&self, req: &Request<Body>) -> Result<(), BoxError> {
        let config = &self.config;
        let required = required_capabilities(req).map_err(BoxError::from)?;
        let connection = req
            .extensions()
            .get_ref::<ConnectionContext>()
            .cloned()
            .unwrap_or_default();
        let flow = request_flow(
            req,
            req.target_http_version().unwrap_or(req.version()),
            connection,
        )?;
        let seed = config.seed.unwrap_or_else(random_seed);
        let connection_key = config.connection_key.unwrap_or_else(random_draw_key);
        let request_key = config.request_key.unwrap_or_else(random_draw_key);
        let mut request = SelectionRequest {
            client: effective_selector(&config.selector, req.extensions().get_ref::<UserAgent>()),
            required,
            flow,
            pins: req
                .extensions()
                .get_ref::<VariantPins>()
                .copied()
                .unwrap_or(config.pins),
        };
        let fallback = req
            .extensions()
            .get_ref::<ProfileSelectFallback>()
            .copied()
            .unwrap_or(config.select_fallback);
        let mut selected = self.source.select_profile(&request, seed, connection_key);
        for relaxed in fallback.relaxations(&request.client) {
            match &selected {
                Err(error) if is_no_match(error) => {
                    tracing::debug!(
                        ?relaxed,
                        "no captured profile matches the selector, retry with fallback: {error}"
                    );
                }
                _ => break,
            }
            request.client = relaxed;
            selected = self.source.select_profile(&request, seed, connection_key);
        }
        let selected = selected?;
        let selected = Arc::new(
            if req.extensions().contains::<ConnectionBootstrapRequest>() {
                selected.for_connection_bootstrap(seed, connection_key)?
            } else {
                selected
            },
        );
        tracing::debug!(
            user_agent.kind = ?selected.profile().ua_kind,
            user_agent.version = ?selected.profile().ua_version,
            user_agent.platform = ?selected.profile().platform,
            "captured profile selected for emulation"
        );
        req.extensions()
            .insert(SelectedUserAgentProfile::from(selected.profile()));
        selected
            .emulation_context(seed, connection_key, request_key)
            .publish(req.extensions());
        Ok(())
    }
}

/// Caller header names to emit first, in this order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(ua, http))]
struct InputHeaderOrder(Box<[HeaderName]>);

/// The caller opted to pass requests through when they cannot be emulated.
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(ua))]
struct OptionalEmulation;

fn parse_header_order(value: &HeaderValue) -> Result<Box<[HeaderName]>, BoxError> {
    value
        .to_str()
        .context("interpret input header order as utf-8")?
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            HeaderName::from_bytes(name.as_bytes()).map_err(|_error| {
                BoxError::from_static_str("invalid header name in input header order")
                    .context_field("name", name.to_owned())
            })
        })
        .collect()
}

/// Caller headers ordered as requested; unlisted ones keep their relative order after them.
fn ordered_headers(headers: &HeaderMap, order: Option<&InputHeaderOrder>) -> HeaderMap {
    let Some(InputHeaderOrder(order)) = order else {
        return headers.clone();
    };
    let mut remaining = headers.clone().into_ordered_iter().collect::<Vec<_>>();
    let mut output = HeaderMap::with_capacity(remaining.len());
    for name in order {
        remaining.retain(|(header, value)| {
            if header == name {
                output.append(header.clone(), value.clone());
                false
            } else {
                true
            }
        });
    }
    for (name, value) in remaining {
        output.append(name, value);
    }
    output
}

/// Draw the request variant after the pooled connection and protocol are known.
///
/// HTTP/3 field choices follow the emitted occurrences, including rebuilt cookies.
/// Explicit caller QPACK preferences take precedence and are reported as differences.
#[derive(Debug, Clone)]
pub struct ProfileEmulateHttpRequestModifier<S> {
    inner: S,
}

impl<S> ProfileEmulateHttpRequestModifier<S> {
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, Body> Service<Request<Body>> for ProfileEmulateHttpRequestModifier<S>
where
    S: Service<Request<Body>, Error: Into<BoxError>> + ExtensionsRef,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Output, Self::Error> {
        emulate_request(Some(self.inner.extensions()), &mut req)?;
        self.inner.serve(req).await.into_box_error()
    }
}

/// [`ProfileEmulateHttpRequestModifier`] for requests relayed on a connection that the
/// profile connector did not open, such as a MITM proxy's egress connection.
///
/// Each request replays against a drawn connection variant; this is reported as
/// [`LoweredProfileItem::UnemulatedConnection`].
#[derive(Debug, Clone)]
pub struct ProfileEmulateRelayRequestModifier<S> {
    inner: S,
}

impl<S> ProfileEmulateRelayRequestModifier<S> {
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, Body> Service<Request<Body>> for ProfileEmulateRelayRequestModifier<S>
where
    S: Service<Request<Body>, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Output, Self::Error> {
        emulate_request(None, &mut req)?;
        self.inner.serve(req).await.into_box_error()
    }
}

/// Layer for [`ProfileEmulateRelayRequestModifier`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileEmulateRelayRequestModifierLayer;

impl<S> Layer<S> for ProfileEmulateRelayRequestModifierLayer {
    type Service = ProfileEmulateRelayRequestModifier<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProfileEmulateRelayRequestModifier::new(inner)
    }
}

/// Replay the selected request variant unless no context was published; optional
/// emulation passes the request through unchanged when replay fails.
fn emulate_request<Body>(
    connection: Option<&Extensions>,
    req: &mut Request<Body>,
) -> Result<(), BoxError> {
    let Some(context) = EmulationContext::of(req.extensions()).cloned() else {
        return Ok(());
    };
    match replay_request(connection, &context, req) {
        Ok(()) => Ok(()),
        Err(error) if req.extensions().contains::<OptionalEmulation>() => {
            tracing::debug!("profile request emulation skipped, request passed through: {error}");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Every fallible step runs before the request is modified.
fn replay_request<Body>(
    connection_extensions: Option<&Extensions>,
    context: &EmulationContext,
    req: &mut Request<Body>,
) -> Result<(), BoxError> {
    let drawn;
    let found = connection_extensions
        .and_then(|extensions| extensions.get_ref::<ConnectionSelection>())
        .or_else(|| req.extensions().get_ref::<ConnectionSelection>());
    let unemulated_connection = found.is_none();
    let connection = if let Some(connection) = found {
        connection
    } else {
        // Relayed or offline requests have no profile connection: draw the variant to replay.
        drawn = context.selected.connection(
            &req.extensions()
                .get_ref::<ConnectionContext>()
                .cloned()
                .unwrap_or_default(),
            context.seed,
            context.connection_key,
        )?;
        &drawn
    };
    let version = connection_extensions
        .and_then(|extensions| extensions.get_ref::<TargetHttpVersion>())
        .map(|target| target.0)
        .unwrap_or(req.version());
    let flow = request_flow(
        req,
        version,
        connection.effective.context.connection.clone(),
    )?;
    let original = ordered_headers(
        req.headers(),
        req.extensions().get_ref::<InputHeaderOrder>(),
    );
    let selected = context.selected.request(
        connection,
        &flow,
        &original,
        context.seed,
        context.request_key,
    )?;
    let prepared = req.extensions().get_ref::<PreparedConnectionComponents>();
    let initial = prepared.and_then(|prepared| {
        prepared
            .h3_bootstrap
            .as_ref()
            .zip(prepared.h3_sequence.as_ref())
            .filter(|(_, sequence)| !sequence.encoder_instructions.is_empty())
    });
    let replayed = match initial {
        Some((bootstrap, sequence)) => {
            selected.replay_initial_request(&original, bootstrap, sequence)?
        }
        None => selected.replay_request(&original)?,
    };
    let mut report = connection_extensions
        .and_then(|extensions| extensions.get_ref::<ProfilePreservationReport>())
        .or_else(|| req.extensions().get_ref::<ProfilePreservationReport>())
        .cloned()
        .unwrap_or_default()
        .followed_by(replayed.report);
    if unemulated_connection {
        report.push(ProfilePreservationDifference::LoweredProfileItem {
            item: LoweredProfileItem::UnemulatedConnection,
        });
    }
    // Explicit caller QPACK choices take precedence and are reported.
    if let Some(base) = replayed.qpack_base {
        if req
            .extensions()
            .get_ref::<FieldSectionBase>()
            .is_some_and(|caller| *caller != base)
        {
            report.push(ProfilePreservationDifference::LoweredProfileItem {
                item: LoweredProfileItem::CallerQpackBase,
            });
        } else {
            req.extensions().insert(base);
        }
    }
    if let Some(preferences) = replayed.qpack_headers {
        if req
            .extensions()
            .get_ref::<HeaderPreferences>()
            .is_some_and(|caller| {
                caller.headers != preferences.headers
                    || caller.pseudo_headers != preferences.pseudo_headers
            })
        {
            report.push(ProfilePreservationDifference::LoweredProfileItem {
                item: LoweredProfileItem::CallerQpackFieldPreferences,
            });
        } else {
            req.extensions().insert(preferences);
        }
    }
    if let Some(headers) = replayed.headers {
        *req.headers_mut() = headers;
    }
    if let Some(pseudo_headers) = replayed.pseudo_headers {
        req.extensions().insert(pseudo_headers);
    }
    req.extensions().insert(report);
    req.extensions().insert(selected);
    Ok(())
}

/// Layer for [`ProfileEmulateHttpRequestModifier`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileEmulateHttpRequestModifierLayer;

impl<S> Layer<S> for ProfileEmulateHttpRequestModifierLayer {
    type Service = ProfileEmulateHttpRequestModifier<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProfileEmulateHttpRequestModifier::new(inner)
    }
}

fn effective_selector(selector: &ProfileSelector, agent: Option<&UserAgent>) -> ProfileSelector {
    let mut selector = selector.clone();
    if let Some(agent) = agent {
        selector.client.get_or_insert_with(|| {
            agent
                .ua_kind()
                .map_or(agent.header_str(), |kind| kind.as_str())
                .into()
        });
        selector.platform = selector.platform.or_else(|| agent.platform());
        selector.device = selector.device.or_else(|| agent.device());
    }
    selector
}

fn request_flow<Body>(
    req: &Request<Body>,
    version: Version,
    connection: ConnectionContext,
) -> Result<FlowKey, BoxError> {
    Ok(FlowKey::Http {
        version,
        method: req.method().clone(),
        initiator: req.extensions().get_ref::<RequestInitiator>().copied(),
        fetch: FetchContext::from_headers(req.headers(), MAXIMUM_FETCH_CONTEXT_BYTES)?,
        connection,
    })
}

fn required_capabilities<Body>(
    req: &Request<Body>,
) -> Result<CapabilitySet, crate::profile::selection::variants::SelectionError> {
    let explicit = req
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .map(|target| target.0);
    let version = explicit.unwrap_or(req.version());
    let configured = req.extensions().get_ref::<TlsAlpn>().cloned();
    if version == Version::HTTP_3 {
        let alpn = configured.unwrap_or_else(|| alpn_for_version(version));
        return CapabilitySet::for_alpn(&alpn, SelectionTransport::Quic);
    }
    if req
        .target_protocol()
        .is_some_and(|protocol| protocol.is_secure())
    {
        let alpn = configured
            .or_else(|| explicit.map(alpn_for_version))
            .or_else(|| req.target_protocol().and_then(default_tls_alpn))
            .unwrap_or_else(|| alpn_for_version(version));
        CapabilitySet::for_alpn(&alpn, SelectionTransport::TcpTls)
    } else {
        CapabilitySet::for_alpn(&alpn_for_version(version), SelectionTransport::TcpPlain)
    }
}

fn alpn_for_version(version: Version) -> TlsAlpn {
    let protocol = match version {
        Version::HTTP_09 => ApplicationProtocol::HTTP_09,
        Version::HTTP_10 => ApplicationProtocol::HTTP_10,
        Version::HTTP_11 => ApplicationProtocol::HTTP_11,
        Version::HTTP_2 => ApplicationProtocol::HTTP_2,
        Version::HTTP_3 => ApplicationProtocol::HTTP_3,
    };
    TlsAlpn([protocol].into_iter().collect())
}

fn random_seed() -> ProfileSeed {
    ProfileSeed(rand::rng().random())
}

fn random_draw_key() -> DrawKey {
    DrawKey(rand::rng().random())
}

#[cfg(test)]
mod tests;
