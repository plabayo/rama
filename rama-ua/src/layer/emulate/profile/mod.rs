use std::sync::Arc;

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::ExtensionsRef,
};
use rama_http::{
    Request, Version,
    conn::TargetHttpVersion,
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
            request::{ProfilePreservationMode, ProfilePreservationReport},
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

use super::SelectedUserAgentProfile;

const MAXIMUM_FETCH_CONTEXT_BYTES: usize = rama_utils::octets::kib(16);

/// Select a captured profile and publish its immutable emulation context.
///
/// Requests without an explicit [`RequestInitiator`] select a top-level
/// navigation flow. Missing `Sec-Fetch-*` headers do not constrain selection;
/// the chosen captured navigation supplies its profile-owned Fetch metadata.
#[derive(Debug, Clone)]
pub struct ProfileEmulateLayer {
    database: Arc<UserAgentDatabase>,
    selector: ProfileSelector,
    seed: Option<ProfileSeed>,
    connection_key: Option<DrawKey>,
    request_key: Option<DrawKey>,
    pins: VariantPins,
    preservation: ProfilePreservationMode,
}

impl ProfileEmulateLayer {
    #[must_use]
    pub fn new(database: Arc<UserAgentDatabase>) -> Self {
        Self {
            database,
            selector: ProfileSelector::default(),
            seed: None,
            connection_key: None,
            request_key: None,
            pins: VariantPins::default(),
            preservation: ProfilePreservationMode::Strict,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Restrict captured profile selection.
        pub fn selector(mut self, selector: ProfileSelector) -> Self {
            self.selector = selector;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Fix the profile seed for reproducible selection.
        pub fn seed(mut self, seed: Option<ProfileSeed>) -> Self {
            self.seed = seed;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Fix the logical connection draw key.
        pub fn connection_key(mut self, key: Option<DrawKey>) -> Self {
            self.connection_key = key;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Fix the logical request draw key.
        pub fn request_key(mut self, key: Option<DrawKey>) -> Self {
            self.request_key = key;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Pin stored connection and request variants.
        pub fn pins(mut self, pins: VariantPins) -> Self {
            self.pins = pins;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Select strict or reported best-effort replay.
        pub fn preservation(mut self, preservation: ProfilePreservationMode) -> Self {
            self.preservation = preservation;
            self
        }
    }
}

impl<S> Layer<S> for ProfileEmulateLayer {
    type Service = ProfileEmulateService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProfileEmulateService {
            inner,
            database: Arc::clone(&self.database),
            selector: self.selector.clone(),
            seed: self.seed,
            connection_key: self.connection_key,
            request_key: self.request_key,
            pins: self.pins,
            preservation: self.preservation,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProfileEmulateService {
            inner,
            database: self.database,
            selector: self.selector,
            seed: self.seed,
            connection_key: self.connection_key,
            request_key: self.request_key,
            pins: self.pins,
            preservation: self.preservation,
        }
    }
}

/// Request service produced by [`ProfileEmulateLayer`].
#[derive(Debug, Clone)]
pub struct ProfileEmulateService<S> {
    inner: S,
    database: Arc<UserAgentDatabase>,
    selector: ProfileSelector,
    seed: Option<ProfileSeed>,
    connection_key: Option<DrawKey>,
    request_key: Option<DrawKey>,
    pins: VariantPins,
    preservation: ProfilePreservationMode,
}

impl<S> ProfileEmulateService<S> {
    define_inner_service_accessors!();
}

impl<S, Body> Service<Request<Body>> for ProfileEmulateService<S>
where
    S: Service<Request<Body>, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let required = required_capabilities(&req).map_err(BoxError::from)?;
        let connection = req
            .extensions()
            .get_ref::<ConnectionContext>()
            .cloned()
            .unwrap_or_default();
        let flow = request_flow(
            &req,
            req.target_http_version().unwrap_or(req.version()),
            connection,
        )?;
        let selector = effective_selector(&self.selector, req.extensions().get_ref::<UserAgent>());
        let seed = self.seed.unwrap_or_else(random_seed);
        let connection_key = self.connection_key.unwrap_or_else(random_draw_key);
        let request_key = self.request_key.unwrap_or_else(random_draw_key);
        let selected = self.database.select(
            &SelectionRequest {
                client: selector,
                required,
                flow,
                pins: req
                    .extensions()
                    .get_ref::<VariantPins>()
                    .copied()
                    .unwrap_or(self.pins),
            },
            seed,
            connection_key,
        )?;
        let selected = Arc::new(
            if req.extensions().contains::<ConnectionBootstrapRequest>() {
                selected.for_connection_bootstrap(seed, connection_key)?
            } else {
                selected
            },
        );
        req.extensions()
            .insert(SelectedUserAgentProfile::from(selected.profile()));
        selected
            .emulation_context(seed, connection_key, request_key)
            .publish(req.extensions());
        req.extensions().insert(self.preservation);
        self.inner.serve(req).await.into_box_error()
    }
}

/// Draw the request variant after the pooled connection and protocol are known.
///
/// HTTP/3 field choices follow the emitted occurrences, including rebuilt cookies.
/// Explicit caller QPACK preferences must agree with the selected capture.
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
        if let Some(context) = EmulationContext::of(req.extensions()) {
            let connection = self
                .inner
                .extensions()
                .get_ref::<ConnectionSelection>()
                .or_else(|| req.extensions().get_ref::<ConnectionSelection>())
                .ok_or_else(|| {
                    BoxError::from_static_str("captured profile connection ticket is missing")
                })?;
            let version = self
                .inner
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|target| target.0)
                .unwrap_or(req.version());
            let flow = request_flow(
                &req,
                version,
                connection.effective.context.connection.clone(),
            )?;
            let preservation = req
                .extensions()
                .get_ref::<ProfilePreservationMode>()
                .copied()
                .unwrap_or_default();
            let selected = context.selected.request(
                connection,
                &flow,
                req.headers(),
                preservation,
                context.seed,
                context.request_key,
            )?;
            let prepared = req.extensions().get_ref::<PreparedConnectionComponents>();
            let initial = prepared.and_then(|prepared| {
                prepared
                    .h3_bootstrap
                    .as_ref()
                    .zip(prepared.h3_sequence.as_ref())
            });
            let replayed = match initial {
                Some((bootstrap, sequence)) => selected.replay_initial_request(
                    req.headers(),
                    preservation,
                    bootstrap,
                    sequence,
                )?,
                None => selected.replay_request(req.headers(), preservation)?,
            };
            let report = self
                .inner
                .extensions()
                .get_ref::<ProfilePreservationReport>()
                .or_else(|| req.extensions().get_ref::<ProfilePreservationReport>())
                .cloned()
                .unwrap_or_default()
                .followed_by(replayed.report);
            // Validate both caller choices before publishing either override.
            if let Some(base) = replayed.qpack_base
                && req
                    .extensions()
                    .get_ref::<FieldSectionBase>()
                    .is_some_and(|caller| *caller != base)
            {
                return Err(BoxError::from_static_str(
                    "caller and captured QPACK Base preferences conflict",
                ));
            }
            if let Some(preferences) = &replayed.qpack_headers
                && req
                    .extensions()
                    .get_ref::<HeaderPreferences>()
                    .is_some_and(|caller| {
                        caller.headers != preferences.headers
                            || caller.pseudo_headers != preferences.pseudo_headers
                    })
            {
                return Err(BoxError::from_static_str(
                    "caller and captured QPACK field preferences conflict",
                ));
            }

            if let Some(base) = replayed.qpack_base {
                req.extensions().insert(base);
            }
            if let Some(preferences) = replayed.qpack_headers {
                req.extensions().insert(preferences);
            }
            if let Some(headers) = replayed.headers {
                *req.headers_mut() = headers;
            }
            if let Some(pseudo_headers) = replayed.pseudo_headers {
                req.extensions().insert(pseudo_headers);
            }
            req.extensions().insert(report);
            req.extensions().insert(selected);
        }
        self.inner.serve(req).await.into_box_error()
    }
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
