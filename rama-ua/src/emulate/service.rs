use std::{borrow::Cow, fmt};

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    telemetry::tracing,
};
use rama_http_headers::{ClientHint, all_client_hints};
use rama_http_types::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version,
    conn::{H2ClientContextParams, Http1ClientContextParams},
    header::{
        ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, ORIGIN,
        REFERER, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
        SEC_WEBSOCKET_VERSION, USER_AGENT,
    },
    proto::h1::{
        Http1HeaderMap,
        headers::{HeaderMapValueRemover, original::OriginalHttp1Headers},
    },
};
use rama_net::{
    Protocol,
    address::{Authority, Host},
    http::RequestContext,
};
use rama_utils::str::{starts_with_ignore_ascii_case, submatch_ignore_ascii_case};

use crate::{
    HttpAgent, UserAgent,
    emulate::SelectedUserAgentProfile,
    profile::{
        CUSTOM_HEADER_MARKER, HttpHeadersProfile, HttpProfile, PreserveHeaderUserAgent,
        RequestInitiator,
    },
};

use super::{UserAgentProvider, UserAgentSelectFallback};

/// Service to select a [`UserAgentProfile`] and inject its info into the input [`Context`].
///
/// Note that actual http emulation is done by also ensuring a service
/// such as [`UserAgentEmulateHttpRequestModifier`] and [`UserAgentEmulateHttpConnectModifier`] is in use within your connector stack.
/// Tls emulation is facilitated by a tls client connector which respects
/// the injected (tls) client profile.
///
/// See the implementation of[`EasyHttpWebClient`] for the reference implementation of how
/// one can make use of this profile to emulate a user agent on the tls layer.
///
/// [`EasyHttpWebClient`]: https://ramaproxy.org/docs/rama/http/client/struct.EasyHttpWebClient.html
pub struct UserAgentEmulateService<S, P> {
    inner: S,
    provider: P,
    optional: bool,
    try_auto_detect_user_agent: bool,
    input_header_order: Option<HeaderName>,
    select_fallback: Option<UserAgentSelectFallback>,
}

impl<S: fmt::Debug, P: fmt::Debug> fmt::Debug for UserAgentEmulateService<S, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAgentEmulateService")
            .field("inner", &self.inner)
            .field("provider", &self.provider)
            .field("optional", &self.optional)
            .field(
                "try_auto_detect_user_agent",
                &self.try_auto_detect_user_agent,
            )
            .field("input_header_order", &self.input_header_order)
            .field("select_fallback", &self.select_fallback)
            .finish()
    }
}

impl<S: Clone, P: Clone> Clone for UserAgentEmulateService<S, P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            provider: self.provider.clone(),
            optional: self.optional,
            try_auto_detect_user_agent: self.try_auto_detect_user_agent,
            input_header_order: self.input_header_order.clone(),
            select_fallback: self.select_fallback,
        }
    }
}

impl<S, P> UserAgentEmulateService<S, P> {
    /// Create a new [`UserAgentEmulateService`] with the given inner service and provider.
    ///
    /// Provider is implicitly expected to be a [`UserAgentProvider`].
    pub fn new(inner: S, provider: P) -> Self {
        Self {
            inner,
            provider,
            optional: false,
            try_auto_detect_user_agent: false,
            input_header_order: None,
            select_fallback: None,
        }
    }

    /// When no user agent profile was found it will
    /// fail the request unless optional is true. In case of
    /// the latter the service will do nothing.
    #[must_use]
    pub fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    /// See [`Self::optional`].
    pub fn set_optional(&mut self, optional: bool) -> &mut Self {
        self.optional = optional;
        self
    }

    /// If true, the service will try to auto-detect the user agent from the request,
    /// but only in case that info is not yet found in the context.
    #[must_use]
    pub fn try_auto_detect_user_agent(mut self, try_auto_detect_user_agent: bool) -> Self {
        self.try_auto_detect_user_agent = try_auto_detect_user_agent;
        self
    }

    /// See [`Self::try_auto_detect_user_agent`].
    pub fn set_try_auto_detect_user_agent(
        &mut self,
        try_auto_detect_user_agent: bool,
    ) -> &mut Self {
        self.try_auto_detect_user_agent = try_auto_detect_user_agent;
        self
    }

    /// Define a header that if present is to contain a CSV header name list,
    /// that allows you to define the desired header order for the (extra) headers
    /// found in the input (http) request.
    ///
    /// Extra meaning any headers not considered a base header and already defined
    /// by the (selected) User Agent Profile.
    ///
    /// This can be useful because your http client might not respect the header casing
    /// and/or order of the headers taken together. Using this metadata allows you to
    /// communicate this data through anyway. If however your http client does respect
    /// casing and order, or you don't care about some of it, you might not need it.
    #[must_use]
    pub fn input_header_order(mut self, name: HeaderName) -> Self {
        self.input_header_order = Some(name);
        self
    }

    /// See [`Self::input_header_order`].
    pub fn set_input_header_order(&mut self, name: HeaderName) -> &mut Self {
        self.input_header_order = Some(name);
        self
    }

    /// Choose what to do in case no profile could be selected
    /// using the regular pre-conditions as specified by the provider.
    #[must_use]
    pub fn select_fallback(mut self, fb: UserAgentSelectFallback) -> Self {
        self.select_fallback = Some(fb);
        self
    }

    /// See [`Self::select_fallback`].
    pub fn set_select_fallback(&mut self, fb: UserAgentSelectFallback) -> &mut Self {
        self.select_fallback = Some(fb);
        self
    }
}

impl<State, Body, S, P> Service<State, Request<Body>> for UserAgentEmulateService<S, P>
where
    State: Clone + Send + Sync + 'static,
    Body: Send + Sync + 'static,
    S: Service<State, Request<Body>, Error: Into<BoxError>>,
    P: UserAgentProvider<State>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        mut req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(fallback) = self.select_fallback {
            ctx.insert(fallback);
        }

        if self.try_auto_detect_user_agent && !ctx.contains::<UserAgent>() {
            match req
                .headers()
                .get(USER_AGENT)
                .and_then(|ua| ua.to_str().ok())
            {
                Some(ua_str) => {
                    let user_agent = UserAgent::new(ua_str);
                    tracing::trace!(
                        user_agent.original = %ua_str,
                        "user agent {user_agent} auto-detected from request"
                    );
                    ctx.insert(user_agent);
                }
                None => {
                    tracing::debug!(
                        "user agent auto-detection not possible: no user agent header present"
                    );
                }
            }
        }

        let Some(profile) = self.provider.select_user_agent_profile(&ctx) else {
            return if self.optional {
                Ok(self.inner.serve(ctx, req).await.map_err(Into::into)?)
            } else {
                Err(OpaqueError::from_display(
                    "requirement not fulfilled: user agent profile could not be selected",
                )
                .into_boxed())
            };
        };

        tracing::debug!(
            user_agent.kind = %profile.ua_kind,
            user_agent.version = ?profile.ua_version,
            user_agent.platform = ?profile.platform,
            "user agent profile selected for emulation"
        );

        let preserve_http = matches!(
            ctx.get::<UserAgent>().and_then(|ua| ua.http_agent()),
            Some(HttpAgent::Preserve),
        );

        if preserve_http {
            tracing::trace!(
                user_agent.kind = %profile.ua_kind,
                user_agent.version = ?profile.ua_version,
                user_agent.platform = ?profile.platform,
                "user agent emulation: skip http settings as http is instructed to be preserved"
            );
        } else {
            tracing::trace!(
                user_agent.kind = %profile.ua_kind,
                user_agent.version = ?profile.ua_version,
                user_agent.platform = ?profile.platform,
                "user agent emulation: inject http context data to prepare for HTTP emulation"
            );
            ctx.insert(profile.http.clone());

            if let Some(header) = self
                .input_header_order
                .as_ref()
                .and_then(|name| req.headers().get(name))
            {
                let s = header.to_str().context("interpret header as a utf-8 str")?;
                let mut headers = OriginalHttp1Headers::with_capacity(s.matches(',').count());
                for s in s.split(',') {
                    let s = s.trim();
                    if s.is_empty() {
                        continue;
                    }
                    headers.push(s.parse().context("parse header part as h1 headern name")?);
                }
                req.extensions_mut().insert(headers);
            }
        }

        #[cfg(feature = "tls")]
        {
            use crate::TlsAgent;

            let preserve_tls = matches!(
                ctx.get::<UserAgent>().and_then(|ua| ua.tls_agent()),
                Some(TlsAgent::Preserve),
            );
            if preserve_tls {
                tracing::trace!(
                    user_agent.kind = %profile.ua_kind,
                    user_agent.version = ?profile.ua_version,
                    user_agent.platform = ?profile.platform,
                    "user agent emulation: skip tls settings as tls is instructed to be preserved"
                );
            } else {
                ctx.insert(profile.tls.clone());
                tracing::trace!(
                    user_agent.kind = %profile.ua_kind,
                    user_agent.version = ?profile.ua_version,
                    user_agent.platform = ?profile.platform,
                    "user agent emulation: tls profile injected in ctx"
                );
            }
        }

        // inject the selected user agent profile into the context
        ctx.insert(SelectedUserAgentProfile::from(profile));

        // serve emulated http(s) request via inner service
        self.inner.serve(ctx, req).await.map_err(Into::into)
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
// a http RequestInspector which is to be used in combination
// with the [`UserAgentEmulateService`] to facilitate the
// http emulation based on the injected http profile.
pub struct UserAgentEmulateHttpConnectModifier;

impl UserAgentEmulateHttpConnectModifier {
    #[inline]
    /// Create a new (default) [`UserAgentEmulateHttpConnectModifier`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<State, ReqBody> Service<State, Request<ReqBody>> for UserAgentEmulateHttpConnectModifier
where
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<State>, Request<ReqBody>);

    async fn serve(
        &self,
        mut ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        match ctx.get().cloned() {
            Some(http_profile) => {
                tracing::trace!(
                    http.version = ?req.version(),
                    "http profile found in context to use for http connection emulation, proceed",
                );
                emulate_http_connect_settings(&mut ctx, &mut req, &http_profile);
            }
            None => {
                tracing::trace!(
                    http.version = ?req.version(),
                    "no http profile found in context to use for http connection emulation, request is passed through as-is",
                );
            }
        }
        Ok((ctx, req))
    }
}

fn emulate_http_connect_settings<Body, State>(
    ctx: &mut Context<State>,
    req: &mut Request<Body>,
    profile: &HttpProfile,
) {
    match req.version() {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
            tracing::trace!("UA emulation add http1-specific settings",);
            ctx.insert(Http1ClientContextParams {
                title_header_case: profile.h1.settings.title_case_headers,
            });
        }
        Version::HTTP_2 => {
            let pseudo_headers = profile.h2.settings.http_pseudo_headers.clone();
            let early_frames = profile.h2.settings.early_frames.clone();

            if pseudo_headers.is_some() || early_frames.is_some() {
                tracing::trace!(
                    "user agent emulation: insert h2 settings into extensions: (pseudo headers = {:?} ; early frames: {:?})",
                    pseudo_headers,
                    early_frames,
                );
                req.extensions_mut().insert(H2ClientContextParams {
                    headers_pseudo_order: pseudo_headers,
                    early_frames,
                });
            }
        }
        Version::HTTP_3 => tracing::debug!(
            "UA emulation not yet supported for h3: not applying anything h3-specific"
        ),
        _ => tracing::debug!(
            http.version = ?req.version(),
            "UA emulation not supported for unknown http version: not applying anything version-specific",
        ),
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
// a http RequestInspector which is to be used in combination
// with the [`UserAgentEmulateService`] to facilitate the
// http emulation based on the injected http profile.
pub struct UserAgentEmulateHttpRequestModifier;

impl UserAgentEmulateHttpRequestModifier {
    #[inline]
    /// Create a new (default) [`UserAgentEmulateHttpRequestModifier`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<State, ReqBody> Service<State, Request<ReqBody>> for UserAgentEmulateHttpRequestModifier
where
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<State>, Request<ReqBody>);

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        match ctx.get() {
            Some(http_profile) => {
                tracing::trace!(
                    http.version = ?req.version(),
                    "http profile found in context to use for emulation, proceed",
                );

                match get_base_http_headers(&ctx, &req, http_profile) {
                    Some(base_http_headers) => {
                        let original_http_header_order =
                            ctx.get().or_else(|| req.extensions().get()).cloned();
                        let original_headers = req.headers().clone();

                        let preserve_ua_header = ctx.contains::<PreserveHeaderUserAgent>();

                        let (authority, protocol) = match ctx.get::<RequestContext>() {
                            Some(ctx) => (
                                Some(Cow::Borrowed(&ctx.authority)),
                                Some(Cow::Borrowed(&ctx.protocol)),
                            ),
                            None => match RequestContext::try_from((&ctx, &req)) {
                                Ok(ctx) => (
                                    Some(Cow::Owned(ctx.authority)),
                                    Some(Cow::Owned(ctx.protocol)),
                                ),
                                Err(err) => {
                                    tracing::debug!(
                                        "failed to compute request's authority and protocol for UA Emulation purposes: {err:?}",
                                    );
                                    (None, None)
                                }
                            },
                        };

                        let output_headers = merge_http_headers(
                            base_http_headers,
                            original_http_header_order,
                            original_headers,
                            preserve_ua_header,
                            authority,
                            protocol,
                            Some(req.method()),
                            ctx.get::<Vec<ClientHint>>().map(|v| v.as_slice()),
                        );

                        tracing::trace!("user agent emulation: http emulated");
                        let (output_headers, original_headers) = output_headers.into_parts();
                        *req.headers_mut() = output_headers;
                        req.extensions_mut().insert(original_headers);
                    }
                    None => {
                        tracing::debug!(
                            "user agent emulation: no http headers to emulate: no base http headers found"
                        );
                    }
                }

                if req.version() == Version::HTTP_2 {
                    let pseudo_headers = http_profile.h2.settings.http_pseudo_headers.clone();

                    tracing::trace!(
                        "user agent emulation: insert h2 pseudo headers into request extensions: {pseudo_headers:?}"
                    );

                    if let Some(pseudo_headers) = pseudo_headers {
                        req.extensions_mut().insert(pseudo_headers);
                    }
                }
            }
            None => {
                tracing::trace!(
                    http.version = ?req.version(),
                    "no http profile found in context to use for emulation, request is passed through as-is",
                );
            }
        }
        Ok((ctx, req))
    }
}

fn get_base_http_headers<'a, Body, State>(
    ctx: &Context<State>,
    req: &Request<Body>,
    profile: &'a HttpProfile,
) -> Option<&'a Http1HeaderMap> {
    let headers_profile = match req.version() {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => &profile.h1.headers,
        Version::HTTP_2 => &profile.h2.headers,
        _ => {
            tracing::debug!(
                http.version = ?req.version(),
                "UA emulation not supported for unknown http version: not applying anything version-specific",
            );
            return None;
        }
    };
    match ctx.get::<RequestInitiator>().copied() {
        Some(req_init) => {
            tracing::trace!(
                "base http headers defined based on hint from UserAgent (overwrite): {req_init}"
            );
            get_base_http_headers_from_req_init(req_init, headers_profile)
        }
        // NOTE: the primitive checks below are pretty bad,
        // feel free to help improve. Just need to make sure it has good enough fallbacks,
        // and that they are cheap enough to check.
        None => match *req.method() {
            Method::GET => {
                let req_init = if headers_contains_partial_value(
                    req.headers(),
                    &X_REQUESTED_WITH,
                    "XmlHttpRequest",
                ) {
                    RequestInitiator::Xhr
                } else if headers_contains_partial_value(
                    req.headers(),
                    &SEC_WEBSOCKET_VERSION,
                    "13",
                ) {
                    RequestInitiator::Ws
                } else {
                    RequestInitiator::Navigate
                };
                tracing::trace!(
                    "base http headers defined based on Get=XhrOrWsOrNavigate assumption: {req_init}"
                );
                get_base_http_headers_from_req_init(req_init, headers_profile)
            }
            Method::POST => {
                let req_init = if headers_contains_partial_value(
                    req.headers(),
                    &X_REQUESTED_WITH,
                    "XmlHttpRequest",
                ) {
                    RequestInitiator::Xhr
                } else if headers_contains_partial_value(req.headers(), &CONTENT_TYPE, "form-") {
                    RequestInitiator::Form
                } else {
                    RequestInitiator::Fetch
                };
                tracing::trace!(
                    "base http headers defined based on Post=FormOrFetch assumption: {req_init}"
                );
                get_base_http_headers_from_req_init(req_init, headers_profile)
            }
            _ => {
                let req_init = if headers_contains_partial_value(
                    req.headers(),
                    &X_REQUESTED_WITH,
                    "XmlHttpRequest",
                ) {
                    RequestInitiator::Xhr
                } else if req.version() == Version::HTTP_2
                    && req.method() == Method::CONNECT
                    && headers_contains_partial_value(req.headers(), &SEC_WEBSOCKET_VERSION, "13")
                {
                    RequestInitiator::Ws
                } else {
                    RequestInitiator::Fetch
                };
                tracing::trace!(
                    "base http headers defined based on XhrOrWsOrFetch assumption: {req_init}"
                );
                get_base_http_headers_from_req_init(req_init, headers_profile)
            }
        },
    }
}

static X_REQUESTED_WITH: HeaderName = HeaderName::from_static("x-requested-with");

fn headers_contains_partial_value(headers: &HeaderMap, name: &HeaderName, value: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|s| submatch_ignore_ascii_case(s, value))
        .unwrap_or_default()
}

fn get_base_http_headers_from_req_init(
    req_init: RequestInitiator,
    headers: &HttpHeadersProfile,
) -> Option<&Http1HeaderMap> {
    match req_init {
        RequestInitiator::Navigate => Some(&headers.navigate),
        RequestInitiator::Form => Some(headers.form.as_ref().unwrap_or(&headers.navigate)),
        RequestInitiator::Xhr => Some(
            headers
                .xhr
                .as_ref()
                .or(headers.fetch.as_ref())
                .unwrap_or(&headers.navigate),
        ),
        RequestInitiator::Fetch => Some(
            headers
                .fetch
                .as_ref()
                .or(headers.xhr.as_ref())
                .unwrap_or(&headers.navigate),
        ),
        RequestInitiator::Ws => headers.ws.as_ref(),
    }
}

const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn merge_http_headers<'a>(
    base_http_headers: &Http1HeaderMap,
    original_http_header_order: Option<OriginalHttp1Headers>,
    original_headers: HeaderMap,
    preserve_ua_header: bool,
    request_authority: Option<Cow<'a, Authority>>,
    protocol: Option<Cow<'a, Protocol>>,
    method: Option<&Method>,
    requested_client_hints: Option<&[ClientHint]>,
) -> Http1HeaderMap {
    let original_header_referer_value = original_headers.get(&REFERER).cloned();
    let is_secure_request = protocol.as_ref().map(|p| p.is_secure()).unwrap_or_default();

    let mut original_headers = HeaderMapValueRemover::from(original_headers);

    // to support clients that pass in client hints as well. We'll ignore their
    // header values, but can still take the hint none the less
    let original_client_hints: Vec<_> = all_client_hints()
        .filter(|p| {
            p.iter_header_names()
                .filter_map(|name| original_headers.remove(&name).map(|_| 1))
                .sum::<u16>()
                > 0
        })
        .collect();

    let mut output_headers_a = Vec::new();
    let mut output_headers_b = Vec::new();

    let mut output_headers_ref = &mut output_headers_a;

    let is_header_allowed = |header_name: &HeaderName| {
        if let Some(hint) = ClientHint::match_header_name(header_name) {
            is_secure_request
                && (hint.is_low_entropy()
                    || requested_client_hints
                        .map(|hints| hints.contains(&hint))
                        .unwrap_or_default()
                    || original_client_hints.contains(&hint))
        } else {
            is_secure_request || !starts_with_ignore_ascii_case(header_name.as_str(), "sec-fetch")
        }
    };

    // put all "base" headers in correct order, and with proper name casing
    for (base_name, base_value) in base_http_headers.clone().into_iter() {
        let base_header_name = base_name.header_name();
        let original_value = original_headers.remove(base_header_name);
        match base_header_name {
            &ACCEPT
            | &ACCEPT_LANGUAGE
            | &SEC_WEBSOCKET_KEY
            | &SEC_WEBSOCKET_EXTENSIONS
            | &SEC_WEBSOCKET_PROTOCOL => {
                let value = original_value.unwrap_or(base_value);
                output_headers_ref.push((base_name, value));
            }
            &REFERER | &COOKIE | &AUTHORIZATION | &HOST | &ORIGIN | &CONTENT_LENGTH
            | &CONTENT_TYPE => {
                if let Some(value) = original_value {
                    output_headers_ref.push((base_name, value));
                }
            }
            &USER_AGENT => {
                if preserve_ua_header {
                    let value = original_value.unwrap_or(base_value);
                    output_headers_ref.push((base_name, value));
                } else {
                    output_headers_ref.push((base_name, base_value));
                }
            }
            _ => {
                if base_header_name == CUSTOM_HEADER_MARKER {
                    output_headers_ref = &mut output_headers_b;
                } else if is_header_allowed(base_header_name) {
                    if base_header_name == SEC_FETCH_SITE {
                        // assumption: is_header_allowed ensures that this only
                        // is reached in a secure context :)
                        let value = compute_sec_fetch_site_value(
                            original_header_referer_value.as_ref(),
                            method,
                            protocol.as_deref(),
                            request_authority.as_deref(),
                        );
                        output_headers_ref.push((base_name, value));
                    } else {
                        output_headers_ref.push((base_name, base_value));
                    }
                }
            }
        }
    }

    // respect original header order of original headers where possible
    for header_name in original_http_header_order.into_iter().flatten() {
        let std_header_name = header_name.header_name();
        if let Some(value) = original_headers.remove(std_header_name) {
            if is_header_allowed(header_name.header_name())
                && ClientHint::match_header_name(std_header_name).is_none()
            {
                output_headers_a.push((header_name, value));
            }
        }
    }

    let original_headers_iter = original_headers
        .into_iter()
        .filter(|(header_name, _)| is_header_allowed(header_name.header_name()));

    Http1HeaderMap::from_iter(
        output_headers_a
            .into_iter()
            .chain(original_headers_iter) // add all remaining original headers in any order within the right loc
            .chain(output_headers_b),
    )
}

fn compute_sec_fetch_site_value(
    original_header_referer_value: Option<&HeaderValue>,
    method: Option<&Method>,
    protocol: Option<&Protocol>,
    request_authority: Option<&Authority>,
) -> HeaderValue {
    match &original_header_referer_value {
        Some(referer_value) => {
            match referer_value
                .to_str()
                .context("turn referer into str")
                .and_then(|s| {
                    s.parse::<Uri>()
                        .context("turn referer header value str into http Uri")
                }) {
                Ok(uri) => {
                    let referer_protocol =
                        Protocol::maybe_from_uri_scheme_str_and_method(uri.scheme(), method);

                    let default_port = uri
                        .port_u16()
                        .or_else(|| referer_protocol.as_ref().and_then(|p| p.default_port()));

                    let maybe_authority = uri
                        .host()
                        .and_then(|h| Host::try_from(h).ok().and_then(|h| {
                            if let Some(default_port) = default_port {
                                tracing::trace!(url.full = %uri, "detected host {h} from (abs) referer uri");
                                Some(Authority::new(h, default_port))
                            } else {
                                tracing::trace!(url.full = %uri, "detected host {h} from (abs) referer uri: but no port available");
                                None
                            }
                        }));

                    if let Some(authority) = maybe_authority {
                        if referer_protocol.as_ref() == protocol {
                            if Some(&authority) == request_authority {
                                HeaderValue::from_static("same-origin")
                            } else if let Some(request_host) =
                                request_authority.as_ref().map(|a| a.host())
                            {
                                let is_same_registrable_domain =
                                    match (authority.host(), request_host) {
                                        (Host::Name(a), Host::Name(b)) => {
                                            a.have_same_registrable_domain(b)
                                        }
                                        (Host::Address(a), Host::Address(b)) => a == b,
                                        _ => false,
                                    };
                                if is_same_registrable_domain {
                                    HeaderValue::from_static("same-site")
                                } else {
                                    HeaderValue::from_static("cross-site")
                                }
                            } else {
                                tracing::debug!(
                                    http.request.header.referer = ?referer_value,
                                    "missing request authority, returning none as default",
                                );
                                HeaderValue::from_static("none")
                            }
                        } else {
                            HeaderValue::from_static("cross-site")
                        }
                    } else {
                        tracing::debug!(
                            http.request.header.referer = ?referer_value,
                            "invalid referer value (failed to extract authority from uri value)",
                        );
                        HeaderValue::from_static("none")
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        http.request.header.referer = ?referer_value,
                        "invalid referer value (expected a valid uri, defaulting to none): {err:?}",
                    );
                    HeaderValue::from_static("none")
                }
            }
        }
        None => HeaderValue::from_static("none"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{convert::Infallible, str::FromStr, sync::Arc};

    use itertools::Itertools as _;
    use rama_core::{Layer, inspect::RequestInspectorLayer, service::service_fn};
    use rama_http_types::{Body, HeaderValue, header::ETAG, proto::h1::Http1HeaderName};
    use rama_net::address::Host;

    use crate::emulate::UserAgentEmulateLayer;
    use crate::profile::{
        Http1Profile, Http1Settings, Http2Profile, Http2Settings, HttpHeadersProfile, HttpProfile,
        UserAgentProfile,
    };

    #[test]
    fn test_merge_http_headers() {
        struct TestCase {
            description: &'static str,
            base_http_headers: Vec<(&'static str, &'static str)>,
            original_http_header_order: Option<Vec<&'static str>>,
            original_headers: Vec<(&'static str, &'static str)>,
            preserve_ua_header: bool,
            request_authority: Authority,
            protocol: Protocol,
            requested_client_hints: Option<Vec<&'static str>>,
            expected: Vec<(&'static str, &'static str)>,
        }

        let test_cases = [
            TestCase {
                description: "empty",
                base_http_headers: vec![],
                original_http_header_order: None,
                original_headers: vec![],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![],
            },
            TestCase {
                description: "base headers only",
                base_http_headers: vec![
                    ("Accept", "text/html"),
                    ("Content-Type", "application/json"),
                ],
                original_http_header_order: None,
                original_headers: vec![],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![("Accept", "text/html")],
            },
            TestCase {
                description: "base headers only with content-type",
                base_http_headers: vec![
                    ("Accept", "text/html"),
                    ("Content-Type", "application/json"),
                ],
                original_http_header_order: None,
                original_headers: vec![("content-type", "text/xml")],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![("Accept", "text/html"), ("Content-Type", "text/xml")],
            },
            TestCase {
                description: "original headers only",
                base_http_headers: vec![],
                original_http_header_order: None,
                original_headers: vec![("accept", "text/html")],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![("accept", "text/html")],
            },
            TestCase {
                description: "original and base headers, no conflicts",
                base_http_headers: vec![("accept", "text/html"), ("user-agent", "python/3.10")],
                original_http_header_order: None,
                original_headers: vec![("content-type", "application/json")],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![
                    ("accept", "text/html"),
                    ("user-agent", "python/3.10"),
                    ("content-type", "application/json"),
                ],
            },
            TestCase {
                description: "original and base headers, with conflicts",
                base_http_headers: vec![
                    ("accept", "text/html"),
                    ("content-type", "text/html"),
                    ("user-agent", "python/3.10"),
                ],
                original_http_header_order: Some(vec!["content-type", "user-agent"]),
                original_headers: vec![
                    ("content-type", "application/json"),
                    ("user-agent", "php/8.0"),
                ],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![
                    ("accept", "text/html"),
                    ("content-type", "application/json"),
                    ("user-agent", "python/3.10"),
                ],
            },
            TestCase {
                description: "original and base headers, with conflicts, preserve ua header",
                base_http_headers: vec![
                    ("accept", "text/html"),
                    ("content-type", "text/html"),
                    ("user-agent", "python/3.10"),
                ],
                original_http_header_order: Some(vec!["content-type", "user-agent"]),
                original_headers: vec![
                    ("content-type", "application/json"),
                    ("user-agent", "php/8.0"),
                ],
                preserve_ua_header: true,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![
                    ("accept", "text/html"),
                    ("content-type", "application/json"),
                    ("user-agent", "php/8.0"),
                ],
            },
            TestCase {
                description: "no opt-in base headers defined",
                base_http_headers: vec![
                    ("accept", "text/html"),
                    ("authorization", "Bearer 1234567890"),
                    ("cookie", "session=1234567890"),
                    ("referer", "https://example.com"),
                ],
                original_http_header_order: Some(vec!["content-type", "user-agent"]),
                original_headers: vec![
                    ("content-type", "application/json"),
                    ("user-agent", "php/8.0"),
                ],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![
                    ("accept", "text/html"),
                    ("content-type", "application/json"),
                    ("user-agent", "php/8.0"),
                ],
            },
            TestCase {
                description: "some opt-in base headers defined",
                base_http_headers: vec![
                    ("accept", "text/html"),
                    ("authorization", "Bearer 1234567890"),
                    ("cookie", "session=1234567890"),
                    ("referer", "https://example.com"),
                ],
                original_http_header_order: Some(vec![
                    "content-type",
                    "cookie",
                    "user-agent",
                    "referer",
                ]),
                original_headers: vec![
                    ("content-type", "application/json"),
                    ("cookie", "foo=bar"),
                    ("user-agent", "php/8.0"),
                    ("referer", "https://ramaproxy.org"),
                ],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::from_str("ramaproxy.org").unwrap(),
                    Protocol::HTTPS.default_port().unwrap(),
                ),
                protocol: Protocol::HTTPS,
                requested_client_hints: None,
                expected: vec![
                    ("accept", "text/html"),
                    ("cookie", "foo=bar"),
                    ("referer", "https://ramaproxy.org"),
                    ("content-type", "application/json"),
                    ("user-agent", "php/8.0"),
                ],
            },
            TestCase {
                description: "all opt-in base headers defined",
                base_http_headers: vec![
                    ("accept", "text/html"),
                    ("authorization", "Bearer 1234567890"),
                    ("cookie", "session=1234567890"),
                    ("referer", "https://example.com"),
                ],
                original_http_header_order: Some(vec![
                    "content-type",
                    "cookie",
                    "user-agent",
                    "referer",
                    "authorization",
                ]),
                original_headers: vec![
                    ("content-type", "application/json"),
                    ("cookie", "foo=bar"),
                    ("user-agent", "php/8.0"),
                    ("referer", "https://ramaproxy.org"),
                    ("authorization", "Bearer 42"),
                ],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::EXAMPLE_NAME,
                    Protocol::HTTPS.default_port().unwrap(),
                ),
                protocol: Protocol::HTTPS,
                requested_client_hints: None,
                expected: vec![
                    ("accept", "text/html"),
                    ("authorization", "Bearer 42"),
                    ("cookie", "foo=bar"),
                    ("referer", "https://ramaproxy.org"),
                    ("content-type", "application/json"),
                    ("user-agent", "php/8.0"),
                ],
            },
            TestCase {
                description: "all opt-in base headers defined, with custom header marker",
                base_http_headers: vec![
                    ("accept", "text/html"),
                    ("authorization", "Bearer 1234567890"),
                    ("x-rama-custom-header-marker", "1"),
                    ("cookie", "session=1234567890"),
                    ("referer", "https://example.com"),
                ],
                original_http_header_order: Some(vec![
                    "content-type",
                    "cookie",
                    "user-agent",
                    "referer",
                    "authorization",
                ]),
                original_headers: vec![
                    ("content-type", "application/json"),
                    ("cookie", "foo=bar"),
                    ("user-agent", "php/8.0"),
                    ("referer", "https://ramaproxy.org"),
                    ("authorization", "Bearer 42"),
                ],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::from_str("ramaproxy.org").unwrap(),
                    Protocol::HTTPS.default_port().unwrap(),
                ),
                protocol: Protocol::HTTPS,
                requested_client_hints: None,
                expected: vec![
                    ("accept", "text/html"),
                    ("authorization", "Bearer 42"),
                    ("content-type", "application/json"),
                    ("user-agent", "php/8.0"),
                    ("cookie", "foo=bar"),
                    ("referer", "https://ramaproxy.org"),
                ],
            },
            TestCase {
                description: "realistic browser example",
                base_http_headers: vec![
                    ("Host", "www.google.com"),
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ),
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    ),
                    ("Accept-Language", "en-US,en;q=0.9"),
                    ("Accept-Encoding", "gzip, deflate, br"),
                    ("Connection", "keep-alive"),
                    ("Referer", "https://www.google.com/"),
                    ("Upgrade-Insecure-Requests", "1"),
                    ("x-rama-custom-header-marker", "1"),
                    ("Cookie", "rama-ua-test=1"),
                    ("Sec-Fetch-Dest", "document"),
                    ("Sec-Fetch-Mode", "navigate"),
                    ("Sec-Fetch-Site", "cross-site"),
                    ("Sec-Fetch-User", "?1"),
                    ("DNT", "1"),
                    ("Sec-GPC", "1"),
                    ("Priority", "u=0, i"),
                ],
                original_http_header_order: Some(vec![
                    "x-show-price",
                    "x-show-price-currency",
                    "accept-language",
                    "cookie",
                ]),
                original_headers: vec![
                    ("x-show-price", "true"),
                    ("x-show-price-currency", "USD"),
                    ("accept-language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
                    ("cookie", "session=on; foo=bar"),
                    ("x-requested-with", "XMLHttpRequest"),
                    ("host", "www.example.com"),
                ],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::from_str("www.google.com").unwrap(),
                    Protocol::HTTP.default_port().unwrap(),
                ),
                protocol: Protocol::HTTP,
                requested_client_hints: None,
                expected: vec![
                    ("Host", "www.example.com"),
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ),
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    ),
                    ("Accept-Language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
                    ("Accept-Encoding", "gzip, deflate, br"),
                    ("Connection", "keep-alive"),
                    ("Upgrade-Insecure-Requests", "1"),
                    ("x-show-price", "true"),
                    ("x-show-price-currency", "USD"),
                    ("x-requested-with", "XMLHttpRequest"),
                    ("Cookie", "session=on; foo=bar"),
                    ("DNT", "1"),
                    ("Sec-GPC", "1"),
                    ("Priority", "u=0, i"),
                ],
            },
            TestCase {
                description: "realistic browser example over tls",
                base_http_headers: vec![
                    ("Host", "www.google.com"),
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ),
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    ),
                    ("Accept-Language", "en-US,en;q=0.9"),
                    ("Accept-Encoding", "gzip, deflate, br"),
                    ("Connection", "keep-alive"),
                    ("Referer", "https://www.google.com/"),
                    ("Upgrade-Insecure-Requests", "1"),
                    ("x-rama-custom-header-marker", "1"),
                    ("Cookie", "rama-ua-test=1"),
                    ("Sec-Fetch-Dest", "document"),
                    ("Sec-Fetch-Mode", "navigate"),
                    ("Sec-Fetch-Site", "cross-site"),
                    ("Sec-Fetch-User", "?1"),
                    ("DNT", "1"),
                    ("Sec-GPC", "1"),
                    ("Priority", "u=0, i"),
                ],
                original_http_header_order: Some(vec![
                    "x-show-price",
                    "x-show-price-currency",
                    "accept-language",
                    "cookie",
                ]),
                original_headers: vec![
                    ("x-show-price", "true"),
                    ("x-show-price-currency", "USD"),
                    ("accept-language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
                    ("cookie", "session=on; foo=bar"),
                    ("x-requested-with", "XMLHttpRequest"),
                ],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::from_str("www.google.com").unwrap(),
                    Protocol::HTTPS.default_port().unwrap(),
                ),
                protocol: Protocol::HTTPS,
                requested_client_hints: None,
                expected: vec![
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ),
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    ),
                    ("Accept-Language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
                    ("Accept-Encoding", "gzip, deflate, br"),
                    ("Connection", "keep-alive"),
                    ("Upgrade-Insecure-Requests", "1"),
                    ("x-show-price", "true"),
                    ("x-show-price-currency", "USD"),
                    ("x-requested-with", "XMLHttpRequest"),
                    ("Cookie", "session=on; foo=bar"),
                    ("Sec-Fetch-Dest", "document"),
                    ("Sec-Fetch-Mode", "navigate"),
                    ("Sec-Fetch-Site", "none"),
                    ("Sec-Fetch-User", "?1"),
                    ("DNT", "1"),
                    ("Sec-GPC", "1"),
                    ("Priority", "u=0, i"),
                ],
            },
            TestCase {
                description: "secure example request with referer",
                base_http_headers: vec![
                    ("Host", "www.google.com"),
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ),
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    ),
                    ("Referer", "https://www.google.com/"),
                    ("Sec-Fetch-Site", "cross-site"),
                ],
                original_http_header_order: None,
                original_headers: vec![("referer", "https://maps.google.com/")],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::from_str("www.google.com").unwrap(),
                    Protocol::HTTPS.default_port().unwrap(),
                ),
                protocol: Protocol::HTTPS,
                requested_client_hints: None,
                expected: vec![
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ),
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    ),
                    ("Referer", "https://maps.google.com/"),
                    ("Sec-Fetch-Site", "same-site"),
                ],
            },
            TestCase {
                description: "realistic browser example over tls with requested client hints",
                base_http_headers: vec![
                    ("Host", "www.google.com"),
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ),
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    ),
                    ("Accept-Language", "en-US,en;q=0.9"),
                    ("Accept-Encoding", "gzip, deflate, br"),
                    ("Connection", "keep-alive"),
                    ("Referer", "https://www.google.com/"),
                    ("Upgrade-Insecure-Requests", "1"),
                    ("x-rama-custom-header-marker", "1"),
                    ("Cookie", "rama-ua-test=1"),
                    ("Sec-Fetch-Dest", "document"),
                    ("Sec-Fetch-Mode", "navigate"),
                    ("Sec-Fetch-Site", "cross-site"),
                    ("Sec-Fetch-User", "?1"),
                    ("Sec-CH-Downlink", "100"),
                    ("Sec-CH-Ect", "4g"),
                    ("Sec-CH-RTT", "100"),
                    ("Sec-CH-UA-Arch", "arm"),
                    ("Sec-CH-UA-Bitness", "64"),
                    ("Sec-CH-UA-Full-Version", "120.0.0.0"),
                    ("Sec-CH-UA-Full-Version-List", "Chrome 120.0.0.0"),
                    ("Sec-CH-UA-Mobile", "?0"),
                    ("Sec-CH-UA-Platform", "macOS"),
                    ("Sec-CH-UA-Platform-Version", "10.15.7"),
                    ("Sec-CH-UA-Model", "LimitedEdition"),
                    ("DNT", "1"),
                    ("Sec-GPC", "1"),
                    ("Priority", "u=0, i"),
                ],
                original_http_header_order: Some(vec![
                    "x-show-price",
                    "x-show-price-currency",
                    "accept-language",
                    "cookie",
                ]),
                original_headers: vec![
                    ("x-show-price", "true"),
                    ("x-show-price-currency", "USD"),
                    ("accept-language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
                    ("cookie", "session=on; foo=bar"),
                    ("x-requested-with", "XMLHttpRequest"),
                    ("sec-ch-ua-model", "Macintosh"),
                    ("sec-ch-prefers-contrast", "xx"),
                ],
                preserve_ua_header: false,
                request_authority: Authority::new(
                    Host::from_str("www.google.com").unwrap(),
                    Protocol::HTTPS.default_port().unwrap(),
                ),
                protocol: Protocol::HTTPS,
                requested_client_hints: Some(vec![
                    "Downlink",
                    "Ect",
                    "RTT",
                    "Sec-CH-UA-Arch",
                    "Sec-CH-UA-Bitness",
                    // requested but not available
                    "Sec-CH-Prefers-Reduced-Transparency",
                ]),
                expected: vec![
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ),
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    ),
                    ("Accept-Language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
                    ("Accept-Encoding", "gzip, deflate, br"),
                    ("Connection", "keep-alive"),
                    ("Upgrade-Insecure-Requests", "1"),
                    ("x-show-price", "true"),
                    ("x-show-price-currency", "USD"),
                    ("x-requested-with", "XMLHttpRequest"),
                    ("Cookie", "session=on; foo=bar"),
                    ("Sec-Fetch-Dest", "document"),
                    ("Sec-Fetch-Mode", "navigate"),
                    ("Sec-Fetch-Site", "none"),
                    ("Sec-Fetch-User", "?1"),
                    ("Sec-CH-Downlink", "100"),
                    ("Sec-CH-Ect", "4g"),
                    ("Sec-CH-RTT", "100"),
                    ("Sec-CH-UA-Arch", "arm"),
                    ("Sec-CH-UA-Bitness", "64"),
                    ("Sec-CH-UA-Mobile", "?0"), // not requested, but low entropy
                    ("Sec-CH-UA-Platform", "macOS"), // not requested, but low entropy
                    ("Sec-CH-UA-Model", "LimitedEdition"),
                    // sec-ch-prefers-contrast was requested, but UA profile doesn't contain it :)
                    ("DNT", "1"),
                    ("Sec-GPC", "1"),
                    ("Priority", "u=0, i"),
                ],
            },
        ];

        for test_case in test_cases {
            let base_http_headers =
                Http1HeaderMap::from_iter(test_case.base_http_headers.into_iter().map(
                    |(name, value)| {
                        (
                            Http1HeaderName::from_str(name).unwrap(),
                            HeaderValue::from_static(value),
                        )
                    },
                ));
            let original_http_header_order = test_case.original_http_header_order.map(|headers| {
                OriginalHttp1Headers::from_iter(
                    headers
                        .into_iter()
                        .map(|header| Http1HeaderName::from_str(header).unwrap()),
                )
            });
            let original_headers = HeaderMap::from_iter(
                test_case.original_headers.into_iter().map(|(name, value)| {
                    (
                        HeaderName::from_static(name),
                        HeaderValue::from_static(value),
                    )
                }),
            );
            let preserve_ua_header = test_case.preserve_ua_header;
            let requested_client_hints = test_case.requested_client_hints.map(|hints| {
                hints
                    .into_iter()
                    .map(|hint| ClientHint::from_str(hint).unwrap())
                    .collect::<Vec<_>>()
            });

            let output_headers = merge_http_headers(
                &base_http_headers,
                original_http_header_order,
                original_headers,
                preserve_ua_header,
                Some(Cow::Borrowed(&test_case.request_authority)),
                Some(Cow::Borrowed(&test_case.protocol)),
                None,
                requested_client_hints.as_deref(),
            );

            let output_str = output_headers
                .into_iter()
                .map(|(name, value)| format!("{}: {}\r\n", name, value.to_str().unwrap()))
                .join("");

            let expected_str = test_case
                .expected
                .iter()
                .map(|(name, value)| format!("{name}: {value}\r\n"))
                .join("");

            assert_eq!(
                output_str, expected_str,
                "test case '{}' failed",
                test_case.description
            );
        }
    }

    #[tokio::test]
    async fn test_get_base_h2_headers() {
        let ua = UserAgent::new(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );

        let ua_profile = UserAgentProfile {
            ua_kind: ua.ua_kind().unwrap(),
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: HttpProfile {
                h1: Arc::new(Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                        ws: None,
                    },
                    settings: Http1Settings::default(),
                }),
                h2: Arc::new(Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("navigate"))]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: None,
                        xhr: None,
                        form: None,
                        ws: None,
                    },
                    settings: Http2Settings::default(),
                }),
            },
            #[cfg(feature = "tls")]
            tls: crate::profile::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
                ws_client_config_overwrites: None,
            },
            runtime: None,
        };

        let ua_service = (
            UserAgentEmulateLayer::new(ua_profile),
            RequestInspectorLayer::new(UserAgentEmulateHttpRequestModifier::default()),
        )
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .map(|header| header.to_str().unwrap().to_owned())
                        .unwrap_or_default(),
                )
            }));

        let req = Request::builder()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        assert_eq!(res, "");

        let req = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_2)
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        assert_eq!(res, "navigate");
    }

    #[tokio::test]
    async fn test_get_base_http_headers_profile_with_only_navigate_headers() {
        let ua = UserAgent::new(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
        let ua_profile = UserAgentProfile {
            ua_kind: ua.ua_kind().unwrap(),
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: HttpProfile {
                h1: Arc::new(Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("navigate"))]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        xhr: None,
                        fetch: None,
                        form: None,
                        ws: None,
                    },
                    settings: Http1Settings::default(),
                }),
                h2: Arc::new(Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                        ws: None,
                    },
                    settings: Http2Settings::default(),
                }),
            },
            #[cfg(feature = "tls")]
            tls: crate::profile::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
                ws_client_config_overwrites: None,
            },
            runtime: None,
        };

        let ua_service = (
            UserAgentEmulateLayer::new(ua_profile),
            RequestInspectorLayer::new(UserAgentEmulateHttpRequestModifier::default()),
        )
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .map(|header| header.to_str().unwrap().to_owned())
                        .unwrap_or_default(),
                )
            }));

        let req = Request::builder()
            .method(Method::DELETE)
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        assert_eq!(res, "navigate");
    }

    #[tokio::test]
    async fn test_get_base_http_headers_profile_without_fetch_headers() {
        let ua = UserAgent::new(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
        let ua_profile = UserAgentProfile {
            ua_kind: ua.ua_kind().unwrap(),
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: HttpProfile {
                h1: Arc::new(Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("navigate"))]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        xhr: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("xhr"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        fetch: None,
                        form: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("form"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        ws: None,
                    },
                    settings: Http1Settings::default(),
                }),
                h2: Arc::new(Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                        ws: None,
                    },
                    settings: Http2Settings::default(),
                }),
            },
            #[cfg(feature = "tls")]
            tls: crate::profile::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
                ws_client_config_overwrites: None,
            },
            runtime: None,
        };

        let ua_service = (
            UserAgentEmulateLayer::new(ua_profile),
            RequestInspectorLayer::new(UserAgentEmulateHttpRequestModifier::default()),
        )
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .map(|header| header.to_str().unwrap().to_owned())
                        .unwrap_or_default(),
                )
            }));

        let req = Request::builder()
            .method(Method::DELETE)
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        assert_eq!(res, "xhr");
    }

    #[tokio::test]
    async fn test_get_base_http_headers_profile_without_xhr_headers() {
        let ua = UserAgent::new(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
        let ua_profile = UserAgentProfile {
            ua_kind: ua.ua_kind().unwrap(),
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: HttpProfile {
                h1: Arc::new(Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("navigate"))]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("fetch"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        xhr: None,
                        form: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("form"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        ws: None,
                    },
                    settings: Http1Settings::default(),
                }),
                h2: Arc::new(Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                        ws: None,
                    },
                    settings: Http2Settings::default(),
                }),
            },
            #[cfg(feature = "tls")]
            tls: crate::profile::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
                ws_client_config_overwrites: None,
            },
            runtime: None,
        };

        let ua_service = (
            UserAgentEmulateLayer::new(ua_profile),
            RequestInspectorLayer::new(UserAgentEmulateHttpRequestModifier::default()),
        )
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .map(|header| header.to_str().unwrap().to_owned())
                        .unwrap_or_default(),
                )
            }));

        let req = Request::builder()
            .method(Method::DELETE)
            .header(
                HeaderName::from_static("x-requested-with"),
                "XmlHttpRequest",
            )
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        assert_eq!(res, "fetch");
    }

    #[tokio::test]
    async fn test_get_base_http_headers() {
        let ua = UserAgent::new(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
        let ua_profile = UserAgentProfile {
            ua_kind: ua.ua_kind().unwrap(),
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: HttpProfile {
                h1: Arc::new(Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("navigate"))]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("fetch"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        xhr: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("xhr"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        form: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("form"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        ws: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("ws"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                    },
                    settings: Http1Settings::default(),
                }),
                h2: Arc::new(Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("navigate2"))]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("fetch2"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        xhr: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("xhr2"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        form: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("form2"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        ws: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_static("ws2"))]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                    },
                    settings: Http2Settings::default(),
                }),
            },
            #[cfg(feature = "tls")]
            tls: crate::profile::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
                ws_client_config_overwrites: None,
            },
            runtime: None,
        };

        let ua_service = (
            UserAgentEmulateLayer::new(ua_profile),
            RequestInspectorLayer::new(UserAgentEmulateHttpRequestModifier::default()),
        )
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .map(|header| header.to_str().unwrap().to_owned())
                        .unwrap_or_default(),
                )
            }));

        struct TestCase {
            description: &'static str,
            version: Option<Version>,
            method: Option<Method>,
            headers: Option<HeaderMap>,
            ctx: Option<Context<()>>,
            expected: &'static str,
        }

        let test_cases = [
            TestCase {
                description: "GET request",
                version: None,
                method: None,
                headers: None,
                ctx: None,
                expected: "navigate",
            },
            TestCase {
                description: "GET request with XRW header",
                version: None,
                method: None,
                headers: Some(
                    [(
                        HeaderName::from_static("x-requested-with"),
                        HeaderValue::from_static("XmlHttpRequest"),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ctx: None,
                expected: "xhr",
            },
            TestCase {
                description: "GET request with RequestInitiator hint Navigate",
                version: None,
                method: None,
                headers: None,
                ctx: Some({
                    let mut ctx = Context::default();
                    ctx.insert(RequestInitiator::Navigate);
                    ctx
                }),
                expected: "navigate",
            },
            TestCase {
                description: "GET request with RequestInitiator hint Form",
                version: None,
                method: None,
                headers: None,
                ctx: Some({
                    let mut ctx = Context::default();
                    ctx.insert(RequestInitiator::Form);
                    ctx
                }),
                expected: "form",
            },
            TestCase {
                description: "explicit GET request",
                version: None,
                method: Some(Method::GET),
                headers: None,
                ctx: None,
                expected: "navigate",
            },
            TestCase {
                description: "HTTP/1.1 WebSocket upgrade request",
                version: None,
                method: Some(Method::GET),
                headers: Some(
                    [(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"))]
                        .into_iter()
                        .collect(),
                ),
                ctx: None,
                expected: "ws",
            },
            TestCase {
                description: "H2 WebSocket upgrade request",
                version: Some(Version::HTTP_2),
                method: Some(Method::CONNECT),
                headers: Some(
                    [(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"))]
                        .into_iter()
                        .collect(),
                ),
                ctx: None,
                expected: "ws2",
            },
            TestCase {
                description: "explicit POST request",
                version: None,
                method: Some(Method::POST),
                headers: None,
                ctx: None,
                expected: "fetch",
            },
            TestCase {
                description: "explicit POST request with XRW header",
                version: None,
                method: Some(Method::POST),
                headers: Some(
                    [(
                        HeaderName::from_static("x-requested-with"),
                        HeaderValue::from_static("XmlHttpRequest"),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ctx: None,
                expected: "xhr",
            },
            TestCase {
                description: "explicit POST request with multipart/form-data and XRW header",
                version: None,
                method: Some(Method::POST),
                headers: Some(
                    [
                        (
                            CONTENT_TYPE,
                            HeaderValue::from_static(
                                "multipart/form-data; boundary=ExampleBoundaryString",
                            ),
                        ),
                        (
                            HeaderName::from_static("x-requested-with"),
                            HeaderValue::from_static("XmlHttpRequest"),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ctx: None,
                expected: "xhr",
            },
            TestCase {
                description: "explicit POST request with application/x-www-form-urlencoded and XRW header",
                version: None,
                method: Some(Method::POST),
                headers: Some(
                    [
                        (
                            CONTENT_TYPE,
                            HeaderValue::from_static("application/x-www-form-urlencoded"),
                        ),
                        (
                            HeaderName::from_static("x-requested-with"),
                            HeaderValue::from_static("XmlHttpRequest"),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ctx: None,
                expected: "xhr",
            },
            TestCase {
                description: "explicit POST request with multipart/form-data",
                version: None,
                method: Some(Method::POST),
                headers: Some(
                    [(
                        CONTENT_TYPE,
                        HeaderValue::from_static(
                            "multipart/form-data; boundary=ExampleBoundaryString",
                        ),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ctx: None,
                expected: "form",
            },
            TestCase {
                description: "explicit POST request with application/x-www-form-urlencoded",
                version: None,
                method: Some(Method::POST),
                headers: Some(
                    [(
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/x-www-form-urlencoded"),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ctx: None,
                expected: "form",
            },
            TestCase {
                description: "explicit DELETE request with XRW header",
                version: None,
                method: Some(Method::DELETE),
                headers: Some(
                    [(
                        HeaderName::from_static("x-requested-with"),
                        HeaderValue::from_static("XmlHttpRequest"),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ctx: None,
                expected: "xhr",
            },
            TestCase {
                description: "explicit DELETE request",
                version: None,
                method: Some(Method::DELETE),
                headers: None,
                ctx: None,
                expected: "fetch",
            },
            TestCase {
                description: "explicit DELETE request with RequestInitiator hint",
                version: None,
                method: Some(Method::DELETE),
                headers: None,
                ctx: Some({
                    let mut ctx = Context::default();
                    ctx.insert(RequestInitiator::Xhr);
                    ctx
                }),
                expected: "xhr",
            },
        ];

        for test_case in test_cases {
            let mut req = Request::builder()
                .version(test_case.version.unwrap_or(Version::HTTP_11))
                .method(test_case.method.unwrap_or(Method::GET))
                .body(Body::empty())
                .unwrap();
            if let Some(headers) = test_case.headers {
                req.headers_mut().extend(headers);
            }
            let ctx = test_case.ctx.unwrap_or_default();
            let res = ua_service.serve(ctx, req).await.unwrap();
            assert_eq!(res, test_case.expected, "{}", test_case.description);
        }
    }

    #[test]
    fn test_compute_sec_fetch_site_value() {
        #[derive(Debug)]
        struct TestCase {
            referer: Option<&'static str>,
            method: Option<Method>,
            protocol: Protocol,
            request_authority: Authority,
            expected_value: &'static str,
        }

        let test_cases = [
            TestCase {
                referer: None,
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new(Host::EXAMPLE_NAME, 80),
                expected_value: "none",
            },
            TestCase {
                referer: Some("http://example.com/foo?q=1"),
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new(Host::EXAMPLE_NAME, 80),
                expected_value: "same-origin",
            },
            TestCase {
                referer: Some("http://example.com:8080/foo?q=1"),
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new(Host::EXAMPLE_NAME, 80),
                expected_value: "same-site",
            },
            TestCase {
                referer: Some("https://example.com/foo?q=1"),
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new(Host::EXAMPLE_NAME, 80),
                expected_value: "cross-site",
            },
            TestCase {
                referer: Some("http://example.com/foo?q=1"),
                method: None,
                protocol: Protocol::HTTPS,
                request_authority: Authority::new(Host::EXAMPLE_NAME, 80),
                expected_value: "cross-site",
            },
            TestCase {
                referer: Some("http://example.be/foo?q=1"),
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new(Host::EXAMPLE_NAME, 80),
                expected_value: "cross-site",
            },
            TestCase {
                referer: Some("http://sub.example.com/foo?q=1"),
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new(Host::EXAMPLE_NAME, 80),
                expected_value: "same-site",
            },
            TestCase {
                referer: Some("http://example.com/foo?q=1"),
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new("sub.example.com".parse().unwrap(), 80),
                expected_value: "same-site",
            },
            TestCase {
                referer: Some("http://a.example.com/foo?q=1"),
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new("b.example.com".parse().unwrap(), 80),
                expected_value: "same-site",
            },
            TestCase {
                referer: Some("......."),
                method: None,
                protocol: Protocol::HTTP,
                request_authority: Authority::new("b.example.com".parse().unwrap(), 80),
                expected_value: "none",
            },
        ];

        for test_case in test_cases {
            let original_header_referer_value = test_case.referer.map(HeaderValue::from_static);
            let computed_value = compute_sec_fetch_site_value(
                original_header_referer_value.as_ref(),
                test_case.method.as_ref(),
                Some(&test_case.protocol),
                Some(&test_case.request_authority),
            );
            assert_eq!(
                computed_value.to_str().unwrap(),
                test_case.expected_value,
                "test_case: {test_case:?}",
            );
        }
    }
}
