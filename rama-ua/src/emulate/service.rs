use std::fmt;

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, OpaqueError},
};
use rama_http_types::{
    HeaderMap, HeaderName, Method, Request, Version,
    conn::Http1ClientContextParams,
    header::{ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION, CONTENT_TYPE, COOKIE, REFERER, USER_AGENT},
    proto::{
        h1::{
            Http1HeaderMap,
            headers::{HeaderMapValueRemover, original::OriginalHttp1Headers},
        },
        h2::PseudoHeaderOrder,
    },
};
use rama_utils::macros::match_ignore_ascii_case_str;

use crate::{CUSTOM_HEADER_MARKER, HttpAgent, RequestInitiator, UserAgent, UserAgentProfile};

use super::{UserAgentProvider, UserAgentSelectFallback};

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
                        ua_str = %ua_str,
                        %user_agent,
                        "user agent auto-detected from request"
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

        let profile = match self.provider.select_user_agent_profile(&ctx) {
            Some(profile) => profile,
            None => {
                return if self.optional {
                    self.inner.serve(ctx, req).await.map_err(Into::into)
                } else {
                    Err(OpaqueError::from_display(
                        "requirement not fulfilled: user agent profile could not be selected",
                    )
                    .into_boxed())
                };
            }
        };

        tracing::debug!(
            ua_kind = %profile.ua_kind,
            ua_version = ?profile.ua_version,
            platform = ?profile.platform,
            "user agent profile selected for emulation"
        );

        let preserve_http = matches!(
            ctx.get::<UserAgent>().and_then(|ua| ua.http_agent()),
            Some(HttpAgent::Preserve),
        );

        if preserve_http {
            tracing::trace!(
                ua_kind = %profile.ua_kind,
                ua_version = ?profile.ua_version,
                platform = ?profile.platform,
                "user agent emulation: skip http settings as http is instructed to be preserved"
            );
        } else {
            emulate_http_settings(&mut ctx, &mut req, profile);
            let base_http_headers = get_base_http_headers(&ctx, &req, profile);
            let original_http_header_order =
                get_original_http_header_order(&ctx, &req, self.input_header_order.as_ref())
                    .context("collect original http header order")?;

            let original_headers = req.headers().clone();

            let preserve_ua_header = ctx
                .get::<UserAgent>()
                .map(|ua| ua.preserve_ua_header())
                .unwrap_or_default();

            let output_headers = merge_http_headers(
                base_http_headers,
                original_http_header_order,
                original_headers,
                preserve_ua_header,
            )?;

            tracing::trace!(
                ua_kind = %profile.ua_kind,
                ua_version = ?profile.ua_version,
                platform = ?profile.platform,
                "user agent emulation: http settings and headers emulated"
            );
            let (output_headers, original_headers) = output_headers.into_parts();
            *req.headers_mut() = output_headers;
            req.extensions_mut().insert(original_headers);
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
                    ua_kind = %profile.ua_kind,
                    ua_version = ?profile.ua_version,
                    platform = ?profile.platform,
                    "user agent emulation: skip tls settings as http is instructed to be preserved"
                );
            } else {
                // client_config's Arc is to be lazilly cloned by a tls connector
                // only when a connection is to be made, as to play nicely
                // with concepts such as connection pooling
                ctx.insert(profile.tls.client_config.clone());
            }
        }

        // serve emulated http(s) request via inner service
        self.inner.serve(ctx, req).await.map_err(Into::into)
    }
}

fn emulate_http_settings<Body, State>(
    ctx: &mut Context<State>,
    req: &mut Request<Body>,
    profile: &UserAgentProfile,
) {
    match req.version() {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
            if let Some(h1) = &profile.http.h1 {
                tracing::trace!(
                    ua_kind = %profile.ua_kind,
                    ua_version = ?profile.ua_version,
                    platform = ?profile.platform,
                    "UA emulation add http1-specific settings",
                );
                ctx.insert(Http1ClientContextParams {
                    title_header_case: h1.title_case_headers,
                });
            }
        }
        Version::HTTP_2 => {
            if let Some(h2) = &profile.http.h2 {
                tracing::trace!(
                    ua_kind = %profile.ua_kind,
                    ua_version = ?profile.ua_version,
                    platform = ?profile.platform,
                    "UA emulation add h2-specific settings",
                );
                req.extensions_mut()
                    .insert(PseudoHeaderOrder::from_iter(h2.http_pseudo_headers.iter()));
            }
        }
        Version::HTTP_3 => tracing::debug!(
            "UA emulation not yet supported for h3: not applying anything h3-specific"
        ),
        _ => tracing::debug!(
            version = ?req.version(),
            "UA emulation not supported for unknown http version: not applying anything version-specific",
        ),
    }
}

fn get_base_http_headers<'a, Body, State>(
    ctx: &Context<State>,
    req: &Request<Body>,
    profile: &'a UserAgentProfile,
) -> &'a Http1HeaderMap {
    match ctx
        .get::<RequestInitiator>()
        .copied()
        .or_else(|| ctx.get::<UserAgent>().and_then(|ua| ua.request_initiator()))
    {
        Some(req_init) => {
            tracing::trace!(%req_init, "base http headers defined based on hint from UserAgent (overwrite)");
            get_base_http_headers_from_req_init(req_init, profile)
        }
        // NOTE: the primitive checks below are pretty bad,
        // feel free to help improve. Just need to make sure it has good enough fallbacks,
        // and that they are cheap enough to check.
        None => match *req.method() {
            Method::GET => {
                tracing::trace!("base http headers defined based on Get=Navigate assumption");
                &profile.http.headers.navigate
            }
            Method::POST => {
                let req_init = req
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|ct| ct.to_str().ok())
                    .and_then(|s| {
                        match_ignore_ascii_case_str! {
                            match (s) {
                                "form-" => Some(RequestInitiator::Form),
                                _ => None,
                            }
                        }
                    })
                    .unwrap_or(RequestInitiator::Fetch);
                tracing::trace!(%req_init, "base http headers defined based on Post=FormOrFetch assumption");
                get_base_http_headers_from_req_init(req_init, profile)
            }
            _ => {
                let req_init = req
                    .headers()
                    .get(HeaderName::from_static("x-requested-with"))
                    .and_then(|ct| ct.to_str().ok())
                    .and_then(|s| {
                        match_ignore_ascii_case_str! {
                            match (s) {
                                "XmlHttpRequest" => Some(RequestInitiator::Xhr),
                                _ => None,
                            }
                        }
                    })
                    .unwrap_or(RequestInitiator::Fetch);
                tracing::trace!(%req_init, "base http headers defined based on XhrOrFetch assumption");
                get_base_http_headers_from_req_init(req_init, profile)
            }
        },
    }
}

fn get_base_http_headers_from_req_init(
    req_init: RequestInitiator,
    profile: &UserAgentProfile,
) -> &Http1HeaderMap {
    match req_init {
        RequestInitiator::Navigate => &profile.http.headers.navigate,
        RequestInitiator::Form => profile
            .http
            .headers
            .form
            .as_ref()
            .unwrap_or(&profile.http.headers.navigate),
        RequestInitiator::Xhr => profile
            .http
            .headers
            .xhr
            .as_ref()
            .or(profile.http.headers.fetch.as_ref())
            .unwrap_or(&profile.http.headers.navigate),
        RequestInitiator::Fetch => profile
            .http
            .headers
            .fetch
            .as_ref()
            .or(profile.http.headers.xhr.as_ref())
            .unwrap_or(&profile.http.headers.navigate),
    }
}

fn get_original_http_header_order<Body, State>(
    ctx: &Context<State>,
    req: &Request<Body>,
    input_header_order: Option<&HeaderName>,
) -> Result<Option<OriginalHttp1Headers>, OpaqueError> {
    if let Some(header) = input_header_order.and_then(|name| req.headers().get(name)) {
        let s = header.to_str().context("interpret header as a utf-8 str")?;
        let mut headers = OriginalHttp1Headers::with_capacity(s.matches(',').count());
        for s in s.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            headers.push(s.parse().context("parse header part as h1 headern name")?);
        }
        return Ok(Some(headers));
    }
    Ok(ctx.get().or_else(|| req.extensions().get()).cloned())
}

fn merge_http_headers(
    base_http_headers: &Http1HeaderMap,
    original_http_header_order: Option<OriginalHttp1Headers>,
    original_headers: HeaderMap,
    preserve_ua_header: bool,
) -> Result<Http1HeaderMap, OpaqueError> {
    let mut original_headers = HeaderMapValueRemover::from(original_headers);

    let mut output_headers_a = Vec::new();
    let mut output_headers_b = Vec::new();

    let mut output_headers_ref = &mut output_headers_a;

    // put all "base" headers in correct order, and with proper name casing
    for (base_name, base_value) in base_http_headers.clone().into_iter() {
        let base_header_name = base_name.header_name();
        let original_value = original_headers.remove(base_header_name);
        match base_header_name {
            &ACCEPT | &ACCEPT_LANGUAGE | &CONTENT_TYPE => {
                let value = original_value.unwrap_or(base_value);
                output_headers_ref.push((base_name, value));
            }
            &REFERER | &COOKIE | &AUTHORIZATION => {
                if let Some(value) = original_value {
                    output_headers_ref.push((base_name, value));
                }
            }
            &USER_AGENT => {
                if preserve_ua_header {
                    output_headers_ref.push((base_name, base_value));
                } else {
                    let value = original_value.unwrap_or(base_value);
                    output_headers_ref.push((base_name, value));
                }
            }
            _ => {
                if base_header_name == CUSTOM_HEADER_MARKER {
                    output_headers_ref = &mut output_headers_b;
                } else {
                    output_headers_ref.push((base_name, base_value));
                }
            }
        }
    }

    // respect original header order of original headers where possible
    for header_name in original_http_header_order.into_iter().flatten() {
        if let Some(value) = original_headers.remove(header_name.header_name()) {
            output_headers_a.push((header_name, value));
        }
    }

    Ok(Http1HeaderMap::from_iter(
        output_headers_a
            .into_iter()
            .chain(original_headers) // add all remaining original headers in any order within the right loc
            .chain(output_headers_b),
    ))
}

// TODO: test:
// - get_base_http_headers
// - get_original_http_header_order
// - merge_http_headers
