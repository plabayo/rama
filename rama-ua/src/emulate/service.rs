use std::fmt;

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, OpaqueError},
};
use rama_http_types::{
    HeaderMap, HeaderName, IntoResponse, Method, Request, Response, Version,
    compression::DecompressIfPossible,
    conn::Http1ClientContextParams,
    header::{
        ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, ORIGIN,
        REFERER, USER_AGENT,
    },
    headers::encoding::{Encoding, parse_accept_encoding_headers},
    proto::{
        h1::{
            Http1HeaderMap,
            headers::{HeaderMapValueRemover, original::OriginalHttp1Headers},
        },
        h2::PseudoHeaderOrder,
    },
};
use rama_net::{Protocol, http::RequestContext};

use crate::{
    CUSTOM_HEADER_MARKER, HttpAgent, HttpHeadersProfile, RequestInitiator, UserAgent,
    UserAgentProfile, contains_ignore_ascii_case, starts_with_ignore_ascii_case,
};

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
    S: Service<State, Request<Body>, Response: IntoResponse, Error: Into<BoxError>>,
    P: UserAgentProvider<State>,
{
    type Response = Response;
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
                    Ok(self
                        .inner
                        .serve(ctx, req)
                        .await
                        .map_err(Into::into)?
                        .into_response())
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

        let mut original_requested_encodings = None;

        if preserve_http {
            tracing::trace!(
                ua_kind = %profile.ua_kind,
                ua_version = ?profile.ua_version,
                platform = ?profile.platform,
                "user agent emulation: skip http settings as http is instructed to be preserved"
            );
        } else {
            emulate_http_settings(&mut ctx, &mut req, profile);
            match get_base_http_headers(&ctx, &req, profile) {
                Some(base_http_headers) => {
                    let original_http_header_order = get_original_http_header_order(
                        &ctx,
                        &req,
                        self.input_header_order.as_ref(),
                    )
                    .context("collect original http header order")?;

                    let original_headers = req.headers().clone();

                    let preserve_ua_header = ctx
                        .get::<UserAgent>()
                        .map(|ua| ua.preserve_ua_header())
                        .unwrap_or_default();

                    let is_secure_request = match ctx.get::<RequestContext>() {
                        Some(request_ctx) => request_ctx.protocol.is_secure(),
                        None => req
                            .uri()
                            .scheme()
                            .map(|s| Protocol::from(s.clone()).is_secure())
                            .unwrap_or_default(),
                    };

                    original_requested_encodings = Some(
                        parse_accept_encoding_headers(&original_headers, true)
                            .map(|qv| qv.value)
                            .collect::<Vec<_>>(),
                    );

                    let output_headers = merge_http_headers(
                        base_http_headers,
                        original_http_header_order,
                        original_headers,
                        preserve_ua_header,
                        is_secure_request,
                    );

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
                None => {
                    tracing::debug!(
                        "user agent emulation: no http headers to emulate: no base http headers found"
                    );
                }
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
        let mut res = self
            .inner
            .serve(ctx, req)
            .await
            .map_err(Into::into)?
            .into_response();

        if let Some(original_requested_encodings) = original_requested_encodings {
            if let Some(content_encoding) =
                Encoding::maybe_from_content_encoding_header(res.headers(), true)
            {
                if !original_requested_encodings.contains(&content_encoding) {
                    // Only request decompression if the server used a content-encoding
                    // not listed in the original request's Accept-Encoding header
                    // or because the callee didn't set this header at all.
                    res.extensions_mut().insert(DecompressIfPossible::default());
                }
            }
        }

        Ok(res)
    }
}

fn emulate_http_settings<Body, State>(
    ctx: &mut Context<State>,
    req: &mut Request<Body>,
    profile: &UserAgentProfile,
) {
    match req.version() {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
            tracing::trace!(
                ua_kind = %profile.ua_kind,
                ua_version = ?profile.ua_version,
                platform = ?profile.platform,
                "UA emulation add http1-specific settings",
            );
            ctx.insert(Http1ClientContextParams {
                title_header_case: profile.http.h1.title_case_headers,
            });
        }
        Version::HTTP_2 => {
            tracing::trace!(
            ua_kind = %profile.ua_kind,
            ua_version = ?profile.ua_version,
            platform = ?profile.platform,
            "UA emulation add h2-specific settings",
            );
            req.extensions_mut().insert(PseudoHeaderOrder::from_iter(
                profile.http.h2.http_pseudo_headers.iter(),
            ));
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
) -> Option<&'a Http1HeaderMap> {
    let headers_profile = match req.version() {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => &profile.http.h1.headers,
        Version::HTTP_2 => &profile.http.h2.headers,
        _ => {
            tracing::debug!(
                version = ?req.version(),
                "UA emulation not supported for unknown http version: not applying anything version-specific",
            );
            return None;
        }
    };
    Some(
        match ctx.get::<UserAgent>().and_then(|ua| ua.request_initiator()) {
            Some(req_init) => {
                tracing::trace!(%req_init, "base http headers defined based on hint from UserAgent (overwrite)");
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
                    } else {
                        RequestInitiator::Navigate
                    };
                    tracing::trace!(%req_init, "base http headers defined based on Get=NavigateOrXhr assumption");
                    get_base_http_headers_from_req_init(req_init, headers_profile)
                }
                Method::POST => {
                    let req_init = if headers_contains_partial_value(
                        req.headers(),
                        &X_REQUESTED_WITH,
                        "XmlHttpRequest",
                    ) {
                        RequestInitiator::Xhr
                    } else if headers_contains_partial_value(req.headers(), &CONTENT_TYPE, "form-")
                    {
                        RequestInitiator::Form
                    } else {
                        RequestInitiator::Fetch
                    };
                    tracing::trace!(%req_init, "base http headers defined based on Post=FormOrFetch assumption");
                    get_base_http_headers_from_req_init(req_init, headers_profile)
                }
                _ => {
                    let req_init = if headers_contains_partial_value(
                        req.headers(),
                        &X_REQUESTED_WITH,
                        "XmlHttpRequest",
                    ) {
                        RequestInitiator::Xhr
                    } else {
                        RequestInitiator::Fetch
                    };
                    tracing::trace!(%req_init, "base http headers defined based on XhrOrFetch assumption");
                    get_base_http_headers_from_req_init(req_init, headers_profile)
                }
            },
        },
    )
}

static X_REQUESTED_WITH: HeaderName = HeaderName::from_static("x-requested-with");

fn headers_contains_partial_value(headers: &HeaderMap, name: &HeaderName, value: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|s| contains_ignore_ascii_case(s, value).is_some())
        .unwrap_or_default()
}

fn get_base_http_headers_from_req_init(
    req_init: RequestInitiator,
    headers: &HttpHeadersProfile,
) -> &Http1HeaderMap {
    match req_init {
        RequestInitiator::Navigate => &headers.navigate,
        RequestInitiator::Form => headers.form.as_ref().unwrap_or(&headers.navigate),
        RequestInitiator::Xhr => headers
            .xhr
            .as_ref()
            .or(headers.fetch.as_ref())
            .unwrap_or(&headers.navigate),
        RequestInitiator::Fetch => headers
            .fetch
            .as_ref()
            .or(headers.xhr.as_ref())
            .unwrap_or(&headers.navigate),
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
    is_secure_request: bool,
) -> Http1HeaderMap {
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
            &REFERER | &COOKIE | &AUTHORIZATION | &HOST | &ORIGIN | &CONTENT_LENGTH => {
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
                } else if starts_with_ignore_ascii_case(base_header_name.as_str(), "sec-fetch") {
                    if is_secure_request {
                        output_headers_ref.push((base_name, base_value));
                    }
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

    Http1HeaderMap::from_iter(
        output_headers_a
            .into_iter()
            .chain(original_headers) // add all remaining original headers in any order within the right loc
            .chain(output_headers_b),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{convert::Infallible, str::FromStr};

    use itertools::Itertools as _;
    use rama_core::service::service_fn;
    use rama_http_types::{
        Body, BodyExtractExt, HeaderValue, header::ETAG, proto::h1::Http1HeaderName,
    };

    use crate::{Http1Profile, Http2Profile, HttpHeadersProfile, HttpProfile};

    #[test]
    fn test_merge_http_headers() {
        struct TestCase {
            description: &'static str,
            base_http_headers: Vec<(&'static str, &'static str)>,
            original_http_header_order: Option<Vec<&'static str>>,
            original_headers: Vec<(&'static str, &'static str)>,
            preserve_ua_header: bool,
            is_secure_request: bool,
            expected: Vec<(&'static str, &'static str)>,
        }

        let test_cases = [
            TestCase {
                description: "empty",
                base_http_headers: vec![],
                original_http_header_order: None,
                original_headers: vec![],
                preserve_ua_header: false,
                is_secure_request: false,
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
                is_secure_request: false,
                expected: vec![
                    ("Accept", "text/html"),
                    ("Content-Type", "application/json"),
                ],
            },
            TestCase {
                description: "original headers only",
                base_http_headers: vec![],
                original_http_header_order: None,
                original_headers: vec![("accept", "text/html")],
                preserve_ua_header: false,
                is_secure_request: false,
                expected: vec![("accept", "text/html")],
            },
            TestCase {
                description: "original and base headers, no conflicts",
                base_http_headers: vec![("accept", "text/html"), ("user-agent", "python/3.10")],
                original_http_header_order: None,
                original_headers: vec![("content-type", "application/json")],
                preserve_ua_header: false,
                is_secure_request: false,
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
                is_secure_request: false,
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
                is_secure_request: false,
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
                is_secure_request: false,
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
                is_secure_request: false,
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
                is_secure_request: false,
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
                is_secure_request: false,
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
                is_secure_request: false,
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
                is_secure_request: true,
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
                    ("Sec-Fetch-Site", "cross-site"),
                    ("Sec-Fetch-User", "?1"),
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
            let is_secure_request = test_case.is_secure_request;

            let output_headers = merge_http_headers(
                &base_http_headers,
                original_http_header_order,
                original_headers,
                preserve_ua_header,
                is_secure_request,
            );

            let output_str = output_headers
                .into_iter()
                .map(|(name, value)| format!("{}: {}\r\n", name, value.to_str().unwrap()))
                .join("");

            let expected_str = test_case
                .expected
                .iter()
                .map(|(name, value)| format!("{}: {}\r\n", name, value))
                .join("");

            assert_eq!(
                output_str, expected_str,
                "test case '{}' failed",
                test_case.description
            );
        }
    }

    #[test]
    fn test_get_original_http_header_order() {
        struct TestCase {
            description: &'static str,
            req: Request,
            ctx: Option<Context<()>>,
            expected_input_header_order: &'static str,
        }

        let test_cases = [
            TestCase {
                description: "empty request",
                req: Request::new(Body::empty()),
                ctx: None,
                expected_input_header_order: "",
            },
            TestCase {
                description: "request original header order in req extensions",
                req: {
                    let mut req = Request::new(Body::empty());
                    req.extensions_mut()
                        .insert(OriginalHttp1Headers::from_iter([
                            Http1HeaderName::from_str("x-REQUESTED-with").unwrap(),
                            Http1HeaderName::from_str("Accept").unwrap(),
                        ]));
                    req
                },
                ctx: None,
                expected_input_header_order: "x-REQUESTED-with,Accept",
            },
            TestCase {
                description: "request original header order in ctx",
                req: {
                    let mut req = Request::new(Body::empty());
                    req.headers_mut().insert(
                        HeaderName::from_static("foo"),
                        HeaderValue::from_static("BAR"),
                    );
                    req
                },
                // ctx has precedence over req extensions
                ctx: Some({
                    let mut ctx = Context::default();
                    ctx.insert(OriginalHttp1Headers::from_iter([
                        Http1HeaderName::from_str("x-REQUESTED-with").unwrap(),
                        Http1HeaderName::from_str("Accept").unwrap(),
                    ]));
                    ctx
                }),
                expected_input_header_order: "x-REQUESTED-with,Accept",
            },
            TestCase {
                description: "request with headers but no original header order",
                req: {
                    let mut req = Request::new(Body::empty());
                    req.headers_mut().insert(
                        HeaderName::from_static("foo"),
                        HeaderValue::from_static("BAR"),
                    );
                    req
                },
                ctx: None,
                expected_input_header_order: "",
            },
        ];

        for test_case in test_cases {
            let input_header_order = get_original_http_header_order(
                test_case.ctx.as_ref().unwrap_or(&Context::default()),
                &test_case.req,
                None,
            )
            .unwrap();
            let input_header_order_str = input_header_order
                .map(|headers| {
                    headers
                        .into_iter()
                        .map(|header| header.to_string())
                        .join(",")
                })
                .unwrap_or_default();
            assert_eq!(
                input_header_order_str, test_case.expected_input_header_order,
                "{}",
                test_case.description,
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
                h1: Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                    },
                    title_case_headers: false,
                },
                h2: Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("navigate").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: None,
                        xhr: None,
                        form: None,
                    },
                    http_pseudo_headers: vec![],
                },
            },
            #[cfg(feature = "tls")]
            tls: crate::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
            },
        };

        let ua_service = UserAgentEmulateService::new(
            service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .map(|header| header.to_str().unwrap().to_owned())
                        .unwrap_or_default(),
                )
            }),
            ua_profile,
        );

        let req = Request::builder()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        let body = res.into_body().try_into_string().await.unwrap();
        assert_eq!(body, "");

        let req = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_2)
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        let body = res.into_body().try_into_string().await.unwrap();
        assert_eq!(body, "navigate");
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
                h1: Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("navigate").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        xhr: None,
                        fetch: None,
                        form: None,
                    },
                    title_case_headers: false,
                },
                h2: Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                    },
                    http_pseudo_headers: vec![],
                },
            },
            #[cfg(feature = "tls")]
            tls: crate::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
            },
        };

        let ua_service = UserAgentEmulateService::new(
            service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                )
            }),
            ua_profile,
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        let body = res.into_body().try_into_string().await.unwrap();
        assert_eq!(body, "navigate");
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
                h1: Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("navigate").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        xhr: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("xhr").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        fetch: None,
                        form: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("form").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                    },
                    title_case_headers: false,
                },
                h2: Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                    },
                    http_pseudo_headers: vec![],
                },
            },
            #[cfg(feature = "tls")]
            tls: crate::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
            },
        };

        let ua_service = UserAgentEmulateService::new(
            service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                )
            }),
            ua_profile,
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        let body = res.into_body().try_into_string().await.unwrap();
        assert_eq!(body, "xhr");
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
                h1: Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("navigate").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("fetch").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        xhr: None,
                        form: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("form").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                    },
                    title_case_headers: false,
                },
                h2: Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                    },
                    http_pseudo_headers: vec![],
                },
            },
            #[cfg(feature = "tls")]
            tls: crate::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
            },
        };

        let ua_service = UserAgentEmulateService::new(
            service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                )
            }),
            ua_profile,
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .header(
                HeaderName::from_static("x-requested-with"),
                "XmlHttpRequest",
            )
            .body(Body::empty())
            .unwrap();
        let res = ua_service.serve(Context::default(), req).await.unwrap();
        let body = res.into_body().try_into_string().await.unwrap();
        assert_eq!(body, "fetch");
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
                h1: Http1Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("navigate").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("fetch").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        xhr: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("xhr").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                        form: Some(Http1HeaderMap::new(
                            [(ETAG, HeaderValue::from_str("form").unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        )),
                    },
                    title_case_headers: false,
                },
                h2: Http2Profile {
                    headers: HttpHeadersProfile {
                        navigate: Http1HeaderMap::default(),
                        fetch: None,
                        xhr: None,
                        form: None,
                    },
                    http_pseudo_headers: vec![],
                },
            },
            #[cfg(feature = "tls")]
            tls: crate::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
            },
        };

        let ua_service = UserAgentEmulateService::new(
            service_fn(async |req: Request| {
                Ok::<_, Infallible>(
                    req.headers()
                        .get(ETAG)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                )
            }),
            ua_profile,
        );

        struct TestCase {
            description: &'static str,
            method: Option<Method>,
            headers: Option<HeaderMap>,
            ctx: Option<Context<()>>,
            expected: &'static str,
        }

        let test_cases = [
            TestCase {
                description: "GET request",
                method: None,
                headers: None,
                ctx: None,
                expected: "navigate",
            },
            TestCase {
                description: "GET request with XRW header",
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
                method: None,
                headers: None,
                ctx: Some({
                    let mut ctx = Context::default();
                    ctx.insert(
                        UserAgent::new("").with_request_initiator(RequestInitiator::Navigate),
                    );
                    ctx
                }),
                expected: "navigate",
            },
            TestCase {
                description: "GET request with RequestInitiator hint Form",
                method: None,
                headers: None,
                ctx: Some({
                    let mut ctx = Context::default();
                    ctx.insert(UserAgent::new("").with_request_initiator(RequestInitiator::Form));
                    ctx
                }),
                expected: "form",
            },
            TestCase {
                description: "explicit GET request",
                method: Some(Method::GET),
                headers: None,
                ctx: None,
                expected: "navigate",
            },
            TestCase {
                description: "explicit POST request",
                method: Some(Method::POST),
                headers: None,
                ctx: None,
                expected: "fetch",
            },
            TestCase {
                description: "explicit POST request with XRW header",
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
                method: Some(Method::DELETE),
                headers: None,
                ctx: None,
                expected: "fetch",
            },
            TestCase {
                description: "explicit DELETE request with RequestInitiator hint",
                method: Some(Method::DELETE),
                headers: None,
                ctx: Some({
                    let mut ctx = Context::default();
                    ctx.insert(UserAgent::new("").with_request_initiator(RequestInitiator::Xhr));
                    ctx
                }),
                expected: "xhr",
            },
        ];

        for test_case in test_cases {
            let mut req = Request::builder()
                .method(test_case.method.unwrap_or(Method::GET))
                .body(Body::empty())
                .unwrap();
            if let Some(headers) = test_case.headers {
                req.headers_mut().extend(headers);
            }
            let ctx = test_case.ctx.unwrap_or_default();
            let res = ua_service.serve(ctx, req).await.unwrap();
            let body = res.into_body().try_into_string().await.unwrap();
            assert_eq!(body, test_case.expected, "{}", test_case.description);
        }
    }
}
