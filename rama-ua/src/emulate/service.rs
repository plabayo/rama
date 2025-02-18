use std::fmt;

use rama_core::{
    error::{BoxError, OpaqueError},
    Context, Service,
};
use rama_http_types::{
    conn::Http1ClientContextParams,
    header::CONTENT_TYPE,
    proto::{h1::Http1HeaderMap, h2::PseudoHeaderOrder},
    HeaderName, Method, Request, Version,
};
use rama_utils::macros::match_ignore_ascii_case_str;

use crate::{HttpAgent, RequestInitiator, UserAgent, UserAgentProfile};

use super::{UserAgentProvider, UserAgentSelectFallback};

pub struct UserAgentEmulateService<S, P> {
    inner: S,
    provider: P,
    optional: bool,
    select_fallback: Option<UserAgentSelectFallback>,
}

impl<S: fmt::Debug, P: fmt::Debug> fmt::Debug for UserAgentEmulateService<S, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAgentEmulateService")
            .field("inner", &self.inner)
            .field("provider", &self.provider)
            .field("optional", &self.optional)
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
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(fallback) = self.select_fallback {
            ctx.insert(fallback);
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
            emulate_http_settings(&mut ctx, &req, profile);
            let _base_http_headers = get_base_http_headers(&ctx, &req, profile);

            // TODO: merge base headers with incoming headers... allowing some to overwrite, others not...
            // also allowing anyway to overwrite if something is set...
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
    req: &Request<Body>,
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
            ctx.insert(PseudoHeaderOrder::from_iter(
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
