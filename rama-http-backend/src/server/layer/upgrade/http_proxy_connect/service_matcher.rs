use std::convert::Infallible;

use rama_core::{
    extensions::ExtensionsRef,
    matcher::service::{ServiceMatch, ServiceMatcher},
    telemetry::tracing,
};
use rama_http::{Request, Response};
use rama_http_types::proxy::is_req_http_proxy_connect;
use rama_net::{
    proxy::{IoForwardService, ProxyTarget},
    user::{ProxyCredential, credentials::DpiProxyCredential},
};

#[derive(Debug, Clone)]
/// Default matcher that can be used for Http proxy connects.
///
/// Request matches for an http proxy connect request return
/// a [`HttpProxyConnectRelayServiceResponseMatcher`] instance which
/// will match on any success responses...
pub struct HttpProxyConnectRelayServiceRequestMatcher<S = IoForwardService> {
    relay_svc: S,
}

impl Default for HttpProxyConnectRelayServiceRequestMatcher {
    fn default() -> Self {
        Self {
            relay_svc: IoForwardService::new(),
        }
    }
}

impl<S> HttpProxyConnectRelayServiceRequestMatcher<S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpProxyConnectRelayServiceRequestMatcher`].
    pub fn new(relay_svc: S) -> Self {
        Self { relay_svc }
    }
}

impl<S, Body> ServiceMatcher<Request<Body>> for HttpProxyConnectRelayServiceRequestMatcher<S>
where
    S: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    type Service = HttpProxyConnectRelayServiceResponseMatcher<S>;
    type Error = Infallible;
    type ModifiedInput = Request<Body>;

    async fn match_service(
        &self,
        req: Request<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        let Self { relay_svc } = self;

        let mut svc_match = ServiceMatch {
            service: None,
            input: req,
        };

        if !is_req_http_proxy_connect(&svc_match.input) {
            tracing::debug!(
                "no req http proxy connect match: target = {:?}; http version = {:?}; method = {:?}; uri = {:?}",
                svc_match.input.extensions().get::<ProxyTarget>(),
                svc_match.input.version(),
                svc_match.input.method(),
                svc_match.input.uri(),
            );
            return Ok(svc_match);
        }

        tracing::debug!(
            "http proxy connect match: target = {:?}; http version = {:?}; method = {:?}; uri = {:?}",
            svc_match.input.extensions().get::<ProxyTarget>(),
            svc_match.input.version(),
            svc_match.input.method(),
            svc_match.input.uri(),
        );

        svc_match.service = Some(HttpProxyConnectRelayServiceResponseMatcher {
            relay_svc: relay_svc.clone(),
        });

        Ok(svc_match)
    }

    async fn into_match_service(
        self,
        req: Request<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        let Self { relay_svc } = self;

        let mut svc_match = ServiceMatch {
            service: None,
            input: req,
        };

        if !is_req_http_proxy_connect(&svc_match.input) {
            tracing::debug!(
                "no req http proxy connect match: target = {:?}; http version = {:?}; method = {:?}; uri = {:?}",
                svc_match.input.extensions().get::<ProxyTarget>(),
                svc_match.input.version(),
                svc_match.input.method(),
                svc_match.input.uri(),
            );
            return Ok(svc_match);
        }

        tracing::debug!(
            "http proxy connect match: target = {:?}; http version = {:?}; method = {:?}; uri = {:?}",
            svc_match.input.extensions().get::<ProxyTarget>(),
            svc_match.input.version(),
            svc_match.input.method(),
            svc_match.input.uri(),
        );

        svc_match.service = Some(HttpProxyConnectRelayServiceResponseMatcher { relay_svc });

        Ok(svc_match)
    }
}

#[derive(Debug, Clone)]
/// Created by [`HttpProxyConnectRelayServiceRequestMatcher`] for a valid http proxy connect
/// request match, this response matcher half ensures the returned status code is successfull.
pub struct HttpProxyConnectRelayServiceResponseMatcher<S> {
    relay_svc: S,
}

impl<S, Body> ServiceMatcher<Response<Body>> for HttpProxyConnectRelayServiceResponseMatcher<S>
where
    S: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    type Service = S;
    type Error = Infallible;
    type ModifiedInput = Response<Body>;

    async fn match_service(
        &self,
        res: Response<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        let Self { relay_svc } = self;

        let mut svc_match = ServiceMatch {
            service: None,
            input: res,
        };

        if !svc_match.input.status().is_success() {
            tracing::debug!(
                "no res http proxy connect match: target = {:?}; http version = {:?}",
                svc_match.input.extensions().get::<ProxyTarget>(),
                svc_match.input.version(),
            );
            return Ok(svc_match);
        }

        let proxy_target = svc_match.input.extensions().get::<ProxyTarget>();
        let proxy_credential_info =
            svc_match
                .input
                .extensions()
                .get()
                .map(|DpiProxyCredential(c)| match c {
                    ProxyCredential::Basic(user_pass) => ("basic", user_pass.username()),
                    ProxyCredential::Bearer(_) => ("bearer", "***"),
                });
        tracing::debug!(
            "response matched by (HTTP) proxy request: proxy target = {proxy_target:?}; credials = {proxy_credential_info:?}"
        );

        svc_match.service = Some(relay_svc.clone());

        Ok(svc_match)
    }

    async fn into_match_service(
        self,
        res: Response<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        let Self { relay_svc } = self;

        let mut svc_match = ServiceMatch {
            service: None,
            input: res,
        };

        if !svc_match.input.status().is_success() {
            tracing::debug!(
                "no res http proxy connect match: target = {:?}; http version = {:?}",
                svc_match.input.extensions().get::<ProxyTarget>(),
                svc_match.input.version(),
            );
            return Ok(svc_match);
        }

        let proxy_target = svc_match.input.extensions().get::<ProxyTarget>();
        let proxy_credential_info =
            svc_match
                .input
                .extensions()
                .get()
                .map(|DpiProxyCredential(c)| match c {
                    ProxyCredential::Basic(user_pass) => ("basic", user_pass.username()),
                    ProxyCredential::Bearer(_) => ("bearer", "***"),
                });
        tracing::debug!(
            "response matched by (HTTP) proxy request: proxy target = {proxy_target:?}; credials = {proxy_credential_info:?}"
        );

        svc_match.service = Some(relay_svc);

        Ok(svc_match)
    }
}
