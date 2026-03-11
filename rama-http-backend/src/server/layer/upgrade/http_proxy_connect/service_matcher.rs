use std::convert::Infallible;

use rama_core::matcher::service::{ServiceMatch, ServiceMatcher};
use rama_http::{Request, Response};
use rama_http_types::proxy::is_req_http_proxy_connect;
use rama_net::proxy::IoForwardService;

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
        Ok(ServiceMatch {
            service: is_req_http_proxy_connect(&req).then(|| {
                HttpProxyConnectRelayServiceResponseMatcher {
                    relay_svc: self.relay_svc.clone(),
                }
            }),
            input: req,
        })
    }

    async fn into_match_service(
        self,
        req: Request<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        Ok(ServiceMatch {
            service: is_req_http_proxy_connect(&req).then(|| {
                HttpProxyConnectRelayServiceResponseMatcher {
                    relay_svc: self.relay_svc,
                }
            }),
            input: req,
        })
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
        Ok(ServiceMatch {
            service: res.status().is_success().then(|| self.relay_svc.clone()),
            input: res,
        })
    }

    async fn into_match_service(
        self,
        res: Response<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        Ok(ServiceMatch {
            service: res.status().is_success().then_some(self.relay_svc),
            input: res,
        })
    }
}
