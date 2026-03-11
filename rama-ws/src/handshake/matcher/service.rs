use std::convert::Infallible;

use rama_core::matcher::service::{ServiceMatch, ServiceMatcher};
use rama_http::{Request, Response, StatusCode};
use rama_net::proxy::IoForwardService;

#[derive(Debug, Clone)]
/// Default matcher that can be used for Http websocket relays.
///
/// Request matches for an http websocket request return
/// a [`HttpWebSocketRelayServiceResponseMatcher`] instance which
/// will match on 101 status code responses...
pub struct HttpWebSocketRelayServiceRequestMatcher<S = IoForwardService> {
    relay_svc: S,
}

impl Default for HttpWebSocketRelayServiceRequestMatcher {
    fn default() -> Self {
        Self {
            relay_svc: IoForwardService::new(),
        }
    }
}

impl<S> HttpWebSocketRelayServiceRequestMatcher<S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpWebSocketRelayServiceRequestMatcher`].
    pub fn new(relay_svc: S) -> Self {
        Self { relay_svc }
    }
}

impl<S, Body> ServiceMatcher<Request<Body>> for HttpWebSocketRelayServiceRequestMatcher<S>
where
    S: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    type Service = HttpWebSocketRelayServiceResponseMatcher<S>;
    type Error = Infallible;
    type ModifiedInput = Request<Body>;

    async fn match_service(
        &self,
        req: Request<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        Ok(ServiceMatch {
            service: super::is_http_req_websocket_handshake(&req).then(|| {
                HttpWebSocketRelayServiceResponseMatcher {
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
            service: super::is_http_req_websocket_handshake(&req).then(|| {
                HttpWebSocketRelayServiceResponseMatcher {
                    relay_svc: self.relay_svc,
                }
            }),
            input: req,
        })
    }
}

#[derive(Debug, Clone)]
/// Created by [`HttpWebSocketRelayServiceRequestMatcher`] for a valid 101 Switching Protocol response,
/// following the websocket request which started the handshake, request match.
pub struct HttpWebSocketRelayServiceResponseMatcher<S> {
    relay_svc: S,
}

impl<S, Body> ServiceMatcher<Response<Body>> for HttpWebSocketRelayServiceResponseMatcher<S>
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
            service: (res.status() == StatusCode::SWITCHING_PROTOCOLS)
                .then(|| self.relay_svc.clone()),
            input: res,
        })
    }

    async fn into_match_service(
        self,
        res: Response<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        Ok(ServiceMatch {
            service: (res.status() == StatusCode::SWITCHING_PROTOCOLS).then_some(self.relay_svc),
            input: res,
        })
    }
}
