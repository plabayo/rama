use std::{convert::Infallible, sync::Arc};

use rama_core::{
    extensions::ExtensionsMut,
    matcher::service::{ServiceMatch, ServiceMatcher},
    telemetry::tracing,
};
use rama_http::{Request, Response, StatusCode, Version, request, response};
use rama_net::proxy::IoForwardService;

use crate::protocol::WebSocketConfig;

#[derive(Debug, Clone)]
/// Default matcher that can be used for Http websocket relays.
///
/// Request matches for an http websocket request return
/// a [`HttpWebSocketRelayServiceResponseMatcher`] instance which
/// will match on 101 status code responses...
///
/// ## Note
///
/// This matcher does NOT validate if client <-> server
/// handshake flow is compatible with one another. This in contrast
/// to Rama's pure client / server implementations,
/// the MITM flow typically should not botter with that, given there
/// are always those odd balls out there which have RFC
/// incompatible definitions of reality. Fork this file if you
/// have more advanced needs... or feel free to make a proposal
/// on improvements to this file while still respecting its spirit.
pub struct HttpWebSocketRelayServiceRequestMatcher<S = IoForwardService> {
    relay_svc: S,
    websocket_config: Option<WebSocketConfig>,
    store_handshake_req_header: bool,
    store_handshake_res_header: bool,
}

#[derive(Debug, Clone)]
/// Stored in the Ingress extensions
/// by the [`HttpWebSocketRelayServiceRequestMatcher`] if configured to do so.
pub struct HttpWebSocketRelayHandshakeRequest(pub Arc<request::Parts>);

#[derive(Debug, Clone)]
/// Stored in the Egress extensions
/// by the [`HttpWebSocketRelayServiceResponseMatcher`] if configured to do so.
pub struct HttpWebSocketRelayHandshakeResponse(pub Arc<response::Parts>);

impl Default for HttpWebSocketRelayServiceRequestMatcher {
    fn default() -> Self {
        Self {
            relay_svc: IoForwardService::new(),
            websocket_config: None,
            store_handshake_req_header: false,
            store_handshake_res_header: false,
        }
    }
}

impl<S> HttpWebSocketRelayServiceRequestMatcher<S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpWebSocketRelayServiceRequestMatcher`].
    pub fn new(relay_svc: S) -> Self {
        Self {
            relay_svc,
            websocket_config: None,
            store_handshake_req_header: false,
            store_handshake_res_header: false,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the base [`WebSocketConfig`], used for both sides,
        /// overwriting the previous config if already set.
        pub fn websocket_config(mut self, cfg: Option<WebSocketConfig>) -> Self {
            self.websocket_config = cfg;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define if the handshake (http) request headers needs to be stored
        /// in the Ingress Io extensions.
        ///
        /// By default it is not stored.
        ///
        /// ## Note
        ///
        /// It is only stored if requested AND the request is matched.
        pub fn store_handshake_request_header(mut self, store: bool) -> Self {
            self.store_handshake_req_header = store;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define if the handshake (http) response headers needs to be stored
        /// in the Ingress Io extensions.
        ///
        /// By default it is not stored.
        ///
        /// ## Note
        ///
        /// It is only stored if requested AND the response is matched.
        pub fn store_handshake_response_header(mut self, store: bool) -> Self {
            self.store_handshake_res_header = store;
            self
        }
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
        let Self {
            relay_svc,
            websocket_config,
            store_handshake_req_header,
            store_handshake_res_header,
        } = self;

        let mut svc_match = ServiceMatch {
            service: None,
            input: req,
        };

        if !super::is_http_req_websocket_handshake(&svc_match.input) {
            return Ok(svc_match);
        }

        if *store_handshake_req_header {
            let head = svc_match.input.clone_parts();
            svc_match
                .input
                .extensions_mut()
                .insert(HttpWebSocketRelayHandshakeRequest(head.into()));
        }

        svc_match.service = Some(HttpWebSocketRelayServiceResponseMatcher {
            relay_svc: relay_svc.clone(),
            websocket_config: *websocket_config,
            store_handshake_res_header: *store_handshake_res_header,
        });

        Ok(svc_match)
    }

    async fn into_match_service(
        self,
        req: Request<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        let Self {
            relay_svc,
            websocket_config,
            store_handshake_req_header,
            store_handshake_res_header,
        } = self;

        let mut svc_match = ServiceMatch {
            service: None,
            input: req,
        };

        if !super::is_http_req_websocket_handshake(&svc_match.input) {
            return Ok(svc_match);
        }

        if store_handshake_req_header {
            let head = svc_match.input.clone_parts();
            svc_match
                .input
                .extensions_mut()
                .insert(HttpWebSocketRelayHandshakeRequest(head.into()));
        }

        svc_match.service = Some(HttpWebSocketRelayServiceResponseMatcher {
            relay_svc,
            websocket_config,
            store_handshake_res_header,
        });

        Ok(svc_match)
    }
}

#[derive(Debug, Clone)]
/// Created by [`HttpWebSocketRelayServiceRequestMatcher`] for a valid 101 Switching Protocol response,
/// following the websocket request which started the handshake, request match.
pub struct HttpWebSocketRelayServiceResponseMatcher<S> {
    relay_svc: S,
    websocket_config: Option<WebSocketConfig>,
    store_handshake_res_header: bool,
}

#[derive(Debug, Clone)]
/// A [`WebSocketConfig`] extracted as part of the handshake phase prior to the relay...
pub struct RelayWebSocketConfig(pub WebSocketConfig);

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
        let Self {
            relay_svc,
            websocket_config,
            store_handshake_res_header,
        } = self;

        let mut svc_match = ServiceMatch {
            service: None,
            input: res,
        };

        let http_version = svc_match.input.version();
        let http_status = svc_match.input.status();

        match (http_version, http_status) {
            (Version::HTTP_10 | Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS)
            | (Version::HTTP_2, StatusCode::OK) => (),
            _ => {
                tracing::debug!(?http_version, ?http_status, "WS response failed to match");
                return Ok(svc_match);
            }
        }

        if *store_handshake_res_header {
            let head = svc_match.input.clone_parts();
            svc_match
                .input
                .extensions_mut()
                .insert(HttpWebSocketRelayHandshakeResponse(head.into()));
        }

        if let Some(cfg) = crate::handshake::client::apply_response_data_to_base_websocket_config(
            *websocket_config,
            &mut svc_match.input,
        ) {
            svc_match
                .input
                .extensions_mut()
                .insert(RelayWebSocketConfig(cfg));
        }

        svc_match.service = Some(relay_svc.clone());
        Ok(svc_match)
    }

    async fn into_match_service(
        self,
        res: Response<Body>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        let Self {
            relay_svc,
            websocket_config,
            store_handshake_res_header,
        } = self;

        let mut svc_match = ServiceMatch {
            service: None,
            input: res,
        };

        let http_version = svc_match.input.version();
        let http_status = svc_match.input.status();

        match (http_version, http_status) {
            (Version::HTTP_10 | Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS)
            | (Version::HTTP_2, StatusCode::OK) => (),
            _ => {
                tracing::debug!(?http_version, ?http_status, "WS response failed to match");
                return Ok(svc_match);
            }
        }

        if store_handshake_res_header {
            let head = svc_match.input.clone_parts();
            svc_match
                .input
                .extensions_mut()
                .insert(HttpWebSocketRelayHandshakeResponse(head.into()));
        }

        if let Some(cfg) = crate::handshake::client::apply_response_data_to_base_websocket_config(
            websocket_config,
            &mut svc_match.input,
        ) {
            svc_match
                .input
                .extensions_mut()
                .insert(RelayWebSocketConfig(cfg));
        }

        svc_match.service = Some(relay_svc);
        Ok(svc_match)
    }
}
