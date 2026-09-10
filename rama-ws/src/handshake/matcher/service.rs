use std::{convert::Infallible, sync::Arc};

use rama_core::{
    extensions::{Extension, Extensions, ExtensionsRef},
    matcher::service::{ServiceMatch, ServiceMatcher},
    rt::Executor,
    telemetry::tracing,
};
use rama_http::{
    Request, Response, StatusCode, Version,
    headers::sec_websocket_protocol::AcceptedWebSocketProtocol,
    layer::upgrade::mitm::HttpUpgradeMitmRelayExtensions, request, response,
};
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

#[derive(Debug, Clone, Extension)]
#[extension(tags(ws))]
/// Stored in the Ingress extensions
/// by the [`HttpWebSocketRelayServiceRequestMatcher`] if configured to do so.
/// The snapshot contains HTTP fields only; its extensions are empty.
pub struct HttpWebSocketRelayHandshakeRequest(pub Arc<request::Parts>);

#[derive(Debug, Clone, Extension)]
#[extension(tags(ws))]
/// Stored in the Egress extensions
/// by the [`HttpWebSocketRelayServiceResponseMatcher`] if configured to do so.
/// The snapshot contains HTTP fields only; its extensions are empty.
pub struct HttpWebSocketRelayHandshakeResponse(pub Arc<response::Parts>);

impl Default for HttpWebSocketRelayServiceRequestMatcher {
    fn default() -> Self {
        Self {
            relay_svc: IoForwardService::default(),
            websocket_config: None,
            store_handshake_req_header: false,
            store_handshake_res_header: false,
        }
    }
}

impl HttpWebSocketRelayServiceRequestMatcher {
    /// Create a [`HttpWebSocketRelayServiceRequestMatcher`] whose default
    /// fallback relay observes graceful shutdown via the given [`Executor`].
    ///
    /// Prefer this over [`Self::default`] when you have an executor available
    /// — it lets the relay bridge unwind cleanly on shutdown.
    #[must_use]
    pub fn default_with_exec(exec: Executor) -> Self {
        Self {
            relay_svc: IoForwardService::new(exec),
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
        /// in the upgraded ingress Io extensions after a successful relay upgrade.
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
        /// in the upgraded egress Io extensions after a successful relay upgrade.
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
            let mut head = svc_match.input.clone_parts();
            // Parts cloning shares the live extension store. A snapshot stored
            // in that store must not retain a link back to it.
            head.extensions = Extensions::new();
            insert_upgrade_extension(
                svc_match.input.extensions(),
                HttpWebSocketRelayHandshakeRequest(head.into()),
            );
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
            let mut head = svc_match.input.clone_parts();
            // Parts cloning shares the live extension store. A snapshot stored
            // in that store must not retain a link back to it.
            head.extensions = Extensions::new();
            insert_upgrade_extension(
                svc_match.input.extensions(),
                HttpWebSocketRelayHandshakeRequest(head.into()),
            );
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

#[derive(Debug, Clone, Extension)]
#[extension(tags(ws))]
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
            (Version::HTTP_10 | Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS) => (),
            (Version::HTTP_2, status) if status.is_success() => (),
            _ => {
                tracing::debug!(?http_version, ?http_status, "WS response failed to match");
                return Ok(svc_match);
            }
        }

        if *store_handshake_res_header {
            let mut head = svc_match.input.clone_parts();
            head.extensions = Extensions::new();
            insert_upgrade_extension(
                svc_match.input.extensions(),
                HttpWebSocketRelayHandshakeResponse(head.into()),
            );
        }

        if let Some(cfg) = crate::handshake::client::apply_response_data_to_base_websocket_config(
            *websocket_config,
            &mut svc_match.input,
        ) {
            insert_upgrade_extension(svc_match.input.extensions(), RelayWebSocketConfig(cfg));
        }
        if let Some(protocol) = svc_match
            .input
            .extensions()
            .self_get_ref::<AcceptedWebSocketProtocol>()
        {
            svc_match
                .input
                .extensions()
                .self_get_ref_or_insert(HttpUpgradeMitmRelayExtensions::default)
                .0
                .insert(protocol.clone());
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
            (Version::HTTP_10 | Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS) => (),
            (Version::HTTP_2, status) if status.is_success() => (),
            _ => {
                tracing::debug!(?http_version, ?http_status, "WS response failed to match");
                return Ok(svc_match);
            }
        }

        if store_handshake_res_header {
            let mut head = svc_match.input.clone_parts();
            head.extensions = Extensions::new();
            insert_upgrade_extension(
                svc_match.input.extensions(),
                HttpWebSocketRelayHandshakeResponse(head.into()),
            );
        }

        if let Some(cfg) = crate::handshake::client::apply_response_data_to_base_websocket_config(
            websocket_config,
            &mut svc_match.input,
        ) {
            insert_upgrade_extension(svc_match.input.extensions(), RelayWebSocketConfig(cfg));
        }
        if let Some(protocol) = svc_match
            .input
            .extensions()
            .self_get_ref::<AcceptedWebSocketProtocol>()
        {
            svc_match
                .input
                .extensions()
                .self_get_ref_or_insert(HttpUpgradeMitmRelayExtensions::default)
                .0
                .insert(protocol.clone());
        }

        svc_match.service = Some(relay_svc);
        Ok(svc_match)
    }
}

// Keep metadata available on the HTTP message, and explicitly select it for
// transfer to that message's upgraded transport. The selection is local: a
// response's inherited request selection belongs to the ingress side.
fn insert_upgrade_extension<T: Extension + Clone>(extensions: &Extensions, value: T) {
    extensions.insert(value.clone());
    extensions
        .self_get_ref_or_insert(HttpUpgradeMitmRelayExtensions::default)
        .0
        .insert(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::Ingress;
    use rama_http::{
        Body, Method, Request, Response,
        headers::{self, HeaderMapExt as _},
        proto::h2::ext::Protocol,
    };

    fn websocket_request(version: Version) -> Request {
        let mut request = Request::new(Body::empty());
        *request.version_mut() = version;
        if version == Version::HTTP_2 {
            *request.method_mut() = Method::CONNECT;
            request
                .extensions()
                .insert(Protocol::from_static("websocket"));
        } else {
            *request.method_mut() = Method::GET;
            request
                .headers_mut()
                .typed_insert(headers::Upgrade::websocket());
            request
                .headers_mut()
                .typed_insert(headers::Connection::upgrade());
        }
        request
    }

    fn websocket_response(version: Version) -> Response {
        let mut response = Response::new(Body::empty());
        *response.version_mut() = version;
        *response.status_mut() = if version == Version::HTTP_2 {
            StatusCode::OK
        } else {
            StatusCode::SWITCHING_PROTOCOLS
        };
        response
    }

    #[derive(Debug, Extension)]
    struct Lifetime(#[expect(dead_code, reason = "lifetime probe")] Arc<()>);

    #[tokio::test]
    async fn stored_heads_are_detached_snapshots_and_release_http_state() {
        for owned in [false, true] {
            for version in [Version::HTTP_11, Version::HTTP_2] {
                let request_lifetime = Arc::new(());
                let request_weak = Arc::downgrade(&request_lifetime);
                let response_lifetime = Arc::new(());
                let response_weak = Arc::downgrade(&response_lifetime);
                let io_lifetime = Arc::new(());
                let io_weak = Arc::downgrade(&io_lifetime);
                let (request_head, response_head) = {
                    let io = Extensions::new();
                    io.insert(Lifetime(io_lifetime));
                    let mut request = websocket_request(version);
                    *request.uri_mut() = "https://example.test/socket?room=one".parse().unwrap();
                    request
                        .headers_mut()
                        .insert("x-request", "original".parse().unwrap());
                    request.extensions().insert(Ingress(io.clone()));
                    request.extensions().insert(Lifetime(request_lifetime));
                    let matcher = HttpWebSocketRelayServiceRequestMatcher::new(())
                        .with_store_handshake_request_header(true)
                        .with_store_handshake_response_header(true);
                    let matched = if owned {
                        matcher.into_match_service(request).await.unwrap()
                    } else {
                        matcher.match_service(request).await.unwrap()
                    };
                    let mut request = matched.input;
                    let request_head = request
                        .extensions()
                        .self_get_ref::<HttpWebSocketRelayHandshakeRequest>()
                        .unwrap()
                        .clone();
                    assert_eq!(request_head.0.uri, request.uri().clone());
                    assert_eq!(request_head.0.method, request.method().clone());
                    assert_eq!(request_head.0.version, version);
                    assert_eq!(request_head.0.headers["x-request"], "original");
                    request
                        .headers_mut()
                        .insert("x-request", "changed".parse().unwrap());
                    assert_eq!(request_head.0.headers["x-request"], "original");
                    assert!(request_head.0.extensions.self_iter_all().next().is_none());
                    assert!(request_head.0.extensions.parent().is_none());
                    assert!(io.get_ref::<HttpWebSocketRelayHandshakeRequest>().is_none());
                    assert!(
                        request
                            .extensions()
                            .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
                            .unwrap()
                            .0
                            .self_get_ref::<HttpWebSocketRelayHandshakeRequest>()
                            .is_some()
                    );

                    // A real client response forks request state. Its selection
                    // must nevertheless stay independent of the ingress side.
                    let mut response =
                        websocket_response(version).with_extensions(request.extensions().fork());
                    response
                        .headers_mut()
                        .insert("x-response", "original".parse().unwrap());
                    response.extensions().insert(Lifetime(response_lifetime));
                    let matcher = matched.service.unwrap();
                    let matched = if owned {
                        matcher.into_match_service(response).await.unwrap()
                    } else {
                        matcher.match_service(response).await.unwrap()
                    };
                    let mut response = matched.input;
                    let response_head = response
                        .extensions()
                        .self_get_ref::<HttpWebSocketRelayHandshakeResponse>()
                        .unwrap()
                        .clone();
                    assert_eq!(response_head.0.status, response.status());
                    assert_eq!(response_head.0.version, version);
                    response
                        .headers_mut()
                        .insert("x-response", "changed".parse().unwrap());
                    assert_eq!(response_head.0.headers["x-response"], "original");
                    assert!(response_head.0.extensions.self_iter_all().next().is_none());
                    assert!(response_head.0.extensions.parent().is_none());
                    let selected = response
                        .extensions()
                        .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
                        .unwrap();
                    assert!(
                        selected
                            .0
                            .get_ref::<HttpWebSocketRelayHandshakeResponse>()
                            .is_some()
                    );
                    assert!(
                        selected
                            .0
                            .get_ref::<HttpWebSocketRelayHandshakeRequest>()
                            .is_none()
                    );
                    (request_head, response_head)
                };
                // Keeping the snapshots alive must not keep either HTTP
                // exchange or the transport state alive with them.
                assert!(
                    request_weak.upgrade().is_none(),
                    "request leaked: owned={owned}, {version:?}"
                );
                assert!(
                    response_weak.upgrade().is_none(),
                    "response leaked: owned={owned}, {version:?}"
                );
                assert!(
                    io_weak.upgrade().is_none(),
                    "transport leaked: owned={owned}, {version:?}"
                );
                drop((request_head, response_head));
            }
        }
    }

    #[tokio::test]
    async fn storage_flags_and_rejected_handshakes_do_not_select_metadata() {
        for owned in [false, true] {
            for version in [Version::HTTP_11, Version::HTTP_2] {
                for store in [false, true] {
                    for accepted in [false, true] {
                        let matcher = HttpWebSocketRelayServiceRequestMatcher::new(())
                            .with_store_handshake_request_header(store)
                            .with_store_handshake_response_header(store);
                        let mut request = websocket_request(version);
                        if !accepted {
                            *request.method_mut() = Method::POST;
                        }
                        let matched = if owned {
                            matcher.into_match_service(request).await.unwrap()
                        } else {
                            matcher.match_service(request).await.unwrap()
                        };
                        assert_eq!(matched.service.is_some(), accepted);
                        assert_eq!(
                            matched
                                .input
                                .extensions()
                                .self_get_ref::<HttpWebSocketRelayHandshakeRequest>()
                                .is_some(),
                            store && accepted
                        );
                        assert_eq!(
                            matched
                                .input
                                .extensions()
                                .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
                                .is_some(),
                            store && accepted
                        );
                        if let Some(matcher) = matched.service {
                            for status in [
                                StatusCode::BAD_REQUEST,
                                websocket_response(version).status(),
                            ] {
                                let mut response = websocket_response(version);
                                *response.status_mut() = status;
                                let selected = status != StatusCode::BAD_REQUEST;
                                let matched = if owned {
                                    matcher.clone().into_match_service(response).await.unwrap()
                                } else {
                                    matcher.match_service(response).await.unwrap()
                                };
                                assert_eq!(matched.service.is_some(), selected);
                                assert_eq!(
                                    matched
                                        .input
                                        .extensions()
                                        .self_get_ref::<HttpWebSocketRelayHandshakeResponse>()
                                        .is_some(),
                                    store && selected
                                );
                                assert_eq!(
                                    matched
                                        .input
                                        .extensions()
                                        .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
                                        .is_some(),
                                    store && selected
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn negotiation_is_selected_even_when_header_storage_is_disabled() {
        for owned in [false, true] {
            for version in [Version::HTTP_11, Version::HTTP_2] {
                let matcher = HttpWebSocketRelayServiceRequestMatcher::new(())
                    .with_websocket_config(WebSocketConfig {
                        max_message_size: Some(1234),
                        ..WebSocketConfig::default()
                    })
                    .match_service(websocket_request(version))
                    .await
                    .unwrap()
                    .service
                    .unwrap();
                let mut response = websocket_response(version);
                response
                    .headers_mut()
                    .insert("sec-websocket-protocol", "chat".parse().unwrap());
                #[cfg(feature = "compression")]
                response.headers_mut().insert(
                    "sec-websocket-extensions",
                    "permessage-deflate".parse().unwrap(),
                );
                let matched = if owned {
                    matcher.into_match_service(response).await.unwrap()
                } else {
                    matcher.match_service(response).await.unwrap()
                };
                let selected = &matched
                    .input
                    .extensions()
                    .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
                    .unwrap()
                    .0;
                assert!(
                    selected
                        .get_ref::<HttpWebSocketRelayHandshakeResponse>()
                        .is_none()
                );
                assert_eq!(
                    selected
                        .get_ref::<AcceptedWebSocketProtocol>()
                        .unwrap()
                        .0
                        .as_ref(),
                    "chat"
                );
                let config = &selected.get_ref::<RelayWebSocketConfig>().unwrap().0;
                assert_eq!(config.max_message_size, Some(1234));
                #[cfg(feature = "compression")]
                assert!(config.per_message_deflate.is_some());
            }
        }
    }

    #[tokio::test]
    async fn borrowed_and_owned_service_matchers_accept_websocket_handshakes() {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let request_matcher = HttpWebSocketRelayServiceRequestMatcher::new(());
            let borrowed_response_matcher = request_matcher
                .match_service(websocket_request(version))
                .await
                .expect("request match")
                .service
                .expect("borrowed request matcher accepts WebSocket");
            assert!(
                borrowed_response_matcher
                    .match_service(websocket_response(version))
                    .await
                    .expect("response match")
                    .service
                    .is_some(),
                "borrowed response matcher accepts successful WebSocket"
            );

            let owned_response_matcher = request_matcher
                .into_match_service(websocket_request(version))
                .await
                .expect("request match")
                .service
                .expect("owned request matcher accepts WebSocket");
            assert!(
                owned_response_matcher
                    .into_match_service(websocket_response(version))
                    .await
                    .expect("response match")
                    .service
                    .is_some(),
                "owned response matcher accepts successful WebSocket"
            );
        }

        let mut response = websocket_response(Version::HTTP_2);
        *response.status_mut() = StatusCode::CREATED;
        let matcher = HttpWebSocketRelayServiceRequestMatcher::new(())
            .match_service(websocket_request(Version::HTTP_2))
            .await
            .expect("request match")
            .service
            .expect("HTTP/2 request matcher");
        assert!(
            matcher
                .match_service(response)
                .await
                .expect("response match")
                .service
                .is_some(),
            "any successful CONNECT response establishes the tunnel"
        );
    }
}
