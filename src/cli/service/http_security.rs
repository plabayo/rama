//! Shared defence-in-depth HTTP response-header layer used by every
//! HTML-emitting service that ships with rama (fingerprint service, http
//! test service, public IP page).
//!
//! The defaults are intentionally strict so an XSS that slips past the
//! escaping pipeline cannot, on its own, exfiltrate data or be reframed
//! by a third party. Each call-site can widen the policy with
//! [`ContentSecurityPolicy::with`] before passing it to
//! [`defence_in_depth_layer`].

use crate::http::{
    HeaderValue,
    headers::{
        ContentSecurityPolicy, HostSource, ReferrerPolicy, SourceList, XContentTypeOptions,
        XFrameOptions,
    },
    layer::set_header::{
        SetResponseHeaderLayer,
        response::{MakeHeaderValueDefault, TypedHeaderAsMaker},
    },
};
use crate::net::{Protocol, address::Domain};

/// Convenience: build the strict-self CSP, widened only with the image
/// hosts every rama-shipped HTML page needs (the inline favicon SVG via
/// `data:` and the GitHub-hosted banner image). Frame ancestry is denied
/// upstream by [`XFrameOptions::Deny`] and the policy's own
/// `frame-ancestors 'none'`.
///
/// The fingerprint service further extends this with `connect-src 'self'`
/// for the same-origin WebSocket on `/api/ws`; that addition is
/// scheme-aware (`'self'` covers `ws:`/`wss:` to the same origin per
/// CSP3) and is therefore *not* a separate `ws:`/`wss:` scheme
/// allow-list.
#[must_use]
pub fn rama_html_csp() -> ContentSecurityPolicy {
    ContentSecurityPolicy::strict_self().with_img_src(
        SourceList::self_origin().with_data().with_host(
            HostSource::new(Domain::from_static("raw.githubusercontent.com"))
                .with_scheme(Protocol::HTTPS),
        ),
    )
}

/// Build the standard defence-in-depth response-header layer stack.
///
/// Sets `Content-Security-Policy`, `X-Content-Type-Options`,
/// `Referrer-Policy`, and `X-Frame-Options` — each `if-not-present`, so
/// upstream services can override them per-response when needed (e.g.
/// for a `/healthz` JSON endpoint that has its own posture).
///
/// The returned value is itself a tuple of layers and is composed into
/// the surrounding middleware stack the same way as any other layer.
pub fn defence_in_depth_layer(
    csp: ContentSecurityPolicy,
) -> (
    SetResponseHeaderLayer<Option<HeaderValue>>,
    SetResponseHeaderLayer<MakeHeaderValueDefault<TypedHeaderAsMaker<XContentTypeOptions>>>,
    SetResponseHeaderLayer<Option<HeaderValue>>,
    SetResponseHeaderLayer<Option<HeaderValue>>,
) {
    (
        // CSP carries per-page state, so we go through `if_not_present_typed`
        // with a built value rather than `_default_typed`.
        SetResponseHeaderLayer::if_not_present_typed(csp),
        SetResponseHeaderLayer::<XContentTypeOptions>::if_not_present_default_typed(),
        SetResponseHeaderLayer::if_not_present_typed(ReferrerPolicy::NO_REFERRER),
        SetResponseHeaderLayer::if_not_present_typed(XFrameOptions::Deny),
    )
}

#[cfg(test)]
mod tests {
    //! Layer-level regression tests for the defence-in-depth response
    //! headers. Each test wires the layer onto a tiny inner service that
    //! returns an empty 200 response, then asserts what the user agent
    //! ends up seeing.
    //!
    //! The wrapping uses rama's own [`Layer`] / [`Service`] traits, so
    //! these tests fail if either:
    //!  * the helper's directive choices change in a way that surprises
    //!    a downstream caller, or
    //!  * any of the four typed-header impls regress in their encoded
    //!    form.

    use super::*;
    use crate::{
        Layer, Service,
        http::{
            Body, Request, Response,
            headers::HeaderMapExt as _,
            service::web::{IntoEndpointService, response::IntoResponse},
        },
        service::service_fn,
    };
    use std::convert::Infallible;

    async fn invoke(csp: ContentSecurityPolicy) -> crate::http::HeaderMap {
        let svc = defence_in_depth_layer(csp).into_layer(
            service_fn(async || Ok::<_, Infallible>(Response::new(Body::empty())))
                .into_endpoint_service(),
        );
        let resp = svc
            .serve(Request::new(Body::empty()))
            .await
            .expect("infallible service");
        resp.headers().clone()
    }

    /// All four hardening headers must land on a baseline response,
    /// using their typed-header canonical encodings.
    #[tokio::test]
    async fn baseline_strict_self_emits_all_four_headers() {
        let headers = invoke(rama_html_csp()).await;

        let csp: ContentSecurityPolicy = headers.typed_get().expect("CSP set");
        let rendered = csp.to_string();
        // The strict-self baseline is preserved end-to-end; only `img-src`
        // is widened, and the other directives remain `'self'`-only.
        assert!(rendered.contains("default-src 'self'"), "{rendered}");
        assert!(rendered.contains("script-src 'self'"), "{rendered}");
        assert!(rendered.contains("frame-ancestors 'none'"), "{rendered}");
        assert!(
            rendered.contains("img-src 'self' data: https://raw.githubusercontent.com"),
            "{rendered}",
        );
        // Crucially: no `ws:` / `wss:` scheme widening — `connect-src`
        // is *not* in the baseline at all, and any caller that needs WS
        // adds it explicitly as same-origin `'self'` (which is
        // scheme-aware in CSP3 and covers same-origin WebSocket).
        assert!(!rendered.contains("ws:"), "{rendered}");
        assert!(!rendered.contains("wss:"), "{rendered}");

        let xcto: XContentTypeOptions = headers.typed_get().expect("X-Content-Type-Options set");
        assert_eq!(xcto, XContentTypeOptions::nosniff());

        let rp: ReferrerPolicy = headers.typed_get().expect("Referrer-Policy set");
        assert_eq!(rp, ReferrerPolicy::NO_REFERRER);

        let xfo: XFrameOptions = headers.typed_get().expect("X-Frame-Options set");
        assert_eq!(xfo, XFrameOptions::Deny);
    }

    /// `if-not-present` semantics: a downstream service that explicitly
    /// sets one of the security headers takes precedence (so a future
    /// endpoint can opt in to e.g. a relaxed CSP for itself without us
    /// having to widen the global default).
    #[tokio::test]
    async fn does_not_overwrite_existing_headers() {
        let inner_csp = ContentSecurityPolicy::empty().with_default_src(SourceList::none());
        let inner_csp_for_layer = inner_csp.clone();

        let svc = defence_in_depth_layer(rama_html_csp()).into_layer(
            service_fn(move |_req: Request| {
                let csp = inner_csp_for_layer.clone();
                async move {
                    let mut resp = Response::new(Body::empty());
                    resp.headers_mut().typed_insert(csp);
                    Ok::<_, Infallible>(resp.into_response())
                }
            })
            .into_endpoint_service(),
        );

        let resp = svc.serve(Request::new(Body::empty())).await.unwrap();
        let got: ContentSecurityPolicy = resp.headers().typed_get().expect("CSP set");
        // The inner handler's policy is preserved verbatim — the layer
        // did NOT replace it with the helper's strict-self baseline.
        assert_eq!(got, inner_csp);
    }

    /// Caller-supplied per-directive widening flows end-to-end through
    /// the encode/HTTP roundtrip. This is the FP server's pattern (it
    /// adds same-origin WebSocket support).
    #[tokio::test]
    async fn caller_widening_with_connect_src_is_preserved() {
        let csp = rama_html_csp().with_connect_src(SourceList::self_origin());
        let headers = invoke(csp).await;
        let got: ContentSecurityPolicy = headers.typed_get().expect("CSP set");
        assert!(got.to_string().contains("connect-src 'self'"));
    }
}
