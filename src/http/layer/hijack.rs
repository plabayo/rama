//! Middleware to hijack request to a [`Service`] which match using a [`Matcher`].
//!
//! Common usecases for hijacking requests are:
//! - Redirecting requests to a different service based on the conditions specified in the [`Matcher`].
//! - Block requests based on the conditions specified in the [`Matcher`] (and thus act like an Http Firewall).
//!
//! [`Service`]: crate::service::Service
//! [`Matcher`]: crate::http::service::web::matcher::Matcher

use crate::{
    http::{dep::http_body, service::web::matcher::Matcher, Request},
    service::{context::Extensions, Context, Layer, Service},
};

/// Middleware to hijack request to a [`Service`] which match using a [`Matcher`].
///
/// Common usecases for hijacking requests are:
/// - Redirecting requests to a different service based on the conditions specified in the [`Matcher`].
/// - Block requests based on the conditions specified in the [`Matcher`] (and thus act like an Http Firewall).
///
/// [`Service`]: crate::service::Service
/// [`Matcher`]: crate::http::service::web::matcher::Matcher
pub struct HijackService<S, H, M> {
    inner: S,
    hijack: H,
    matcher: M,
}

impl<S, H, M> std::fmt::Debug for HijackService<S, H, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HijackService").finish()
    }
}

impl<S, H, M> Clone for HijackService<S, H, M>
where
    S: Clone,
    H: Clone,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            hijack: self.hijack.clone(),
            matcher: self.matcher.clone(),
        }
    }
}

impl<S, H, M> HijackService<S, H, M> {
    /// Create a new `HijackService`.
    pub fn new(inner: S, hijack: H, matcher: M) -> Self {
        Self {
            inner,
            hijack,
            matcher,
        }
    }
}

impl<S, H, M, State, Body> Service<State, Request<Body>> for HijackService<S, H, M>
where
    S: Service<State, Request<Body>>,
    H: Service<State, Request<Body>>,
    <H as Service<State, Request<Body>>>::Response: Into<S::Response>,
    <H as Service<State, Request<Body>>>::Error: Into<S::Error>,
    M: Matcher<State, Body>,
    State: Send + Sync + 'static,
    Body: http_body::Body + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();
        if self.matcher.matches(&mut ext, &ctx, &req) {
            ctx.extend(ext);
            match self.hijack.serve(ctx, req).await {
                Ok(response) => Ok(response.into()),
                Err(err) => Err(err.into()),
            }
        } else {
            self.inner.serve(ctx, req).await
        }
    }
}

/// Middleware to hijack request to a [`Service`] which match using a [`Matcher`].
///
/// Common usecases for hijacking requests are:
/// - Redirecting requests to a different service based on the conditions specified in the [`Matcher`].
/// - Block requests based on the conditions specified in the [`Matcher`] (and thus act like an Http Firewall).
///
/// [`Service`]: crate::service::Service
/// [`Matcher`]: crate::http::service::web::matcher::Matcher
pub struct HijackLayer<H, M> {
    hijack: H,
    matcher: M,
}

impl<H, M> std::fmt::Debug for HijackLayer<H, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HijackLayer").finish()
    }
}

impl<H, M> Clone for HijackLayer<H, M>
where
    H: Clone,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            hijack: self.hijack.clone(),
            matcher: self.matcher.clone(),
        }
    }
}

impl<H, M> HijackLayer<H, M> {
    /// Create a new [`HijackLayer`].
    pub fn new(matcher: M, hijack: H) -> Self {
        Self { hijack, matcher }
    }
}

impl<S, H, M> Layer<S> for HijackLayer<H, M>
where
    H: Clone,
    M: Clone,
{
    type Service = HijackService<S, H, M>;

    fn layer(&self, inner: S) -> Self::Service {
        HijackService::new(inner, self.hijack.clone(), self.matcher.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::dep::http_body_util::BodyExt;
    use crate::http::{
        service::web::{extract::Query, matcher::DomainFilter, IntoEndpointService, WebService},
        Body,
    };
    use crate::http::{Request, StatusCode};
    use serde::Deserialize;

    #[tokio::test]
    async fn hijack_layer_service() {
        #[derive(Debug, Deserialize)]
        struct Device {
            mobile: Option<bool>,
        }

        let hijack_service =
            WebService::default().get("/profile", |Query(query): Query<Device>| async move {
                if query.mobile.unwrap_or_default() {
                    "Mobile"
                } else {
                    "Not Mobile"
                }
            });
        let hijack_layer = HijackLayer::new(DomainFilter::new("profiles.rama"), hijack_service);

        let service = StatusCode::BAD_REQUEST.into_endpoint_service();
        let service = hijack_layer.layer(service);

        let response = service
            .serve(
                Context::default(),
                Request::builder()
                    .method("GET")
                    .uri("http://profiles.rama/profile?mobile=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "Mobile"
        );

        let response = service
            .serve(
                Context::default(),
                Request::builder()
                    .method("GET")
                    .uri("http://profiles.rama/profile")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "Not Mobile"
        );

        let response = service
            .serve(
                Context::default(),
                Request::builder()
                    .method("GET")
                    .uri("http://example.com/profile")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn hijack_layer_http_firewall() {
        let hijack_layer = HijackLayer::new(
            DomainFilter::sub("example.com"),
            StatusCode::FORBIDDEN.into_endpoint_service(),
        );

        let service = StatusCode::OK.into_endpoint_service();
        let service = hijack_layer.layer(service);

        let response = service
            .serve(
                Context::default(),
                Request::builder()
                    .method("GET")
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = service
            .serve(
                Context::default(),
                Request::builder()
                    .method("GET")
                    .uri("http://www.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = service
            .serve(
                Context::default(),
                Request::builder()
                    .method("GET")
                    .uri("http://example.org")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
