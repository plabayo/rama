use crate::{
    http::{
        headers::{self, HeaderMapExt},
        Request,
    },
    service::{Layer, Service},
};
use std::{
    fmt::{self, Debug},
    future::Future,
};

use super::UserAgent;

/// A [`Service`] that classifies the [`UserAgent`] of incoming [`Request`]s.
///
/// The [`Extensions`] of the [`Context`] is updated with the [`UserAgent`]
/// if the [`Request`] contains a valid [`UserAgent`] header.
///
/// [`Extensions`]: crate::service::context::Extensions
/// [`Context`]: crate::service::Context
pub struct UserAgentClassifier<S> {
    inner: S,
}

impl<S> UserAgentClassifier<S> {
    /// Create a new [`UserAgentClassifier`] [`Service`].
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Debug for UserAgentClassifier<S>
where
    S: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UserAgentClassifier")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S> Clone for UserAgentClassifier<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S> Default for UserAgentClassifier<S>
where
    S: Default,
{
    fn default() -> Self {
        Self {
            inner: S::default(),
        }
    }
}

impl<S, State, Body> Service<State, Request<Body>> for UserAgentClassifier<S>
where
    S: Service<State, Request<Body>>,
    State: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: crate::service::Context<State>,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        if let Some(ua) = req
            .headers()
            .typed_get::<headers::UserAgent>()
            .map(|ua| UserAgent::new(ua.to_string()))
        {
            ctx.insert(ua);
        }
        self.inner.serve(ctx, req)
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A [`Layer`] that wraps a [`Service`] with a [`UserAgentClassifier`].
///
/// This [`Layer`] is used to classify the [`UserAgent`] of incoming [`Request`]s.
pub struct UserAgentClassifierLayer;

impl UserAgentClassifierLayer {
    /// Create a new [`UserAgentClassifierLayer`].
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for UserAgentClassifierLayer {
    type Service = UserAgentClassifier<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UserAgentClassifier::new(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client::HttpClientExt;
    use crate::http::headers;
    use crate::http::{IntoResponse, StatusCode};
    use crate::ua::{PlatformKind, UserAgentKind};
    use crate::{
        http::Response,
        service::{Context, ServiceBuilder},
    };
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_user_agent_classifier_layer_ua_rama() {
        async fn handle<S>(ctx: Context<S>, _req: Request) -> Result<Response, Infallible> {
            let ua: &UserAgent = ctx.get().unwrap();

            assert_eq!(
                ua.header_str(),
                format!("{}/{}", crate::info::NAME, crate::info::VERSION).as_str(),
            );
            assert!(ua.info().is_none());
            assert!(ua.platform().is_none());

            Ok(StatusCode::OK.into_response())
        }

        let service = ServiceBuilder::new()
            .layer(UserAgentClassifierLayer::new())
            .service_fn(handle);

        let _ = service
            .get("http://www.example.com")
            .send(Context::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_user_agent_classifier_layer_ua_chrome() {
        const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67";

        async fn handle<S>(ctx: Context<S>, _req: Request) -> Result<Response, Infallible> {
            let ua: &UserAgent = ctx.get().unwrap();

            assert_eq!(ua.header_str(), UA);
            let ua_info = ua.info().unwrap();
            assert_eq!(ua_info.kind, UserAgentKind::Chromium);
            assert_eq!(ua_info.version, Some(124));
            assert_eq!(ua.platform(), Some(PlatformKind::Windows));

            Ok(StatusCode::OK.into_response())
        }

        let service = ServiceBuilder::new()
            .layer(UserAgentClassifierLayer::new())
            .service_fn(handle);

        let _ = service
            .get("http://www.example.com")
            .typed_header(headers::UserAgent::from_static(UA))
            .send(Context::default())
            .await
            .unwrap();
    }
}
