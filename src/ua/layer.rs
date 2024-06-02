use crate::{
    http::{
        headers::{self, HeaderMapExt},
        HeaderName, Request,
    },
    service::{Layer, Service},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug},
    future::Future,
};

use super::{HttpAgent, TlsAgent, UserAgent};

/// A [`Service`] that classifies the [`UserAgent`] of incoming [`Request`]s.
///
/// The [`Extensions`] of the [`Context`] is updated with the [`UserAgent`]
/// if the [`Request`] contains a valid [`UserAgent`] header.
///
/// [`Extensions`]: crate::service::context::Extensions
/// [`Context`]: crate::service::Context
pub struct UserAgentClassifier<S> {
    inner: S,
    overwrite_header: Option<HeaderName>,
}

/// Information that can be used to overwrite the [`UserAgent`] of a [`Request`].
///
/// Used by the [`UserAgentClassifier`] to overwrite the specified
/// information duing the classification of the [`UserAgent`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserAgentOverwrites {
    /// Overwrite the [`UserAgent`] of the [`Request`] with a custom value.
    ///
    /// This value will be used instead of
    /// [the 'User-Agent' http header](crate::http::headers::UserAgent) value.
    ///
    /// This is useful in case you cannot set the User-Agent header in your request.
    pub ua: Option<String>,
    /// Overwrite the [`HttpAgent`] of the [`Request`] with a custom value.
    pub http: Option<HttpAgent>,
    /// Overwrite the [`TlsAgent`] of the [`Request`] with a custom value.
    pub tls: Option<TlsAgent>,
    /// Preserve the original [`UserAgent`] header of the [`Request`].
    pub preserve_ua: Option<bool>,
}

impl<S> UserAgentClassifier<S> {
    /// Create a new [`UserAgentClassifier`] [`Service`].
    pub fn new(inner: S, overwrite_header: Option<HeaderName>) -> Self {
        Self {
            inner,
            overwrite_header,
        }
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
            overwrite_header: self.overwrite_header.clone(),
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
            overwrite_header: None,
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
        let mut user_agent = req
            .headers()
            .typed_get::<headers::UserAgent>()
            .map(|ua| UserAgent::new(ua.to_string()));

        if let Some(overwrites) = self
            .overwrite_header
            .as_ref()
            .and_then(|header| req.headers().get(header))
            .map(|header| header.as_bytes())
            .and_then(|value| serde_html_form::from_bytes::<UserAgentOverwrites>(value).ok())
        {
            if let Some(ua) = overwrites.ua {
                user_agent = Some(UserAgent::new(ua));
            }
            if let Some(ref mut ua) = user_agent {
                if let Some(http_agent) = overwrites.http {
                    ua.with_http_agent(http_agent);
                }
                if let Some(tls_agent) = overwrites.tls {
                    ua.with_tls_agent(tls_agent);
                }
                if let Some(preserve_ua) = overwrites.preserve_ua {
                    ua.with_preserve_ua_header(preserve_ua);
                }
            }
        }

        if let Some(ua) = user_agent.take() {
            ctx.insert(ua);
        }

        self.inner.serve(ctx, req)
    }
}

#[derive(Debug, Clone, Default)]
/// A [`Layer`] that wraps a [`Service`] with a [`UserAgentClassifier`].
///
/// This [`Layer`] is used to classify the [`UserAgent`] of incoming [`Request`]s.
pub struct UserAgentClassifierLayer {
    overwrite_header: Option<HeaderName>,
}

impl UserAgentClassifierLayer {
    /// Create a new [`UserAgentClassifierLayer`].
    pub fn new() -> Self {
        Self {
            overwrite_header: None,
        }
    }

    /// Define a custom header to allow overwriting certain
    /// [`UserAgent`] information.
    pub fn overwrite_header(mut self, header: HeaderName) -> Self {
        self.overwrite_header = Some(header);
        self
    }
}

impl<S> Layer<S> for UserAgentClassifierLayer {
    type Service = UserAgentClassifier<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UserAgentClassifier::new(inner, self.overwrite_header.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client::HttpClientExt;
    use crate::http::headers;
    use crate::http::layer::required_header::AddRequiredRequestHeadersLayer;
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
                format!(
                    "{}/{}",
                    crate::utils::info::NAME,
                    crate::utils::info::VERSION
                )
                .as_str(),
            );
            assert!(ua.info().is_none());
            assert!(ua.platform().is_none());

            Ok(StatusCode::OK.into_response())
        }

        let service = ServiceBuilder::new()
            .layer(AddRequiredRequestHeadersLayer::default())
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

    #[tokio::test]
    async fn test_user_agent_classifier_layer_overwrite_ua() {
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
            .layer(
                UserAgentClassifierLayer::new()
                    .overwrite_header(HeaderName::from_static("x-proxy-ua")),
            )
            .service_fn(handle);

        let _ = service
            .get("http://www.example.com")
            .header(
                "x-proxy-ua",
                serde_html_form::to_string(&UserAgentOverwrites {
                    ua: Some(UA.to_owned()),
                    ..Default::default()
                })
                .unwrap(),
            )
            .send(Context::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_user_agent_classifier_layer_overwrite_ua_all() {
        const UA: &str = "iPhone App/1.0";

        async fn handle<S>(ctx: Context<S>, _req: Request) -> Result<Response, Infallible> {
            let ua: &UserAgent = ctx.get().unwrap();

            assert_eq!(ua.header_str(), UA);
            assert!(ua.info().is_none());
            assert!(ua.platform().is_none());
            assert_eq!(ua.http_agent(), HttpAgent::Safari);
            assert_eq!(ua.tls_agent(), TlsAgent::Boringssl);
            assert!(ua.preserve_ua_header());

            Ok(StatusCode::OK.into_response())
        }

        let service = ServiceBuilder::new()
            .layer(
                UserAgentClassifierLayer::new()
                    .overwrite_header(HeaderName::from_static("x-proxy-ua")),
            )
            .service_fn(handle);

        let _ = service
            .get("http://www.example.com")
            .header(
                "x-proxy-ua",
                serde_html_form::to_string(&UserAgentOverwrites {
                    ua: Some(UA.to_owned()),
                    http: Some(HttpAgent::Safari),
                    tls: Some(TlsAgent::Boringssl),
                    preserve_ua: Some(true),
                })
                .unwrap(),
            )
            .send(Context::default())
            .await
            .unwrap();
    }
}
