//! User-Agent (see also `rama-ua`) http layer support
//!
//! # Example
//!
//! ```
//! use rama_http::{
//!     service::client::HttpClientExt, Request, Response, StatusCode,
//!     layer::ua::{PlatformKind, UserAgent, UserAgentClassifierLayer, UserAgentKind, UserAgentInfo},
//!     service::web::response::IntoResponse,
//! };
//! use rama_core::{extensions::ExtensionsRef, Layer, service::service_fn};
//! use std::convert::Infallible;
//!
//! const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67";
//!
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     let ua: &UserAgent = req.extensions().get().unwrap();
//!
//!     assert_eq!(ua.header_str(), UA);
//!     assert_eq!(ua.info(), Some(UserAgentInfo{ kind: UserAgentKind::Chromium, version: Some(124) }));
//!     assert_eq!(ua.platform(), Some(PlatformKind::Windows));
//!
//!     Ok(StatusCode::OK.into_response())
//! }
//!
//! # #[tokio::main]
//! # async fn main() {
//! let service = UserAgentClassifierLayer::new().into_layer(service_fn(handle));
//!
//! let _ = service
//!     .get("http://www.example.com")
//!     .typed_header(rama_http::headers::UserAgent::from_static(UA))
//!     .send()
//!     .await
//!     .unwrap();
//! # }
//! ```

use crate::{
    HeaderName, Request,
    headers::{self, HeaderMapExt},
};
use rama_core::{Layer, Service, extensions::ExtensionsMut};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt::{self, Debug};

pub use rama_ua::{
    DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent, UserAgentInfo, UserAgentKind,
    UserAgentOverwrites,
};

/// A [`Service`] that classifies the [`UserAgent`] of incoming [`Request`]s.
///
/// The [`Extensions`] of the [`Context`] is updated with the [`UserAgent`]
/// if the [`Request`] contains a valid [`UserAgent`] header.
///
/// [`Extensions`]: rama_core::extensions::Extensions
/// [`Context`]: rama_core::Context
pub struct UserAgentClassifier<S> {
    inner: S,
    overwrite_header: Option<HeaderName>,
}

impl<S> UserAgentClassifier<S> {
    /// Create a new [`UserAgentClassifier`] [`Service`].
    pub const fn new(inner: S, overwrite_header: Option<HeaderName>) -> Self {
        Self {
            inner,
            overwrite_header,
        }
    }

    define_inner_service_accessors!();
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

impl<S, Body> Service<Request<Body>> for UserAgentClassifier<S>
where
    S: Service<Request<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,

        mut req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let overwrites = self
            .overwrite_header
            .as_ref()
            .and_then(|header| req.headers().get(header))
            .map(|header| header.as_bytes())
            .and_then(|value| serde_html_form::from_bytes::<UserAgentOverwrites>(value).ok());

        let mut user_agent = overwrites
            .as_ref()
            .and_then(|o| o.ua.as_deref())
            .map(UserAgent::new)
            .or_else(|| {
                req.headers()
                    .typed_get::<headers::UserAgent>()
                    .map(|ua| UserAgent::new(ua.to_string()))
            });

        if let Some(mut ua) = user_agent.take() {
            if let Some(overwrites) = overwrites {
                if let Some(http_agent) = overwrites.http {
                    ua.set_http_agent(http_agent);
                }
                if let Some(tls_agent) = overwrites.tls {
                    ua.set_tls_agent(tls_agent);
                }
            }

            req.extensions_mut().insert(ua);
        }

        self.inner.serve(req)
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
    #[must_use]
    pub const fn new() -> Self {
        Self {
            overwrite_header: None,
        }
    }

    /// Define a custom header to allow overwriting certain
    /// [`UserAgent`] information.
    #[must_use]
    pub fn overwrite_header(mut self, header: HeaderName) -> Self {
        self.overwrite_header = Some(header);
        self
    }

    /// Define a custom header to allow overwriting certain
    /// [`UserAgent`] information.
    pub fn set_overwrite_header(&mut self, header: HeaderName) -> &mut Self {
        self.overwrite_header = Some(header);
        self
    }
}

impl<S> Layer<S> for UserAgentClassifierLayer {
    type Service = UserAgentClassifier<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UserAgentClassifier::new(inner, self.overwrite_header.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        UserAgentClassifier::new(inner, self.overwrite_header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::required_header::AddRequiredRequestHeadersLayer;
    use crate::service::client::HttpClientExt;
    use crate::service::web::response::IntoResponse;
    use crate::{Response, StatusCode, headers};
    use rama_core::extensions::ExtensionsRef;
    use rama_core::service::service_fn;
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_user_agent_classifier_layer_ua_rama() {
        async fn handle(req: Request) -> Result<Response, Infallible> {
            let ua: &UserAgent = req.extensions().get().unwrap();

            assert_eq!(
                ua.header_str(),
                format!("{}/{}", rama_utils::info::NAME, rama_utils::info::VERSION).as_str(),
            );
            assert!(ua.info().is_none());
            assert!(ua.platform().is_none());

            Ok(StatusCode::OK.into_response())
        }

        let service = (
            AddRequiredRequestHeadersLayer::default(),
            UserAgentClassifierLayer::new(),
        )
            .into_layer(service_fn(handle));

        let _ = service.get("http://www.example.com").send().await.unwrap();
    }

    #[tokio::test]
    async fn test_user_agent_classifier_layer_ua_iphone_app() {
        const UA: &str = "iPhone App/1.0";

        async fn handle(req: Request) -> Result<Response, Infallible> {
            let ua: &UserAgent = req.extensions().get().unwrap();

            assert_eq!(ua.header_str(), UA);
            assert!(ua.info().is_none());
            assert_eq!(ua.platform(), Some(PlatformKind::IOS));
            assert_eq!(ua.http_agent(), None);
            assert_eq!(ua.tls_agent(), None);

            Ok(StatusCode::OK.into_response())
        }

        let service = UserAgentClassifierLayer::new().into_layer(service_fn(handle));

        let _ = service
            .get("http://www.example.com")
            .typed_header(headers::UserAgent::from_static(UA))
            .send()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_user_agent_classifier_layer_ua_chrome() {
        const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67";

        async fn handle(req: Request) -> Result<Response, Infallible> {
            let ua: &UserAgent = req.extensions().get().unwrap();

            assert_eq!(ua.header_str(), UA);
            let ua_info = ua.info().unwrap();
            assert_eq!(ua_info.kind, UserAgentKind::Chromium);
            assert_eq!(ua_info.version, Some(124));
            assert_eq!(ua.platform(), Some(PlatformKind::Windows));

            Ok(StatusCode::OK.into_response())
        }

        let service = UserAgentClassifierLayer::new().into_layer(service_fn(handle));

        let _ = service
            .get("http://www.example.com")
            .typed_header(headers::UserAgent::from_static(UA))
            .send()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_user_agent_classifier_layer_overwrite_ua() {
        const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67";

        async fn handle(req: Request) -> Result<Response, Infallible> {
            let ua: &UserAgent = req.extensions().get().unwrap();

            assert_eq!(ua.header_str(), UA);
            let ua_info = ua.info().unwrap();
            assert_eq!(ua_info.kind, UserAgentKind::Chromium);
            assert_eq!(ua_info.version, Some(124));
            assert_eq!(ua.platform(), Some(PlatformKind::Windows));

            Ok(StatusCode::OK.into_response())
        }

        let service = UserAgentClassifierLayer::new()
            .overwrite_header(HeaderName::from_static("x-proxy-ua"))
            .into_layer(service_fn(handle));

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
            .send()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_user_agent_classifier_layer_overwrite_ua_all() {
        const UA: &str = "iPhone App/1.0";

        async fn handle(req: Request) -> Result<Response, Infallible> {
            let ua: &UserAgent = req.extensions().get().unwrap();

            assert_eq!(ua.header_str(), UA);
            assert!(ua.info().is_none());
            assert_eq!(ua.platform(), Some(PlatformKind::IOS));
            assert_eq!(ua.http_agent(), Some(HttpAgent::Firefox));
            assert_eq!(ua.tls_agent(), Some(TlsAgent::Boringssl));

            Ok(StatusCode::OK.into_response())
        }

        let service = UserAgentClassifierLayer::new()
            .overwrite_header(HeaderName::from_static("x-proxy-ua"))
            .into_layer(service_fn(handle));

        let _ = service
            .get("http://www.example.com")
            .header(
                "x-proxy-ua",
                serde_html_form::to_string(&UserAgentOverwrites {
                    ua: Some(UA.to_owned()),
                    http: Some(HttpAgent::Firefox),
                    tls: Some(TlsAgent::Boringssl),
                })
                .unwrap(),
            )
            .send()
            .await
            .unwrap();
    }
}
