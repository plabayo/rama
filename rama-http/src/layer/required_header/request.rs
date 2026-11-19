//! Add the `Host` and `User-Agent` headers to a request, if they are missing.
//!
//! See [`AddRequiredRequestHeaders`] for the exact behaviour.

use crate::{
    HeaderValue, Request, Response,
    header::{self, HOST, USER_AGENT},
    headers::HeaderMapExt,
    utils::is_plain_connect,
};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_http_headers::Host;
use rama_net::{AuthorityInputExt, ProtocolInputExt};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// [`Layer`] that wraps a service in [`AddRequiredRequestHeaders`].
///
/// See [`AddRequiredRequestHeaders`] for the headers it adds.
#[derive(Debug, Clone, Default)]
pub struct AddRequiredRequestHeadersLayer {
    overwrite: bool,
    user_agent_header_value: Option<HeaderValue>,
}

impl AddRequiredRequestHeadersLayer {
    /// Create a new [`AddRequiredRequestHeadersLayer`]
    /// which only adds missing headers and uses the default `User-Agent`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            overwrite: false,
            user_agent_header_value: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether the `Host` and `User-Agent` headers
        /// replace values already present on the request.
        ///
        /// When `false` (the default) only missing headers are added.
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`USER_AGENT`] header value to add.
        ///
        /// `None` (the default) uses the [application identity](header::identity).
        pub fn user_agent_header_value(mut self, value: Option<HeaderValue>) -> Self {
            self.user_agent_header_value = value;
            self
        }
    }
}

impl<S> Layer<S> for AddRequiredRequestHeadersLayer {
    type Service = AddRequiredRequestHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddRequiredRequestHeaders {
            inner,
            overwrite: self.overwrite,
            user_agent_header_value: self.user_agent_header_value.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        AddRequiredRequestHeaders {
            inner,
            overwrite: self.overwrite,
            user_agent_header_value: self.user_agent_header_value,
        }
    }
}

/// Middleware that adds the `Host` and `User-Agent` headers to a request
/// before passing it to the inner service.
///
/// - `Host`: derived from the request's target authority. A plain `CONNECT`
///   keeps its port; any other request drops the port when it is the default
///   one for the target protocol. This is done for all http versions.
/// - `User-Agent`: the configured value, or the [application identity](header::identity) by default.
///
/// Existing headers are kept unless overwriting is enabled,
/// see [`AddRequiredRequestHeaders::set_overwrite`].
///
/// # Errors
///
/// Fails without calling the inner service if a `Host` header has to be added
/// but no target authority can be resolved for the request.
/// Errors of the inner service are boxed.
#[derive(Clone, ExtensionsRef)]
pub struct AddRequiredRequestHeaders<S> {
    inner: S,
    overwrite: bool,
    user_agent_header_value: Option<HeaderValue>,
}

impl<S> AddRequiredRequestHeaders<S> {
    /// Wrap `inner` in a new [`AddRequiredRequestHeaders`]
    /// which only adds missing headers and uses the default `User-Agent`.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            overwrite: false,
            user_agent_header_value: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether the `Host` and `User-Agent` headers
        /// replace values already present on the request.
        ///
        /// When `false` (the default) only missing headers are added.
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`USER_AGENT`] header value to add.
        ///
        /// `None` (the default) uses the [application identity](header::identity).
        pub fn user_agent_header_value(mut self, value: Option<HeaderValue>) -> Self {
            self.user_agent_header_value = value;
            self
        }
    }

    define_inner_service_accessors!();
}

impl<S> fmt::Debug for AddRequiredRequestHeaders<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddRequiredRequestHeaders")
            .field("inner", &self.inner)
            .field("overwrite", &self.overwrite)
            .field("user_agent_header_value", &self.user_agent_header_value)
            .finish()
    }
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for AddRequiredRequestHeaders<S>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if self.overwrite || !req.headers().contains_key(HOST) {
            let authority = req
                .target_authority()
                .context("AddRequiredRequestHeaders: resolve authority")?;
            // A plain CONNECT names its port; anything else drops a default one.
            let authority = if is_plain_connect(&req) {
                authority
            } else {
                authority.without_default_port_for(req.target_protocol())
            };
            tracing::trace!(
                server.address = %authority,
                "add missing authority as host header",
            );
            req.headers_mut().typed_insert(Host::from(authority));
        }

        if self.overwrite {
            req.headers_mut().insert(
                USER_AGENT,
                self.user_agent_header_value
                    .as_ref()
                    .unwrap_or_else(|| header::identity_header())
                    .clone(),
            );
        } else if let header::Entry::Vacant(header) = req.headers_mut().entry(USER_AGENT) {
            header.insert(
                self.user_agent_header_value
                    .as_ref()
                    .unwrap_or_else(|| header::identity_header())
                    .clone(),
            );
        }

        self.inner.serve(req).await.into_box_error()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Body, Request};
    use rama_core::service::service_fn;
    use rama_core::{Layer, Service};
    use std::convert::Infallible;

    #[tokio::test]
    async fn add_required_request_headers() {
        let svc = AddRequiredRequestHeadersLayer::default().into_layer(service_fn(
            async |req: Request| {
                assert!(req.headers().contains_key(HOST));
                assert!(req.headers().contains_key(USER_AGENT));
                Ok::<_, Infallible>(rama_http_types::Response::new(Body::empty()))
            },
        ));

        let req = Request::builder()
            .uri("http://www.example.com/")
            .body(Body::empty())
            .unwrap();
        let resp = svc.serve(req).await.unwrap();

        assert!(!resp.headers().contains_key(HOST));
        assert!(!resp.headers().contains_key(USER_AGENT));
    }

    #[tokio::test]
    async fn add_required_request_headers_custom_ua() {
        let svc = AddRequiredRequestHeadersLayer::default()
            .with_user_agent_header_value(HeaderValue::from_static("foo"))
            .into_layer(service_fn(async |req: Request| {
                assert!(req.headers().contains_key(HOST));
                assert_eq!(
                    req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()),
                    Some("foo")
                );
                Ok::<_, Infallible>(rama_http_types::Response::new(Body::empty()))
            }));

        let req = Request::builder()
            .uri("http://www.example.com/")
            .body(Body::empty())
            .unwrap();
        let resp = svc.serve(req).await.unwrap();

        assert!(!resp.headers().contains_key(HOST));
        assert!(!resp.headers().contains_key(USER_AGENT));
    }

    #[tokio::test]
    async fn add_required_request_headers_overwrite() {
        let svc = AddRequiredRequestHeadersLayer::new()
            .with_overwrite(true)
            .into_layer(service_fn(async |req: Request| {
                assert_eq!(req.headers().get(HOST).unwrap(), "127.0.0.1");
                assert_eq!(
                    req.headers().get(USER_AGENT).unwrap(),
                    header::identity_header()
                );
                Ok::<_, Infallible>(rama_http_types::Response::new(Body::empty()))
            }));

        let req = Request::builder()
            .uri("http://127.0.0.1/")
            .header(HOST, "example.com")
            .header(USER_AGENT, "test")
            .body(Body::empty())
            .unwrap();

        let resp = svc.serve(req).await.unwrap();

        assert!(!resp.headers().contains_key(HOST));
        assert!(!resp.headers().contains_key(USER_AGENT));
    }

    #[tokio::test]
    async fn add_required_request_headers_overwrite_custom_ua() {
        let svc = AddRequiredRequestHeadersLayer::new()
            .with_overwrite(true)
            .with_user_agent_header_value(HeaderValue::from_static("foo"))
            .into_layer(service_fn(async |req: Request| {
                assert_eq!(req.headers().get(HOST).unwrap(), "127.0.0.1");
                assert_eq!(
                    req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()),
                    Some("foo")
                );
                Ok::<_, Infallible>(rama_http_types::Response::new(Body::empty()))
            }));

        let req = Request::builder()
            .uri("http://127.0.0.1/")
            .header(HOST, "example.com")
            .header(USER_AGENT, "test")
            .body(Body::empty())
            .unwrap();

        let resp = svc.serve(req).await.unwrap();

        assert!(!resp.headers().contains_key(HOST));
        assert!(!resp.headers().contains_key(USER_AGENT));
    }
}
