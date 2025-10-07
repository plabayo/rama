//! Set required headers on the request, if they are missing.
//!
//! For now this only sets `Host` header on http/1.1,
//! as well as always a User-Agent for all versions.

use crate::{
    HeaderValue, Request, Response,
    header::{self, HOST, RAMA_ID_HEADER_VALUE, USER_AGENT},
    headers::HeaderMapExt,
};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    telemetry::tracing,
};
use rama_http_headers::Host;
use rama_net::http::RequestContext;
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Layer that applies [`AddRequiredRequestHeaders`] which adds a request header.
///
/// See [`AddRequiredRequestHeaders`] for more details.
#[derive(Debug, Clone, Default)]
pub struct AddRequiredRequestHeadersLayer {
    overwrite: bool,
    user_agent_header_value: Option<HeaderValue>,
}

impl AddRequiredRequestHeadersLayer {
    /// Create a new [`AddRequiredRequestHeadersLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            overwrite: false,
            user_agent_header_value: None,
        }
    }

    /// Set whether to overwrite the existing headers.
    /// If set to `true`, the headers will be overwritten.
    ///
    /// Default is `false`.
    #[must_use]
    pub const fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Set whether to overwrite the existing headers.
    /// If set to `true`, the headers will be overwritten.
    ///
    /// Default is `false`.
    pub fn set_overwrite(&mut self, overwrite: bool) -> &mut Self {
        self.overwrite = overwrite;
        self
    }

    /// Set a custom [`USER_AGENT`] header value.
    ///
    /// By default a versioned `rama` value is used.
    #[must_use]
    pub fn user_agent_header_value(mut self, value: HeaderValue) -> Self {
        self.user_agent_header_value = Some(value);
        self
    }

    /// Maybe set a custom [`USER_AGENT`] header value.
    ///
    /// By default a versioned `rama` value is used.
    #[must_use]
    pub fn maybe_user_agent_header_value(mut self, value: Option<HeaderValue>) -> Self {
        self.user_agent_header_value = value;
        self
    }

    /// Set a custom [`USER_AGENT`] header value.
    ///
    /// By default a versioned `rama` value is used.
    pub fn set_user_agent_header_value(&mut self, value: HeaderValue) -> &mut Self {
        self.user_agent_header_value = Some(value);
        self
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

/// Middleware that sets a header on the request.
#[derive(Clone)]
pub struct AddRequiredRequestHeaders<S> {
    inner: S,
    overwrite: bool,
    user_agent_header_value: Option<HeaderValue>,
}

impl<S> AddRequiredRequestHeaders<S> {
    /// Create a new [`AddRequiredRequestHeaders`].
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            overwrite: false,
            user_agent_header_value: None,
        }
    }

    /// Set whether to overwrite the existing headers.
    /// If set to `true`, the headers will be overwritten.
    ///
    /// Default is `false`.
    #[must_use]
    pub const fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Set whether to overwrite the existing headers.
    /// If set to `true`, the headers will be overwritten.
    ///
    /// Default is `false`.
    pub fn set_overwrite(&mut self, overwrite: bool) -> &mut Self {
        self.overwrite = overwrite;
        self
    }

    /// Set a custom [`USER_AGENT`] header value.
    ///
    /// By default a versioned `rama` value is used.
    #[must_use]
    pub fn user_agent_header_value(mut self, value: HeaderValue) -> Self {
        self.user_agent_header_value = Some(value);
        self
    }

    /// Maybe set a custom [`USER_AGENT`] header value.
    ///
    /// By default a versioned `rama` value is used.
    #[must_use]
    pub fn maybe_user_agent_header_value(mut self, value: Option<HeaderValue>) -> Self {
        self.user_agent_header_value = value;
        self
    }

    /// Set a custom [`USER_AGENT`] header value.
    ///
    /// By default a versioned `rama` value is used.
    pub fn set_user_agent_header_value(&mut self, value: HeaderValue) -> &mut Self {
        self.user_agent_header_value = Some(value);
        self
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
            .field("user_agent_header_value", &self.user_agent_header_value)
            .finish()
    }
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for AddRequiredRequestHeaders<S>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error: Into<BoxError>>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        if self.overwrite || !req.headers().contains_key(HOST) {
            let request_ctx = RequestContext::try_from(&req).context(
                "AddRequiredRequestHeaders: get/compute RequestContext to set authority",
            )?;
            if request_ctx.authority_has_default_port() {
                let host = request_ctx.authority.host().clone();
                tracing::trace!(
                    server.address = %host,
                    "add missing host from authority as host header",
                );
                req.headers_mut().typed_insert(Host::from(host));
            } else {
                let authority = request_ctx.authority;
                tracing::trace!(
                    server.address = %authority.host(),
                    server.port = %authority.port(),
                    "add missing authority as host header"
                );
                req.headers_mut().typed_insert(Host::from(authority));
            }
        }

        if self.overwrite {
            req.headers_mut().insert(
                USER_AGENT,
                self.user_agent_header_value
                    .as_ref()
                    .unwrap_or(&RAMA_ID_HEADER_VALUE)
                    .clone(),
            );
        } else if let header::Entry::Vacant(header) = req.headers_mut().entry(USER_AGENT) {
            header.insert(
                self.user_agent_header_value
                    .as_ref()
                    .unwrap_or(&RAMA_ID_HEADER_VALUE)
                    .clone(),
            );
        }

        self.inner.serve(req).await.map_err(Into::into)
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
            .user_agent_header_value(HeaderValue::from_static("foo"))
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
            .overwrite(true)
            .into_layer(service_fn(async |req: Request| {
                assert_eq!(req.headers().get(HOST).unwrap(), "127.0.0.1");
                assert_eq!(
                    req.headers().get(USER_AGENT).unwrap(),
                    RAMA_ID_HEADER_VALUE.to_str().unwrap()
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
            .overwrite(true)
            .user_agent_header_value(HeaderValue::from_static("foo"))
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
