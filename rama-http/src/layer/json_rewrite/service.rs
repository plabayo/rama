//! [`Service`]s that rewrite JSON request or response bodies.

use std::fmt;
use std::sync::Arc;

use rama_core::error::BoxError;
use rama_core::{Layer, Service};
use rama_json::path::JsonPath;
use rama_json::rewrite::JsonValueHandler;
use rama_json::tokenizer::DEFAULT_MAX_BUFFERED_BYTES;
use rama_utils::macros::define_inner_service_accessors;

use super::JsonRewriteBody;
use crate::headers::ContentType;
use crate::layer::remove_header::{
    remove_cache_validation_response_headers, remove_payload_metadata_headers,
};
use crate::layer::util::rewrite_policy::BodyRewritePolicy;
use crate::{HeaderMap, Request, Response, StreamingBody};

/// Rewrites JSON response bodies of the underlying service, using rama's
/// streaming [`JsonRewriter`](rama_json::rewrite::JsonRewriter).
///
/// See the [module docs](crate::layer::json_rewrite) for details. Construct it
/// directly with [`new`](Self::new) or via [`JsonRewriteLayer`].
pub struct JsonRewrite<S, H> {
    pub(crate) inner: S,
    pub(crate) selectors: Arc<[JsonPath]>,
    pub(crate) handler: H,
    policy: BodyRewritePolicy,
    max_buffered_bytes: usize,
}

impl<S, H> JsonRewrite<S, H> {
    /// Creates a new [`JsonRewrite`] service.
    ///
    /// The `selector` index passed to the handler is the index into
    /// `selectors`; keep the two aligned.
    pub fn new(inner: S, selectors: impl IntoIterator<Item = JsonPath>, handler: H) -> Self {
        Self {
            inner,
            selectors: selectors.into_iter().collect(),
            handler,
            policy: BodyRewritePolicy::unencoded_content_type(is_json_content_type),
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
        }
    }

    /// Sets a custom response rewrite policy.
    ///
    /// The predicate receives the response headers and can narrow rewriting
    /// beyond the built-in `Content-Encoding` guard.
    #[must_use]
    pub fn with_rewrite_policy(
        mut self,
        policy: impl Fn(&HeaderMap) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.policy = BodyRewritePolicy::custom(policy);
        self
    }

    /// Sets the tokenizer buffered-input limit for each rewritten body.
    #[must_use]
    pub fn with_max_buffered_bytes(mut self, max_buffered_bytes: usize) -> Self {
        self.max_buffered_bytes = max_buffered_bytes;
        self
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug, H> fmt::Debug for JsonRewrite<S, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonRewrite")
            .field("inner", &self.inner)
            .field("selectors", &self.selectors)
            .field("handler", &std::any::type_name::<H>())
            .field("policy", &self.policy)
            .field("max_buffered_bytes", &self.max_buffered_bytes)
            .finish()
    }
}

impl<S: Clone, H: Clone> Clone for JsonRewrite<S, H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
            max_buffered_bytes: self.max_buffered_bytes,
        }
    }
}

impl<S, H, ReqBody, ResBody> Service<Request<ReqBody>> for JsonRewrite<S, H>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ResBody: StreamingBody<Data: Send + 'static, Error: Into<BoxError> + Send + 'static>
        + Send
        + 'static,
    H: JsonValueHandler + Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Output = Response<JsonRewriteBody<ResBody, H>>;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(req).await?;
        let rewrite = !self.selectors.is_empty() && self.policy.should_rewrite(res.headers());
        let (mut parts, body) = res.into_parts();
        let body = if rewrite {
            // Rewriting changes the body length and invalidates range support,
            // so drop the now-stale payload metadata (Content-Length,
            // Transfer-Encoding, Accept-Ranges, ...) and representation
            // validators (ETag, Last-Modified, ...); the response becomes
            // chunked / unknown-length.
            remove_payload_metadata_headers(&mut parts.headers);
            remove_cache_validation_response_headers(&mut parts.headers);
            JsonRewriteBody::with_max_buffered_bytes(
                body,
                &self.selectors,
                self.handler.clone(),
                self.max_buffered_bytes,
            )
        } else {
            JsonRewriteBody::passthrough(body)
        };
        Ok(Response::from_parts(parts, body))
    }
}

/// Rewrites JSON request bodies before they reach the underlying service,
/// using rama's streaming [`JsonRewriter`](rama_json::rewrite::JsonRewriter).
///
/// See the [module docs](crate::layer::json_rewrite) for details. Construct it
/// directly with [`new`](Self::new) or via [`JsonRequestRewriteLayer`].
pub struct JsonRequestRewrite<S, H> {
    pub(crate) inner: S,
    pub(crate) selectors: Arc<[JsonPath]>,
    pub(crate) handler: H,
    policy: BodyRewritePolicy,
    max_buffered_bytes: usize,
}

impl<S, H> JsonRequestRewrite<S, H> {
    /// Creates a new [`JsonRequestRewrite`] service.
    ///
    /// The `selector` index passed to the handler is the index into
    /// `selectors`; keep the two aligned.
    pub fn new(inner: S, selectors: impl IntoIterator<Item = JsonPath>, handler: H) -> Self {
        Self {
            inner,
            selectors: selectors.into_iter().collect(),
            handler,
            policy: BodyRewritePolicy::unencoded_content_type(is_json_content_type),
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
        }
    }

    /// Sets a custom request rewrite policy.
    ///
    /// The predicate receives the request headers and can narrow rewriting
    /// beyond the built-in `Content-Encoding` guard.
    #[must_use]
    pub fn with_rewrite_policy(
        mut self,
        policy: impl Fn(&HeaderMap) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.policy = BodyRewritePolicy::custom(policy);
        self
    }

    /// Sets the tokenizer buffered-input limit for each rewritten body.
    #[must_use]
    pub fn with_max_buffered_bytes(mut self, max_buffered_bytes: usize) -> Self {
        self.max_buffered_bytes = max_buffered_bytes;
        self
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug, H> fmt::Debug for JsonRequestRewrite<S, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonRequestRewrite")
            .field("inner", &self.inner)
            .field("selectors", &self.selectors)
            .field("handler", &std::any::type_name::<H>())
            .field("policy", &self.policy)
            .field("max_buffered_bytes", &self.max_buffered_bytes)
            .finish()
    }
}

impl<S: Clone, H: Clone> Clone for JsonRequestRewrite<S, H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
            max_buffered_bytes: self.max_buffered_bytes,
        }
    }
}

impl<S, H, ReqBody> Service<Request<ReqBody>> for JsonRequestRewrite<S, H>
where
    S: Service<Request<JsonRewriteBody<ReqBody, H>>>,
    ReqBody: StreamingBody<Data: Send + 'static, Error: Into<BoxError> + Send + 'static>
        + Send
        + 'static,
    H: JsonValueHandler + Clone + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let rewrite = !self.selectors.is_empty() && self.policy.should_rewrite(req.headers());
        let (mut parts, body) = req.into_parts();
        let body = if rewrite {
            // Rewriting changes the request body length and transfer shape, so
            // drop stale payload metadata before forwarding upstream.
            remove_payload_metadata_headers(&mut parts.headers);
            JsonRewriteBody::with_max_buffered_bytes(
                body,
                &self.selectors,
                self.handler.clone(),
                self.max_buffered_bytes,
            )
        } else {
            JsonRewriteBody::passthrough(body)
        };
        self.inner.serve(Request::from_parts(parts, body)).await
    }
}

/// Whether this content type is JSON that can be rewritten.
fn is_json_content_type(content_type: &ContentType) -> bool {
    let mime = content_type.mime();
    mime.type_() == "application"
        && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"))
}

/// Layer that applies [`JsonRewrite`] to the responses of the wrapped service.
///
/// See the [module docs](crate::layer::json_rewrite).
pub struct JsonRewriteLayer<H> {
    selectors: Arc<[JsonPath]>,
    handler: H,
    policy: BodyRewritePolicy,
    max_buffered_bytes: usize,
}

/// Layer that applies [`JsonRequestRewrite`] to requests before they reach the
/// wrapped service.
///
/// See the [module docs](crate::layer::json_rewrite).
pub struct JsonRequestRewriteLayer<H> {
    selectors: Arc<[JsonPath]>,
    handler: H,
    policy: BodyRewritePolicy,
    max_buffered_bytes: usize,
}

impl<H> JsonRequestRewriteLayer<H> {
    /// Creates a new [`JsonRequestRewriteLayer`] that rewrites values matching
    /// `selectors` with `handler` (the handler is cloned per request, so it
    /// starts fresh for each one).
    pub fn new(selectors: impl IntoIterator<Item = JsonPath>, handler: H) -> Self {
        Self {
            selectors: selectors.into_iter().collect(),
            handler,
            policy: BodyRewritePolicy::unencoded_content_type(is_json_content_type),
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
        }
    }

    /// Sets a custom request rewrite policy.
    ///
    /// The predicate receives the request headers and can narrow rewriting
    /// beyond the built-in `Content-Encoding` guard.
    #[must_use]
    pub fn with_rewrite_policy(
        mut self,
        policy: impl Fn(&HeaderMap) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.policy = BodyRewritePolicy::custom(policy);
        self
    }

    /// Sets the tokenizer buffered-input limit for each rewritten body.
    #[must_use]
    pub fn with_max_buffered_bytes(mut self, max_buffered_bytes: usize) -> Self {
        self.max_buffered_bytes = max_buffered_bytes;
        self
    }

    /// Wraps a body directly using this layer's selector set and handler.
    ///
    /// This is useful for services that need request-specific gating before
    /// deciding whether a single request body should be rewritten, while
    /// still sharing the same layer configuration.
    pub fn rewrite_body<B>(&self, body: B) -> JsonRewriteBody<B, H>
    where
        H: JsonValueHandler + Clone,
    {
        JsonRewriteBody::with_max_buffered_bytes(
            body,
            &self.selectors,
            self.handler.clone(),
            self.max_buffered_bytes,
        )
    }
}

impl<H: fmt::Debug> fmt::Debug for JsonRequestRewriteLayer<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonRequestRewriteLayer")
            .field("selectors", &self.selectors)
            .field("handler", &self.handler)
            .field("policy", &self.policy)
            .field("max_buffered_bytes", &self.max_buffered_bytes)
            .finish()
    }
}

impl<H: Clone> Clone for JsonRequestRewriteLayer<H> {
    fn clone(&self) -> Self {
        Self {
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
            max_buffered_bytes: self.max_buffered_bytes,
        }
    }
}

impl<S, H: Clone> Layer<S> for JsonRequestRewriteLayer<H> {
    type Service = JsonRequestRewrite<S, H>;

    fn layer(&self, inner: S) -> Self::Service {
        JsonRequestRewrite {
            inner,
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
            max_buffered_bytes: self.max_buffered_bytes,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        JsonRequestRewrite {
            inner,
            selectors: self.selectors,
            handler: self.handler,
            policy: self.policy,
            max_buffered_bytes: self.max_buffered_bytes,
        }
    }
}

impl<H> JsonRewriteLayer<H> {
    /// Creates a new [`JsonRewriteLayer`] that rewrites values matching
    /// `selectors` with `handler` (the handler is cloned per response, so it
    /// starts fresh for each one).
    pub fn new(selectors: impl IntoIterator<Item = JsonPath>, handler: H) -> Self {
        Self {
            selectors: selectors.into_iter().collect(),
            handler,
            policy: BodyRewritePolicy::unencoded_content_type(is_json_content_type),
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
        }
    }

    /// Sets a custom response rewrite policy.
    ///
    /// The predicate receives the response headers and can narrow rewriting
    /// beyond the built-in `Content-Encoding` guard.
    #[must_use]
    pub fn with_rewrite_policy(
        mut self,
        policy: impl Fn(&HeaderMap) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.policy = BodyRewritePolicy::custom(policy);
        self
    }

    /// Sets the tokenizer buffered-input limit for each rewritten body.
    #[must_use]
    pub fn with_max_buffered_bytes(mut self, max_buffered_bytes: usize) -> Self {
        self.max_buffered_bytes = max_buffered_bytes;
        self
    }

    /// Wraps a body directly using this layer's selector set and handler.
    ///
    /// This is useful for services that need request-specific gating before
    /// deciding whether a single response body should be rewritten, while
    /// still sharing the same layer configuration.
    pub fn rewrite_body<B>(&self, body: B) -> JsonRewriteBody<B, H>
    where
        H: JsonValueHandler + Clone,
    {
        JsonRewriteBody::with_max_buffered_bytes(
            body,
            &self.selectors,
            self.handler.clone(),
            self.max_buffered_bytes,
        )
    }
}

impl<H: fmt::Debug> fmt::Debug for JsonRewriteLayer<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonRewriteLayer")
            .field("selectors", &self.selectors)
            .field("handler", &self.handler)
            .field("policy", &self.policy)
            .field("max_buffered_bytes", &self.max_buffered_bytes)
            .finish()
    }
}

impl<H: Clone> Clone for JsonRewriteLayer<H> {
    fn clone(&self) -> Self {
        Self {
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
            max_buffered_bytes: self.max_buffered_bytes,
        }
    }
}

impl<S, H: Clone> Layer<S> for JsonRewriteLayer<H> {
    type Service = JsonRewrite<S, H>;

    fn layer(&self, inner: S) -> Self::Service {
        JsonRewrite {
            inner,
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
            max_buffered_bytes: self.max_buffered_bytes,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        JsonRewrite {
            inner,
            selectors: self.selectors,
            handler: self.handler,
            policy: self.policy,
            max_buffered_bytes: self.max_buffered_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::HeaderMapExt;
    use crate::{HeaderMap, header};

    #[test]
    fn rewrite_content_type_policy() {
        let cases = [
            ("application/json", true),
            ("application/json; charset=utf-8", true),
            ("application/problem+json", true),
            ("text/json", false),
            ("text/plain", false),
        ];

        for (content_type, expected) in cases {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                content_type.parse().expect("valid header"),
            );
            let content_type = headers.typed_get::<ContentType>().expect("content type");
            assert_eq!(
                is_json_content_type(&content_type),
                expected,
                "{content_type}"
            );
        }
    }

    #[test]
    fn rewrite_policy_skips_content_encoded_json() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        let policy = BodyRewritePolicy::unencoded_content_type(is_json_content_type);
        assert!(!policy.should_rewrite(&headers));
    }
}
