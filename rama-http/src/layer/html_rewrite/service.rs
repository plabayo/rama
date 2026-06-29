//! [`Service`] that rewrites `text/html` response bodies.

use std::fmt;
use std::sync::Arc;

use rama_core::error::BoxError;
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;

use super::HtmlRewriteBody;
use crate::headers::ContentType;
use crate::layer::remove_header::{
    remove_cache_validation_response_headers, remove_payload_metadata_headers,
};
use crate::layer::util::rewrite_policy::BodyRewritePolicy;
use crate::protocols::html::rewrite::ElementContentHandler;
use crate::protocols::html::selector::Selector;
use crate::{HeaderMap, Request, Response, StreamingBody};

/// Rewrites the `text/html` response bodies of the underlying service, using
/// rama's streaming [`HtmlRewriter`](crate::protocols::html::rewrite::HtmlRewriter).
///
/// See the [module docs](crate::layer::html_rewrite) for details. Construct it
/// directly with [`new`](Self::new) or via [`HtmlRewriteLayer`].
pub struct HtmlRewrite<S, H> {
    pub(crate) inner: S,
    pub(crate) selectors: Arc<[Selector]>,
    pub(crate) handler: H,
    policy: BodyRewritePolicy,
}

impl<S, H> HtmlRewrite<S, H> {
    /// Creates a new [`HtmlRewrite`] service.
    ///
    /// The `selector` index passed to the handler is the index into
    /// `selectors`; keep the two aligned.
    pub fn new(inner: S, selectors: impl IntoIterator<Item = Selector>, handler: H) -> Self {
        Self {
            inner,
            selectors: selectors.into_iter().collect(),
            handler,
            policy: BodyRewritePolicy::unencoded_content_type(is_html_content_type),
        }
    }

    /// Sets a custom response rewrite policy.
    ///
    /// The predicate receives the response headers and is responsible for any
    /// `Content-Encoding` / `Content-Type` checks it needs.
    #[must_use]
    pub fn with_rewrite_policy(
        mut self,
        policy: impl Fn(&HeaderMap) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.policy = BodyRewritePolicy::custom(policy);
        self
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug, H> fmt::Debug for HtmlRewrite<S, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HtmlRewrite")
            .field("inner", &self.inner)
            .field("selectors", &self.selectors)
            .field("handler", &std::any::type_name::<H>())
            .field("policy", &"<body rewrite policy>")
            .finish()
    }
}

impl<S: Clone, H: Clone> Clone for HtmlRewrite<S, H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
        }
    }
}

impl<S, H, ReqBody, ResBody> Service<Request<ReqBody>> for HtmlRewrite<S, H>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ResBody: StreamingBody<Data: Send + 'static, Error: Into<BoxError> + Send + 'static>
        + Send
        + 'static,
    H: ElementContentHandler + Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Output = Response<HtmlRewriteBody<ResBody, H>>;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(req).await?;
        let rewrite = !self.selectors.is_empty() && self.policy.should_rewrite(res.headers());
        let (mut parts, body) = res.into_parts();
        let body = if rewrite {
            // Rewriting changes the body length and invalidates range support,
            // so drop the now-stale payload metadata (Content-Length,
            // Transfer-Encoding, Accept-Ranges, …) and representation
            // validators (ETag, Last-Modified, …); the response becomes
            // chunked / unknown-length.
            remove_payload_metadata_headers(&mut parts.headers);
            remove_cache_validation_response_headers(&mut parts.headers);
            HtmlRewriteBody::new(body, &self.selectors, self.handler.clone())
        } else {
            HtmlRewriteBody::passthrough(body)
        };
        Ok(Response::from_parts(parts, body))
    }
}

/// Whether this content type is an HTML document that can be rewritten.
fn is_html_content_type(content_type: &ContentType) -> bool {
    // `essence_str` is the `type/subtype` without parameters (e.g. drops
    // `; charset=...`) and is already lower-cased by the mime parser.
    content_type.mime().essence_str() == "text/html"
}

/// Layer that applies [`HtmlRewrite`] to the responses of the wrapped service.
///
/// See the [module docs](crate::layer::html_rewrite).
pub struct HtmlRewriteLayer<H> {
    selectors: Arc<[Selector]>,
    handler: H,
    policy: BodyRewritePolicy,
}

impl<H> HtmlRewriteLayer<H> {
    /// Creates a new [`HtmlRewriteLayer`] that rewrites elements matching
    /// `selectors` with `handler` (the handler is cloned per response, so it
    /// starts fresh for each one).
    pub fn new(selectors: impl IntoIterator<Item = Selector>, handler: H) -> Self {
        Self {
            selectors: selectors.into_iter().collect(),
            handler,
            policy: BodyRewritePolicy::unencoded_content_type(is_html_content_type),
        }
    }

    /// Sets a custom response rewrite policy.
    ///
    /// The predicate receives the response headers and is responsible for any
    /// `Content-Encoding` / `Content-Type` checks it needs.
    #[must_use]
    pub fn with_rewrite_policy(
        mut self,
        policy: impl Fn(&HeaderMap) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.policy = BodyRewritePolicy::custom(policy);
        self
    }

    /// Wraps a body directly using this layer's selector set and handler.
    ///
    /// This is useful for services that need request-specific gating before
    /// deciding whether a single response body should be rewritten, while
    /// still sharing the same layer configuration.
    pub fn rewrite_body<B>(&self, body: B) -> HtmlRewriteBody<B, H>
    where
        H: ElementContentHandler + Clone,
    {
        HtmlRewriteBody::new(body, &self.selectors, self.handler.clone())
    }
}

impl<H: fmt::Debug> fmt::Debug for HtmlRewriteLayer<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HtmlRewriteLayer")
            .field("selectors", &self.selectors)
            .field("handler", &self.handler)
            .field("policy", &"<body rewrite policy>")
            .finish()
    }
}

impl<H: Clone> Clone for HtmlRewriteLayer<H> {
    fn clone(&self) -> Self {
        Self {
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
        }
    }
}

impl<S, H: Clone> Layer<S> for HtmlRewriteLayer<H> {
    type Service = HtmlRewrite<S, H>;

    fn layer(&self, inner: S) -> Self::Service {
        HtmlRewrite {
            inner,
            selectors: self.selectors.clone(),
            handler: self.handler.clone(),
            policy: self.policy.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HtmlRewrite {
            inner,
            selectors: self.selectors,
            handler: self.handler,
            policy: self.policy,
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
            ("text/html", true),
            ("text/html; charset=utf-8", true),
            ("application/xhtml+xml", false),
            ("application/json", false),
        ];

        for (content_type, expected) in cases {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                content_type.parse().expect("valid header"),
            );
            let content_type = headers.typed_get::<ContentType>().expect("content type");
            assert_eq!(
                is_html_content_type(&content_type),
                expected,
                "{content_type}"
            );
        }
    }

    #[test]
    fn rewrite_policy_skips_content_encoded_html() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "text/html".parse().unwrap());
        headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        let policy = BodyRewritePolicy::unencoded_content_type(is_html_content_type);
        assert!(!policy.should_rewrite(&headers));
    }
}
