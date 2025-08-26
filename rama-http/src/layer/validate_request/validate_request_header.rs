use super::{AcceptHeader, BoxValidateRequestFn, ValidateRequest};
use crate::{Request, Response};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Layer that applies [`ValidateRequestHeader`] which validates all requests.
///
/// See the [module docs](crate::layer::validate_request) for an example.
pub struct ValidateRequestHeaderLayer<T> {
    pub(crate) validate: T,
}

impl<T: fmt::Debug> fmt::Debug for ValidateRequestHeaderLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidateRequestHeaderLayer")
            .field("validate", &self.validate)
            .finish()
    }
}

impl<T> Clone for ValidateRequestHeaderLayer<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            validate: self.validate.clone(),
        }
    }
}

impl<ResBody> ValidateRequestHeaderLayer<AcceptHeader<ResBody>> {
    /// Validate requests have the required Accept header.
    ///
    /// The `Accept` header is required to be `*/*`, `type/*` or `type/subtype`,
    /// as configured.
    ///
    /// # Panics
    ///
    /// Panics if `header_value` is not in the form: `type/subtype`, such as `application/json`
    /// See `AcceptHeader::new` for when this method panics.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http::layer::validate_request::{AcceptHeader, ValidateRequestHeaderLayer};
    ///
    /// let layer = ValidateRequestHeaderLayer::<AcceptHeader>::accept("application/json");
    /// ```
    ///
    /// [`Accept`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept
    #[must_use]
    pub fn accept(value: &str) -> Self
    where
        ResBody: Default,
    {
        Self::custom(AcceptHeader::new(value))
    }
}

impl<T> ValidateRequestHeaderLayer<T> {
    /// Validate requests using a custom validator.
    pub fn custom(validate: T) -> Self {
        Self { validate }
    }
}

impl<F, A> ValidateRequestHeaderLayer<BoxValidateRequestFn<F, A>> {
    /// Validate requests using a custom validator Fn.
    pub fn custom_fn(validate: F) -> Self {
        Self {
            validate: BoxValidateRequestFn::new(validate),
        }
    }
}

impl<S, T> Layer<S> for ValidateRequestHeaderLayer<T>
where
    T: Clone,
{
    type Service = ValidateRequestHeader<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        ValidateRequestHeader::new(inner, self.validate.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ValidateRequestHeader::new(inner, self.validate)
    }
}

/// Middleware that validates requests.
///
/// See the [module docs](crate::layer::validate_request) for an example.
pub struct ValidateRequestHeader<S, T> {
    inner: S,
    pub(crate) validate: T,
}

impl<S: fmt::Debug, T: fmt::Debug> fmt::Debug for ValidateRequestHeader<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidateRequestHeader")
            .field("inner", &self.inner)
            .field("validate", &self.validate)
            .finish()
    }
}

impl<S, T> Clone for ValidateRequestHeader<S, T>
where
    S: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            validate: self.validate.clone(),
        }
    }
}

impl<S, T> ValidateRequestHeader<S, T> {
    fn new(inner: S, validate: T) -> Self {
        Self::custom(inner, validate)
    }

    define_inner_service_accessors!();
}

impl<S, ResBody> ValidateRequestHeader<S, AcceptHeader<ResBody>> {
    /// Validate requests have the required Accept header.
    ///
    /// The `Accept` header is required to be `*/*`, `type/*` or `type/subtype`,
    /// as configured.
    ///
    /// # Panics
    ///
    /// See `AcceptHeader::new` for when this method panics.
    pub fn accept(inner: S, value: &str) -> Self
    where
        ResBody: Default,
    {
        Self::custom(inner, AcceptHeader::new(value))
    }
}

impl<S, T> ValidateRequestHeader<S, T> {
    /// Validate requests using a custom validator.
    pub fn custom(inner: S, validate: T) -> Self {
        Self { inner, validate }
    }
}

impl<S, F, A> ValidateRequestHeader<S, BoxValidateRequestFn<F, A>> {
    /// Validate requests using a custom validator Fn.
    pub fn custom_fn(inner: S, validate: F) -> Self {
        Self {
            inner,
            validate: BoxValidateRequestFn::new(validate),
        }
    }
}

impl<ReqBody, ResBody, S, V> Service<Request<ReqBody>> for ValidateRequestHeader<S, V>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    V: ValidateRequest<ReqBody, ResponseBody = ResBody>,
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<ResBody>;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        match self.validate.validate(ctx, req).await {
            Ok((ctx, req)) => self.inner.serve(ctx, req).await,
            Err(res) => Ok(res),
        }
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    use crate::{Body, StatusCode, header};
    use rama_core::{Layer, error::BoxError, service::service_fn};

    #[tokio::test]
    async fn valid_accept_header() {
        let service =
            ValidateRequestHeaderLayer::accept("application/json").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_accept_header_accept_all_json() {
        let service =
            ValidateRequestHeaderLayer::accept("application/json").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "application/*")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_accept_header_accept_all() {
        let service =
            ValidateRequestHeaderLayer::accept("application/json").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "*/*")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_accept_header() {
        let service =
            ValidateRequestHeaderLayer::accept("application/json").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "invalid")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }
    #[tokio::test]
    async fn not_accepted_accept_header_subtype() {
        let service =
            ValidateRequestHeaderLayer::accept("application/json").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "application/strings")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn not_accepted_accept_header() {
        let service =
            ValidateRequestHeaderLayer::accept("application/json").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "text/strings")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn accepted_multiple_header_value() {
        let service =
            ValidateRequestHeaderLayer::accept("application/json").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "text/strings")
            .header(header::ACCEPT, "invalid, application/json")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn accepted_inner_header_value() {
        let service =
            ValidateRequestHeaderLayer::accept("application/json").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "text/strings, invalid, application/json")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn accepted_header_with_quotes_valid() {
        let value = "foo/bar; parisien=\"baguette, text/html, jambon, fromage\", application/*";
        let service =
            ValidateRequestHeaderLayer::accept("application/xml").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, value)
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn accepted_header_with_quotes_invalid() {
        let value = "foo/bar; parisien=\"baguette, text/html, jambon, fromage\"";
        let service = ValidateRequestHeaderLayer::accept("text/html").into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, value)
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    async fn echo<B>(req: Request<B>) -> Result<Response<B>, BoxError> {
        Ok(Response::new(req.into_body()))
    }
}
