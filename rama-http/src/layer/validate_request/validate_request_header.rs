use super::{AcceptHeader, BoxValidateRequestFn, ValidateRequest};
use crate::{Request, Response};
use rama_core::{Layer, Service};
use rama_error::OpaqueError;
use rama_http_types::mime::Mime;
use rama_utils::macros::define_inner_service_accessors;

/// Layer that applies [`ValidateRequestHeader`] which validates all requests.
///
/// See the [module docs](crate::layer::validate_request) for an example.
#[derive(Debug, Clone)]
pub struct ValidateRequestHeaderLayer<T> {
    pub(crate) validate: T,
}

impl<ResBody> ValidateRequestHeaderLayer<AcceptHeader<ResBody>> {
    /// Validate requests have the required Accept header.
    ///
    /// The `Accept` header is required to be `*/*`, `type/*` or `type/subtype`,
    /// as configured.
    ///
    /// # Errors
    ///
    /// Errors if `header_value` is not in the form: `type/subtype`, such as `application/json`
    pub fn try_accept_for_str(value: &str) -> Result<Self, OpaqueError> {
        Ok(Self::custom(AcceptHeader::try_new(value)?))
    }

    /// Validate requests have the required Accept header.
    ///
    /// The `Accept` header is required to be `*/*`, `type/*` or `type/subtype`,
    /// as configured.
    #[must_use]
    pub fn accept(mime: Mime) -> Self {
        Self::custom(AcceptHeader::new(mime))
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
#[derive(Debug, Clone)]
pub struct ValidateRequestHeader<S, T> {
    inner: S,
    pub(crate) validate: T,
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
    /// # Errors
    ///
    /// Errors if `header_value` is not in the form: `type/subtype`, such as `application/json`
    pub fn try_accept_for_str(inner: S, value: &str) -> Result<Self, OpaqueError> {
        Ok(Self::custom(inner, AcceptHeader::try_new(value)?))
    }

    /// Validate requests have the required Accept header.
    ///
    /// The `Accept` header is required to be `*/*`, `type/*` or `type/subtype`,
    /// as configured.
    #[must_use]
    pub fn accept(inner: S, mime: Mime) -> Self {
        Self::custom(inner, AcceptHeader::new(mime))
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

impl<ReqBody, ServiceResBody, ValidateResBody, S, V> Service<Request<ReqBody>>
    for ValidateRequestHeader<S, V>
where
    ReqBody: Send + 'static,
    ServiceResBody: Send + 'static,
    ValidateResBody: From<ServiceResBody> + Send + 'static,
    V: ValidateRequest<ReqBody, ResponseBody = ValidateResBody>,
    S: Service<Request<ReqBody>, Output = Response<ServiceResBody>>,
{
    type Output = Response<ValidateResBody>;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        match self.validate.validate(req).await {
            Ok(req) => Ok(self.inner.serve(req).await?.map(ValidateResBody::from)),
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
    use rama_http_types::mime::APPLICATION_JSON;

    #[tokio::test]
    async fn valid_accept_header() {
        let service = ValidateRequestHeaderLayer::try_accept_for_str("application/json")
            .unwrap()
            .into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_accept_header_with_mime() {
        let service =
            ValidateRequestHeaderLayer::accept(APPLICATION_JSON).into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_accept_header_accept_all_json() {
        let service = ValidateRequestHeaderLayer::try_accept_for_str("application/json")
            .unwrap()
            .into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "application/*")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_accept_header_accept_all() {
        let service = ValidateRequestHeaderLayer::try_accept_for_str("application/json")
            .unwrap()
            .into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "*/*")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_accept_header() {
        let service =
            ValidateRequestHeaderLayer::accept(APPLICATION_JSON).into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "invalid")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }
    #[tokio::test]
    async fn not_accepted_accept_header_subtype() {
        let service =
            ValidateRequestHeaderLayer::accept(APPLICATION_JSON).into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "application/strings")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn not_accepted_accept_header() {
        let service =
            ValidateRequestHeaderLayer::accept(APPLICATION_JSON).into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "text/strings")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn accepted_multiple_header_value() {
        let service =
            ValidateRequestHeaderLayer::accept(APPLICATION_JSON).into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "text/strings")
            .header(header::ACCEPT, "invalid, application/json")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn accepted_inner_header_value() {
        let service =
            ValidateRequestHeaderLayer::accept(APPLICATION_JSON).into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, "text/strings, invalid, application/json")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn accepted_header_with_quotes_valid() {
        let value = "foo/bar; parisien=\"baguette, text/html, jambon, fromage\", application/*";
        let service = ValidateRequestHeaderLayer::try_accept_for_str("application/xml")
            .unwrap()
            .into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, value)
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn accepted_header_with_quotes_invalid() {
        let value = "foo/bar; parisien=\"baguette, text/html, jambon, fromage\"";
        let service = ValidateRequestHeaderLayer::try_accept_for_str("text/html")
            .unwrap()
            .into_layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::ACCEPT, value)
            .body(Body::empty())
            .unwrap();

        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    async fn echo<B>(req: Request<B>) -> Result<Response<B>, BoxError> {
        Ok(Response::new(req.into_body()))
    }
}
