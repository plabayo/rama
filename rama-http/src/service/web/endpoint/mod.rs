#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use std::convert::Infallible;

use rama_core::{
    Service,
    service::{BoxService, StaticOutput},
};

use crate::{Body, Request, Response, Version, matcher::HttpMatcher};

pub mod extract;
pub mod response;

use response::IntoResponse;

#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    pub(crate) matcher: HttpMatcher<Body>,
    pub(crate) service: BoxService<Request, Response, Infallible>,
}

/// Accept multiple types as an endpoint service for [`super::WebService`].
///
/// Function handlers enter a generic HTTP application context: HTTP/2 and HTTP/3
/// Cookie fields are joined before extraction. Existing [`Service<Request>`]
/// implementations retain their input unchanged, allowing transparent relays.
pub trait IntoEndpointService<T>: private::Sealed<T, ()> {
    type Service: Service<Request>;

    /// convert the type into a [`rama_core::Service`].
    fn into_endpoint_service(self) -> Self::Service;
}

/// Convert endpoints with state, using the same application boundary as
/// [`IntoEndpointService`].
pub trait IntoEndpointServiceWithState<T, State>: private::Sealed<T, State> {
    type Service: Service<Request>;

    /// convert the type into a [`rama_core::Service`] with state.
    fn into_endpoint_service_with_state(self, state: State) -> Self::Service;
}

impl<S> IntoEndpointService<(S,)> for S
where
    S: Service<Request>,
{
    type Service = Self;

    #[inline(always)]
    fn into_endpoint_service(self) -> Self::Service {
        self
    }
}

impl<S, State> IntoEndpointServiceWithState<(S,), State> for S
where
    S: Service<Request>,
{
    type Service = Self;

    fn into_endpoint_service_with_state(self, _state: State) -> Self::Service {
        self
    }
}

impl<O> IntoEndpointService<()> for Result<O, Infallible>
where
    O: Clone + Send + Sync + 'static,
{
    type Service = StaticOutput<O>;

    fn into_endpoint_service(self) -> Self::Service {
        StaticOutput::new(self.unwrap())
    }
}

impl<O> IntoEndpointService<Response> for O
where
    O: IntoResponse + Clone + Send + Sync + 'static,
{
    type Service = StaticOutput<O>;

    fn into_endpoint_service(self) -> Self::Service {
        StaticOutput::new(self)
    }
}

impl<O, State> IntoEndpointServiceWithState<(), State> for Result<O, Infallible>
where
    O: Clone + Send + Sync + 'static,
{
    type Service = StaticOutput<O>;

    fn into_endpoint_service_with_state(self, _state: State) -> Self::Service {
        self.into_endpoint_service()
    }
}

impl<O, State> IntoEndpointServiceWithState<Response, State> for O
where
    O: IntoResponse + Clone + Send + Sync + 'static,
{
    type Service = StaticOutput<O>;

    fn into_endpoint_service_with_state(self, _state: State) -> Self::Service {
        self.into_endpoint_service()
    }
}

mod service;
#[doc(inline)]
pub use service::EndpointServiceFn;

/// Create an endpoint service from a function with request extractors.
///
/// Before extraction, split HTTP/2 and HTTP/3 Cookie fields are joined with `; `,
/// as required when entering a generic HTTP application context by RFC 9113
/// §8.2.3 and RFC 9114 §4.2.1. Transport-aware services passed directly to a
/// router do not use this wrapper and retain their individual field lines.
pub struct EndpointServiceFnWrapper<F, T, State> {
    inner: F,
    _marker: std::marker::PhantomData<fn(T)>,
    state: State,
}

impl<F: std::fmt::Debug, T, State: std::fmt::Debug> std::fmt::Debug
    for EndpointServiceFnWrapper<F, T, State>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointServiceFnWrapper")
            .field("inner", &self.inner)
            .field("state", &self.state)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn(T)>()),
            )
            .finish()
    }
}

impl<F, T, State> Clone for EndpointServiceFnWrapper<F, T, State>
where
    F: Clone,
    State: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _marker: std::marker::PhantomData,
            state: self.state.clone(),
        }
    }
}

impl<F, T, State> Service<Request> for EndpointServiceFnWrapper<F, T, State>
where
    F: EndpointServiceFn<T, State>,
    T: Send + 'static,
    State: Send + Sync + Clone + 'static,
{
    type Output = F::Output;
    type Error = F::Error;

    async fn serve(&self, mut req: Request) -> Result<Self::Output, Self::Error> {
        if matches!(req.version(), Version::HTTP_2 | Version::HTTP_3) {
            crate::layer::remove_header::coalesce_cookie_headers(req.headers_mut());
        }
        self.inner.call(req, &self.state).await
    }
}

impl<F, T> IntoEndpointService<(F, T)> for F
where
    F: EndpointServiceFn<T, ()>,
    T: Send + 'static,
{
    type Service = EndpointServiceFnWrapper<F, T, ()>;

    fn into_endpoint_service(self) -> Self::Service {
        EndpointServiceFnWrapper {
            inner: self,
            _marker: std::marker::PhantomData,
            state: (),
        }
    }
}

impl<F, T, State> IntoEndpointServiceWithState<(F, T), State> for F
where
    F: EndpointServiceFn<T, State>,
    T: Send + 'static,
    State: Send + Sync + Clone + 'static,
{
    type Service = EndpointServiceFnWrapper<F, T, State>;

    fn into_endpoint_service_with_state(self, state: State) -> Self::Service {
        EndpointServiceFnWrapper {
            inner: self,
            _marker: std::marker::PhantomData,
            state,
        }
    }
}

mod private {
    use super::*;

    pub trait Sealed<T, State> {}

    impl<S, State> Sealed<(S,), State> for S where S: Service<Request> {}

    impl<O, State> Sealed<(), State> for Result<O, Infallible> {}

    impl<O, State> Sealed<Response, State> for O {}

    impl<F, T, State> Sealed<(F, T), State> for F where F: EndpointServiceFn<T, State> {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, HeaderMap, Method, Request, StatusCode, body::util::BodyExt};
    use extract::*;
    use rama_core::conversion::FromRef;

    fn assert_into_endpoint_service<T, I>(_: I)
    where
        I: IntoEndpointService<T>,
    {
    }

    fn split_cookie_request(version: Version) -> Request {
        let mut request = Request::builder()
            .uri("https://example.com/")
            .version(version)
            .body(Body::empty())
            .unwrap();
        let headers = request.headers_mut();
        headers.append(crate::header::COOKIE, crate::HeaderValue::from_static(""));
        headers.append("x-between", crate::HeaderValue::from_static("untouched"));
        let mut sensitive = crate::HeaderValue::from_static("session=secret");
        sensitive.set_sensitive(true);
        headers.append(crate::header::COOKIE, sensitive);
        headers.append(crate::header::COOKIE, crate::HeaderValue::from_static(""));
        request
    }

    fn assert_application_cookies(headers: &HeaderMap) {
        let cookies = headers.get_all(crate::header::COOKIE);
        let mut cookies = cookies.iter();
        let value = cookies.next().unwrap();
        assert_eq!(value, "; session=secret; ");
        assert!(value.is_sensitive());
        assert!(cookies.next().is_none());
        assert_eq!(headers["x-between"], "untouched");
    }

    #[tokio::test]
    async fn function_handlers_join_cookies_before_request_and_header_extraction() {
        let request_handler = (async |request: Request| {
            assert_application_cookies(request.headers());
            StatusCode::OK
        })
        .into_endpoint_service();
        let headers_handler = (async |headers: HeaderMap, _body: extract::Body| {
            assert_application_cookies(&headers);
            StatusCode::OK
        })
        .into_endpoint_service();

        for version in [Version::HTTP_2, Version::HTTP_3] {
            request_handler
                .serve(split_cookie_request(version))
                .await
                .unwrap();
            headers_handler
                .serve(split_cookie_request(version))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn routed_functions_join_cookies_but_transport_services_preserve_lines() {
        let application =
            crate::service::web::WebService::new().with_get("/", async |request: Request| {
                assert_application_cookies(request.headers());
                StatusCode::OK
            });
        let relay = rama_core::service::service_fn(async |request: Request| {
            let lines: Vec<_> = request
                .headers()
                .ordered_iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes(), value.is_sensitive()))
                .collect();
            assert_eq!(
                lines,
                [
                    ("cookie", b"".as_slice(), false),
                    ("x-between", b"untouched".as_slice(), false),
                    ("cookie", b"session=secret".as_slice(), true),
                    ("cookie", b"".as_slice(), false),
                ]
            );
            Ok::<_, Infallible>(StatusCode::OK)
        });
        let relay = crate::service::web::WebService::new().with_get("/", relay);

        for version in [Version::HTTP_2, Version::HTTP_3] {
            assert_eq!(
                application
                    .serve(split_cookie_request(version))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
            assert_eq!(
                relay
                    .serve(split_cookie_request(version))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
    }

    #[test]
    fn test_into_endpoint_service_static() {
        assert_into_endpoint_service(StatusCode::OK);
        assert_into_endpoint_service("hello");
        assert_into_endpoint_service("hello".to_owned());
    }

    #[tokio::test]
    async fn test_into_endpoint_service_impl() {
        #[derive(Debug, Clone)]
        struct OkService;

        impl Service<Request> for OkService {
            type Output = StatusCode;
            type Error = Infallible;

            async fn serve(&self, _req: Request) -> Result<Self::Output, Self::Error> {
                Ok(StatusCode::OK)
            }
        }

        let svc = OkService;
        let resp = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp, StatusCode::OK);

        assert_into_endpoint_service(svc)
    }

    #[test]
    fn test_into_endpoint_service_fn_no_param() {
        assert_into_endpoint_service(async || StatusCode::OK);
        assert_into_endpoint_service(async || "hello");
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_no_param() {
        let svc = async || StatusCode::OK;
        let svc = svc.into_endpoint_service();

        let res = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_single_param_request() {
        let svc = async |req: Request| req.uri().to_string();
        let svc = svc.into_endpoint_service();

        let res = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // native Uri preserves the empty path (no forced trailing `/`)
        assert_eq!(res, "http://example.com")
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_with_state() {
        let state = "test_string".to_owned();
        let svc = async |State(state): State<String>| state;
        let svc = svc.into_endpoint_service_with_state(state.clone());

        let res = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res, "test_string");
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_with_derived_state() {
        #[derive(Clone, Debug, Default, FromRef)]
        #[allow(dead_code)]
        struct GlobalState {
            numbers: u8,
            text: String,
        }

        let state = GlobalState {
            text: "test_string".to_owned(),
            ..Default::default()
        };

        let svc = async |State(state): State<GlobalState>| state.text;
        let svc = svc.into_endpoint_service_with_state(state.clone());

        let res = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res, "test_string");
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_single_param_host() {
        let svc = async |Host(host): Host| host.to_string();
        let svc = svc.into_endpoint_service();

        let res = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res, "example.com")
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_multi_param_host() {
        #[derive(Debug, Clone, serde::Deserialize)]
        struct Params {
            foo: String,
        }

        let svc = crate::service::web::WebService::default().with_get(
            "/{foo}/bar",
            async |Host(host): Host, Path(params): Path<Params>| {
                format!("{} => {}", host, params.foo)
            },
        );
        let svc = svc.into_endpoint_service();

        let resp = svc
            .serve(
                Request::builder()
                    .uri("http://example.com/42/bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "example.com => 42")
    }

    #[test]
    fn test_into_endpoint_service_fn_single_param() {
        #[derive(Debug, Clone, serde::Deserialize)]
        struct Params {
            foo: String,
        }

        assert_into_endpoint_service(async |_path: Path<Params>| StatusCode::OK);
        assert_into_endpoint_service(async |Path(params): Path<Params>| params.foo);
        assert_into_endpoint_service(async |Query(query): Query<Params>| query.foo);
        assert_into_endpoint_service(async |method: Method| method.to_string());
        assert_into_endpoint_service(async |req: Request| req.uri().to_string());
        assert_into_endpoint_service(async |_host: Host| StatusCode::OK);
        assert_into_endpoint_service(async |Host(_host): Host| StatusCode::OK);
    }

    #[test]
    fn test_into_endpoint_service_fn_max_arity_with_owned_parts_and_body() {
        assert_into_endpoint_service(
            async |_one: Method,
                   _two: Method,
                   _three: Method,
                   _four: Method,
                   _five: Method,
                   _six: Method,
                   _seven: Method,
                   _eight: Method,
                   _nine: Method,
                   _ten: Method,
                   _eleven: Method,
                   _headers: HeaderMap,
                   _body: extract::Body| { StatusCode::OK },
        );
    }
}
