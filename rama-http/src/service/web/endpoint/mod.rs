use crate::{Body, Request, Response, matcher::HttpMatcher};
use rama_core::{Layer, Service, layer::MapResponseLayer, service::BoxService};
use std::{convert::Infallible, fmt};

pub mod extract;
pub mod response;

use response::IntoResponse;

pub(crate) struct Endpoint {
    pub(crate) matcher: HttpMatcher<Body>,
    pub(crate) service: BoxService<Request, Response, Infallible>,
}

/// utility trait to accept multiple types as an endpoint service for [`super::WebService`]
pub trait IntoEndpointService<T>: private::Sealed<T, ()> {
    /// convert the type into a [`rama_core::Service`].
    fn into_endpoint_service(
        self,
    ) -> impl Service<Request, Response = Response, Error = Infallible>;
}

pub trait IntoEndpointServiceWithState<T, State>: private::Sealed<T, State> {
    /// convert the type into a [`rama_core::Service`] with state.
    fn into_endpoint_service_with_state(
        self,
        state: State,
    ) -> impl Service<Request, Response = Response, Error = Infallible>;
}

impl<S, R> IntoEndpointService<(R,)> for S
where
    S: Service<Request, Response = R, Error = Infallible>,
    R: IntoResponse + Send + Sync + 'static,
{
    fn into_endpoint_service(
        self,
    ) -> impl Service<Request, Response = Response, Error = Infallible> {
        MapResponseLayer::new(R::into_response).into_layer(self)
    }
}

impl<S, R, State> IntoEndpointServiceWithState<(R,), State> for S
where
    S: Service<Request, Response = R, Error = Infallible>,
    R: IntoResponse + Send + Sync + 'static,
{
    fn into_endpoint_service_with_state(
        self,
        _state: State,
    ) -> impl Service<Request, Response = Response, Error = Infallible> {
        MapResponseLayer::new(R::into_response).into_layer(self)
    }
}

impl<R> IntoEndpointService<()> for R
where
    R: IntoResponse + Clone + Send + Sync + 'static,
{
    fn into_endpoint_service(
        self,
    ) -> impl Service<Request, Response = Response, Error = Infallible> {
        StaticService(self)
    }
}

impl<R, State> IntoEndpointServiceWithState<(), State> for R
where
    R: IntoResponse + Clone + Send + Sync + 'static,
{
    fn into_endpoint_service_with_state(
        self,
        _state: State,
    ) -> impl Service<Request, Response = Response, Error = Infallible> {
        StaticService(self)
    }
}

/// A static [`Service`] that serves a pre-defined response.
pub struct StaticService<R>(R);

impl<R> StaticService<R>
where
    R: IntoResponse + Clone + Send + Sync + 'static,
{
    /// Create a new [`StaticService`] with the given response.
    pub fn new(response: R) -> Self {
        Self(response)
    }
}

impl<T> fmt::Debug for StaticService<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StaticService").field(&self.0).finish()
    }
}

impl<R> Clone for StaticService<R>
where
    R: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<R> Service<Request> for StaticService<R>
where
    R: IntoResponse + Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, _: Request) -> Result<Self::Response, Self::Error> {
        Ok(self.0.clone().into_response())
    }
}

mod service;
#[doc(inline)]
pub use service::EndpointServiceFn;

struct EndpointServiceFnWrapper<F, T, State> {
    inner: F,
    _marker: std::marker::PhantomData<fn(T) -> ()>,
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
                &format_args!("{}", std::any::type_name::<fn(T) -> ()>()),
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
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        Ok(self.inner.call(req, &self.state).await)
    }
}

impl<F, T> IntoEndpointService<(F, T)> for F
where
    F: EndpointServiceFn<T, ()>,
    T: Send + 'static,
{
    fn into_endpoint_service(
        self,
    ) -> impl Service<Request, Response = Response, Error = Infallible> {
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
    fn into_endpoint_service_with_state(
        self,
        state: State,
    ) -> impl Service<Request, Response = Response, Error = Infallible> {
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

    impl<S, R, State> Sealed<(R,), State> for S
    where
        S: Service<Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
    }

    impl<R, State> Sealed<(), State> for R where R: IntoResponse + Send + Sync + 'static {}

    impl<F, T, State> Sealed<(F, T), State> for F where F: EndpointServiceFn<T, State> {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, Method, Request, StatusCode, body::util::BodyExt};
    use extract::*;
    use rama_core::conversion::FromRef;

    fn assert_into_endpoint_service<T, I>(_: I)
    where
        I: IntoEndpointService<T>,
    {
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
            type Response = StatusCode;
            type Error = Infallible;

            async fn serve(&self, _req: Request) -> Result<Self::Response, Self::Error> {
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

        let resp = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_single_param_request() {
        let svc = async |req: Request| req.uri().to_string();
        let svc = svc.into_endpoint_service();

        let resp = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "http://example.com/")
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_with_state() {
        let state = "test_string".to_owned();
        let svc = async |State(state): State<String>| state;
        let svc = svc.into_endpoint_service_with_state(state.clone());

        let resp = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "test_string");
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

        let svc = async |State(state): State<String>| state;
        let svc = svc.into_endpoint_service_with_state(state.clone());

        let resp = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "test_string");
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_single_param_host() {
        let svc = async |Host(host): Host| host.to_string();
        let svc = svc.into_endpoint_service();

        let resp = svc
            .serve(
                Request::builder()
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "example.com")
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_multi_param_host() {
        #[derive(Debug, Clone, serde::Deserialize)]
        struct Params {
            foo: String,
        }

        let svc = crate::service::web::WebService::default().get(
            "/:foo/bar",
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
}
