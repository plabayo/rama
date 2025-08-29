use crate::{Body, Request, Response, matcher::HttpMatcher};
use rama_core::{Context, Layer, Service, layer::MapResponseLayer, service::BoxService};
use std::{convert::Infallible, fmt};

pub mod extract;
pub mod response;

use response::IntoResponse;

pub(crate) struct Endpoint {
    pub(crate) matcher: HttpMatcher<Body>,
    pub(crate) service: BoxService<Request, Response, Infallible>,
}

/// utility trait to accept multiple types as an endpoint service for [`super::WebService`]
pub trait IntoEndpointService<T>: private::Sealed<T> {
    /// convert the type into a [`rama_core::Service`].
    fn into_endpoint_service(
        self,
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

    async fn serve(&self, _: Context, _: Request) -> Result<Self::Response, Self::Error> {
        Ok(self.0.clone().into_response())
    }
}

mod service;
#[doc(inline)]
pub use service::EndpointServiceFn;

struct EndpointServiceFnWrapper<F, T> {
    inner: F,
    _marker: std::marker::PhantomData<fn(T) -> ()>,
}

impl<F: std::fmt::Debug, T> std::fmt::Debug for EndpointServiceFnWrapper<F, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointServiceFnWrapper")
            .field("inner", &self.inner)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn(T) -> ()>()),
            )
            .finish()
    }
}

impl<F, T> Clone for EndpointServiceFnWrapper<F, T>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T> Service<Request> for EndpointServiceFnWrapper<F, T>
where
    F: EndpointServiceFn<T>,
    T: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        Ok(self.inner.call(ctx, req).await)
    }
}

impl<F, T> IntoEndpointService<(F, T)> for F
where
    F: EndpointServiceFn<T>,
    T: Send + 'static,
{
    fn into_endpoint_service(
        self,
    ) -> impl Service<Request, Response = Response, Error = Infallible> {
        EndpointServiceFnWrapper {
            inner: self,
            _marker: std::marker::PhantomData,
        }
    }
}

mod private {
    use super::*;

    pub trait Sealed<T> {}

    impl<S, R> Sealed<(R,)> for S
    where
        S: Service<Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
    }

    impl<F, Fut, R> Sealed<(F, Context, Fut, R)> for F
    where
        F: Fn(Context) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoResponse + Send + Sync + 'static,
    {
    }

    impl<F, Fut, R> Sealed<(F, Context, Request, Fut, R)> for F
    where
        F: Fn(Context, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoResponse + Send + Sync + 'static,
    {
    }

    impl<R> Sealed<()> for R where R: IntoResponse + Send + Sync + 'static {}

    impl<F, T> Sealed<(F, T)> for F where F: EndpointServiceFn<T> {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, Method, Request, StatusCode, dep::http_body_util::BodyExt};
    use extract::*;

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

            async fn serve(
                &self,
                _ctx: Context,
                _req: Request,
            ) -> Result<Self::Response, Self::Error> {
                Ok(StatusCode::OK)
            }
        }

        let svc = OkService;
        let resp = svc
            .serve(
                Context::default(),
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
                Context::default(),
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
                Context::default(),
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
    async fn test_service_fn_wrapper_single_param_host() {
        let svc = async |Host(host): Host| host.to_string();
        let svc = svc.into_endpoint_service();

        let resp = svc
            .serve(
                Context::default(),
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
                Context::default(),
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
