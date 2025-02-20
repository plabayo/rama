use crate::{Body, IntoResponse, Request, Response, matcher::HttpMatcher};
use rama_core::{Context, Layer, Service, layer::MapResponseLayer, service::BoxService};
use std::future::Future;
use std::{convert::Infallible, fmt};

pub mod extract;

pub(crate) struct Endpoint<State> {
    pub(crate) matcher: HttpMatcher<State, Body>,
    pub(crate) service: BoxService<State, Request, Response, Infallible>,
}

/// utility trait to accept multiple types as an endpoint service for [`super::WebService`]
pub trait IntoEndpointService<State, T>: private::Sealed<T> {
    /// convert the type into a [`rama_core::Service`].
    fn into_endpoint_service(
        self,
    ) -> impl Service<State, Request, Response = Response, Error = Infallible>;
}

impl<State, S, R> IntoEndpointService<State, (State, R)> for S
where
    State: Clone + Send + Sync + 'static,
    S: Service<State, Request, Response = R, Error = Infallible>,
    R: IntoResponse + Send + Sync + 'static,
{
    fn into_endpoint_service(
        self,
    ) -> impl Service<State, Request, Response = Response, Error = Infallible> {
        MapResponseLayer::new(R::into_response).layer(self)
    }
}

impl<State, R> IntoEndpointService<State, ()> for R
where
    State: Clone + Send + Sync + 'static,
    R: IntoResponse + Clone + Send + Sync + 'static,
{
    fn into_endpoint_service(
        self,
    ) -> impl Service<State, Request, Response = Response, Error = Infallible> {
        StaticService(self)
    }
}

struct StaticService<R>(R);

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

impl<R, State> Service<State, Request> for StaticService<R>
where
    R: IntoResponse + Clone + Send + Sync + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, _: Context<State>, _: Request) -> Result<Self::Response, Self::Error> {
        Ok(self.0.clone().into_response())
    }
}

mod service;
#[doc(inline)]
pub use service::EndpointServiceFn;

struct EndpointServiceFnWrapper<F, S, T> {
    inner: F,
    _marker: std::marker::PhantomData<fn(S, T) -> ()>,
}

impl<F: std::fmt::Debug, S, T> std::fmt::Debug for EndpointServiceFnWrapper<F, S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointServiceFnWrapper")
            .field("inner", &self.inner)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn(S, T) -> ()>()),
            )
            .finish()
    }
}

impl<F, S, T> Clone for EndpointServiceFnWrapper<F, S, T>
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

impl<F, S, T> Service<S, Request> for EndpointServiceFnWrapper<F, S, T>
where
    F: EndpointServiceFn<S, T>,
    S: Clone + Send + Sync + 'static,
    T: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, ctx: Context<S>, req: Request) -> Result<Self::Response, Self::Error> {
        Ok(self.inner.call(ctx, req).await)
    }
}

impl<F, S, T> IntoEndpointService<S, (F, S, T)> for F
where
    F: EndpointServiceFn<S, T>,
    S: Clone + Send + Sync + 'static,
    T: Send + 'static,
{
    fn into_endpoint_service(
        self,
    ) -> impl Service<S, Request, Response = Response, Error = Infallible> {
        EndpointServiceFnWrapper {
            inner: self,
            _marker: std::marker::PhantomData,
        }
    }
}

mod private {
    use super::*;

    pub trait Sealed<T> {}

    impl<State, S, R> Sealed<(State, R)> for S
    where
        State: Clone + Send + Sync + 'static,
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
    }

    impl<State, F, Fut, R> Sealed<(State, F, Context<State>, Fut, R)> for F
    where
        State: Clone + Send + Sync + 'static,
        F: Fn(Context<State>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoResponse + Send + Sync + 'static,
    {
    }

    impl<State, F, Fut, R> Sealed<(State, F, Context<State>, Request, Fut, R)> for F
    where
        State: Clone + Send + Sync + 'static,
        F: Fn(Context<State>, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoResponse + Send + Sync + 'static,
    {
    }

    impl<R> Sealed<()> for R where R: IntoResponse + Send + Sync + 'static {}

    impl<F, S, T> Sealed<(F, S, T)> for F where F: EndpointServiceFn<S, T> {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, Method, Request, StatusCode, dep::http_body_util::BodyExt};
    use extract::*;

    fn assert_into_endpoint_service<T, I>(_: I)
    where
        I: IntoEndpointService<(), T>,
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

        impl<State> Service<State, Request> for OkService
        where
            State: Clone + Send + Sync + 'static,
        {
            type Response = StatusCode;
            type Error = Infallible;

            async fn serve(
                &self,
                _ctx: Context<State>,
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
        assert_into_endpoint_service(|| async { StatusCode::OK });
        assert_into_endpoint_service(|| async { "hello" });
    }

    #[tokio::test]
    async fn test_service_fn_wrapper_no_param() {
        let svc = || async { StatusCode::OK };
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
        let svc = |req: Request| async move { req.uri().to_string() };
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
        let svc = |Host(host): Host| async move { host.to_string() };
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
            |Host(host): Host, Path(params): Path<Params>| async move {
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

        assert_into_endpoint_service(|_path: Path<Params>| async { StatusCode::OK });
        assert_into_endpoint_service(|Path(params): Path<Params>| async move { params.foo });
        assert_into_endpoint_service(|Query(query): Query<Params>| async move { query.foo });
        assert_into_endpoint_service(|method: Method| async move { method.to_string() });
        assert_into_endpoint_service(|req: Request| async move { req.uri().to_string() });
        assert_into_endpoint_service(|_host: Host| async { StatusCode::OK });
        assert_into_endpoint_service(|Host(_host): Host| async { StatusCode::OK });
    }
}
