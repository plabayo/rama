use std::convert::Infallible;

use rama_core::{
    Service,
    service::{BoxService, StaticService},
};

use crate::{Body, Request, Response, matcher::HttpMatcher};

pub mod extract;
pub mod response;

use response::IntoResponse;

#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    pub(crate) matcher: HttpMatcher<Body>,
    pub(crate) service: BoxService<Request, Response, Infallible>,
}

/// utility trait to accept multiple types as an endpoint service for [`super::WebService`]
pub trait IntoEndpointService<T, O, E>: private::Sealed<T, O, E, ()> {
    type Service: Service<Request, Output = O, Error = E>;

    /// convert the type into a [`rama_core::Service`].
    fn into_endpoint_service(self) -> Self::Service;
}

pub trait IntoEndpointServiceWithState<T, O, E, State>: private::Sealed<T, O, E, State> {
    type Service: Service<Request, Output = O, Error = E>;

    /// convert the type into a [`rama_core::Service`] with state.
    fn into_endpoint_service_with_state(self, state: State) -> Self::Service;
}

impl<S, O, E> IntoEndpointService<(S,), O, E> for S
where
    S: Service<Request, Output = O, Error = E>,
{
    type Service = Self;

    #[inline(always)]
    fn into_endpoint_service(self) -> Self::Service {
        self
    }
}

impl<S, O, E, State> IntoEndpointServiceWithState<(S,), O, E, State> for S
where
    S: Service<Request, Output = O, Error = E>,
{
    type Service = Self;

    fn into_endpoint_service_with_state(self, _state: State) -> Self::Service {
        self
    }
}

impl<O> IntoEndpointService<(), O, Infallible> for Result<O, Infallible>
where
    O: Clone + Send + Sync + 'static,
{
    type Service = StaticService<O>;

    fn into_endpoint_service(self) -> Self::Service {
        StaticService::new(self.unwrap())
    }
}

impl<O, State> IntoEndpointServiceWithState<(), O, Infallible, State> for Result<O, Infallible>
where
    O: Clone + Send + Sync + 'static,
{
    type Service = StaticService<O>;

    fn into_endpoint_service_with_state(self, _state: State) -> Self::Service {
        self.into_endpoint_service()
    }
}

mod service;
#[doc(inline)]
pub use service::EndpointServiceFn;

/// Wrapper svc used for creating a endpoint service from a function.
pub struct EndpointServiceFnWrapper<F, T, O, E, State> {
    inner: F,
    _marker: std::marker::PhantomData<fn(T) -> Result<O, E>>,
    state: State,
}

impl<F: std::fmt::Debug, T, O, E, State: std::fmt::Debug> std::fmt::Debug
    for EndpointServiceFnWrapper<F, T, O, E, State>
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

impl<F, T, O, E, State> Clone for EndpointServiceFnWrapper<F, T, O, E, State>
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

impl<F, O, E, T, State> Service<Request> for EndpointServiceFnWrapper<F, T, O, E, State>
where
    F: EndpointServiceFn<T, O, E, State>,
    T: Send + 'static,
    O: Send + 'static,
    E: Send + 'static,
    State: Send + Sync + Clone + 'static,
{
    type Output = O;
    type Error = E;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        self.inner.call(req, &self.state).await
    }
}

impl<F, T, O, E> IntoEndpointService<(F, T), O, E> for F
where
    F: EndpointServiceFn<T, O, E, ()>,
    T: Send + 'static,
    O: Send + 'static,
    E: Send + 'static,
{
    type Service = EndpointServiceFnWrapper<F, T, O, E, ()>;

    fn into_endpoint_service(self) -> Self::Service {
        EndpointServiceFnWrapper {
            inner: self,
            _marker: std::marker::PhantomData,
            state: (),
        }
    }
}

impl<F, O, E, T, State> IntoEndpointServiceWithState<(F, T), O, E, State> for F
where
    F: EndpointServiceFn<T, O, E, State>,
    T: Send + 'static,
    O: Send + 'static,
    E: Send + 'static,
    State: Send + Sync + Clone + 'static,
{
    type Service = EndpointServiceFnWrapper<F, T, O, E, State>;

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

    pub trait Sealed<T, O, E, State> {}

    impl<S, O, E, State> Sealed<(S,), O, E, State> for S where S: Service<Request, Output = O, Error = E>
    {}

    impl<O, State> Sealed<(), O, Infallible, State> for Result<O, Infallible> {}

    impl<F, O, E, T, State> Sealed<(F, T), O, E, State> for F where F: EndpointServiceFn<T, O, E, State> {}
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{Body, Method, Request, StatusCode, body::util::BodyExt};
//     use extract::*;
//     use rama_core::conversion::FromRef;
//
//     fn assert_into_endpoint_service<T, I>(_: I)
//     where
//         I: IntoEndpointService<T>,
//     {
//     }
//
//     #[test]
//     fn test_into_endpoint_service_static() {
//         assert_into_endpoint_service(StatusCode::OK);
//         assert_into_endpoint_service("hello");
//         assert_into_endpoint_service("hello".to_owned());
//     }
//
//     #[tokio::test]
//     async fn test_into_endpoint_service_impl() {
//         #[derive(Debug, Clone)]
//         struct OkService;
//
//         impl Service<Request> for OkService {
//             type Output = StatusCode;
//             type Error = Infallible;
//
//             async fn serve(&self, _req: Request) -> Result<Self::Output, Self::Error> {
//                 Ok(StatusCode::OK)
//             }
//         }
//
//         let svc = OkService;
//         let resp = svc
//             .serve(
//                 Request::builder()
//                     .uri("http://example.com")
//                     .body(Body::empty())
//                     .unwrap(),
//             )
//             .await
//             .unwrap();
//         assert_eq!(resp, StatusCode::OK);
//
//         assert_into_endpoint_service(svc)
//     }
//
//     #[test]
//     fn test_into_endpoint_service_fn_no_param() {
//         assert_into_endpoint_service(async || StatusCode::OK);
//         assert_into_endpoint_service(async || "hello");
//     }
//
//     #[tokio::test]
//     async fn test_service_fn_wrapper_no_param() {
//         let svc = async || StatusCode::OK;
//         let svc = svc.into_endpoint_service();
//
//         let resp = svc
//             .serve(
//                 Request::builder()
//                     .uri("http://example.com")
//                     .body(Body::empty())
//                     .unwrap(),
//             )
//             .await
//             .unwrap();
//         assert_eq!(resp.status(), StatusCode::OK);
//     }
//
//     #[tokio::test]
//     async fn test_service_fn_wrapper_single_param_request() {
//         let svc = async |req: Request| req.uri().to_string();
//         let svc = svc.into_endpoint_service();
//
//         let resp = svc
//             .serve(
//                 Request::builder()
//                     .uri("http://example.com")
//                     .body(Body::empty())
//                     .unwrap(),
//             )
//             .await
//             .unwrap();
//         assert_eq!(resp.status(), StatusCode::OK);
//         let body = resp.into_body().collect().await.unwrap().to_bytes();
//         assert_eq!(body, "http://example.com/")
//     }
//
//     #[tokio::test]
//     async fn test_service_fn_wrapper_with_state() {
//         let state = "test_string".to_owned();
//         let svc = async |State(state): State<String>| state;
//         let svc = svc.into_endpoint_service_with_state(state.clone());
//
//         let resp = svc
//             .serve(
//                 Request::builder()
//                     .uri("http://example.com")
//                     .body(Body::empty())
//                     .unwrap(),
//             )
//             .await
//             .unwrap();
//         assert_eq!(resp.status(), StatusCode::OK);
//         let body = resp.into_body().collect().await.unwrap().to_bytes();
//         assert_eq!(body, "test_string");
//     }
//
//     #[tokio::test]
//     async fn test_service_fn_wrapper_with_derived_state() {
//         #[derive(Clone, Debug, Default, FromRef)]
//         #[allow(dead_code)]
//         struct GlobalState {
//             numbers: u8,
//             text: String,
//         }
//
//         let state = GlobalState {
//             text: "test_string".to_owned(),
//             ..Default::default()
//         };
//
//         let svc = async |State(state): State<GlobalState>| state.text;
//         let svc = svc.into_endpoint_service_with_state(state.clone());
//
//         let resp = svc
//             .serve(
//                 Request::builder()
//                     .uri("http://example.com")
//                     .body(Body::empty())
//                     .unwrap(),
//             )
//             .await
//             .unwrap();
//         assert_eq!(resp.status(), StatusCode::OK);
//         let body = resp.into_body().collect().await.unwrap().to_bytes();
//         assert_eq!(body, "test_string");
//     }
//
//     #[tokio::test]
//     async fn test_service_fn_wrapper_single_param_host() {
//         let svc = async |Host(host): Host| host.to_string();
//         let svc = svc.into_endpoint_service();
//
//         let resp = svc
//             .serve(
//                 Request::builder()
//                     .uri("http://example.com")
//                     .body(Body::empty())
//                     .unwrap(),
//             )
//             .await
//             .unwrap();
//         assert_eq!(resp.status(), StatusCode::OK);
//         let body = resp.into_body().collect().await.unwrap().to_bytes();
//         assert_eq!(body, "example.com")
//     }
//
//     #[tokio::test]
//     async fn test_service_fn_wrapper_multi_param_host() {
//         #[derive(Debug, Clone, serde::Deserialize)]
//         struct Params {
//             foo: String,
//         }
//
//         let svc = crate::service::web::WebService::default().with_get(
//             "/{foo}/bar",
//             async |Host(host): Host, Path(params): Path<Params>| {
//                 format!("{} => {}", host, params.foo)
//             },
//         );
//         let svc = svc.into_endpoint_service();
//
//         let resp = svc
//             .serve(
//                 Request::builder()
//                     .uri("http://example.com/42/bar")
//                     .body(Body::empty())
//                     .unwrap(),
//             )
//             .await
//             .unwrap();
//         assert_eq!(resp.status(), StatusCode::OK);
//         let body = resp.into_body().collect().await.unwrap().to_bytes();
//         assert_eq!(body, "example.com => 42")
//     }
//
//     #[test]
//     fn test_into_endpoint_service_fn_single_param() {
//         #[derive(Debug, Clone, serde::Deserialize)]
//         struct Params {
//             foo: String,
//         }
//
//         assert_into_endpoint_service(async |_path: Path<Params>| StatusCode::OK);
//         assert_into_endpoint_service(async |Path(params): Path<Params>| params.foo);
//         assert_into_endpoint_service(async |Query(query): Query<Params>| query.foo);
//         assert_into_endpoint_service(async |method: Method| method.to_string());
//         assert_into_endpoint_service(async |req: Request| req.uri().to_string());
//         assert_into_endpoint_service(async |_host: Host| StatusCode::OK);
//         assert_into_endpoint_service(async |Host(_host): Host| StatusCode::OK);
//     }
// }
