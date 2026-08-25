//! Integration between gRPC services and Rama's web [`Router`].

use rama_core::{Layer, Service};
use rama_http::{Request, service::web::Router};

use crate::server::NamedService;

/// Sealed extension methods for registering generated gRPC services on a web [`Router`].
///
/// Import this trait to make [`RouterExt::with_grpc_service`] and
/// [`RouterExt::set_grpc_service`] available on [`Router`]. The route is derived from
/// [`NamedService::NAME`] and preserves the canonical gRPC request URI:
/// `/<package>.<Service>/<Method>`.
pub trait RouterExt<State, L, O, E>: private::Sealed {
    /// Register a generated gRPC service and return the updated router.
    ///
    /// gRPC requests use `POST /<service-name>/<method>`. Unlike mounting a nested service,
    /// this route does not strip the service name from the URI before forwarding the request.
    #[must_use]
    fn with_grpc_service<S>(self, service: S) -> Self
    where
        S: Service<Request> + NamedService,
        L: Layer<S, Service: Service<Request, Output = O, Error = E>>;

    /// Register a generated gRPC service on this router.
    ///
    /// gRPC requests use `POST /<service-name>/<method>`. Unlike mounting a nested service,
    /// this route does not strip the service name from the URI before forwarding the request.
    fn set_grpc_service<S>(&mut self, service: S) -> &mut Self
    where
        S: Service<Request> + NamedService,
        L: Layer<S, Service: Service<Request, Output = O, Error = E>>;
}

impl<State, L, O, E> RouterExt<State, L, O, E> for Router<State, L, O, E>
where
    State: Send + Sync + Clone + 'static,
{
    #[inline]
    fn with_grpc_service<S>(self, service: S) -> Self
    where
        S: Service<Request> + NamedService,
        L: Layer<S, Service: Service<Request, Output = O, Error = E>>,
    {
        self.with_post::<S, (S,)>(grpc_service_route::<S>(), service)
    }

    #[inline]
    fn set_grpc_service<S>(&mut self, service: S) -> &mut Self
    where
        S: Service<Request> + NamedService,
        L: Layer<S, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_post::<S, (S,)>(grpc_service_route::<S>(), service)
    }
}

#[inline]
fn grpc_service_route<S: NamedService>() -> String {
    format!("/{}/{{method}}", S::NAME)
}

mod private {
    use rama_http::service::web::Router;

    pub trait Sealed {}

    impl<State, L, O, E> Sealed for Router<State, L, O, E> {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    use rama_http::{
        Body, Method, Response, StatusCode, layer::trace::TraceLayer,
        service::web::router::RouterError,
    };

    use crate::service::LayerExt as _;

    #[derive(Debug, Clone, Copy)]
    struct TestGrpcService;

    impl NamedService for TestGrpcService {
        const NAME: &'static str = "example.v1.TestService";
    }

    impl Service<Request> for TestGrpcService {
        type Output = Response;
        type Error = Infallible;

        async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
            let path = request
                .uri()
                .path()
                .unwrap_or_default()
                .as_encoded_str()
                .into_owned();
            Ok(Response::builder()
                .header("x-seen-path", path)
                .body(Body::empty())
                .expect("valid response"))
        }
    }

    fn request(method: Method, path: &'static str) -> Request {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .expect("valid request")
    }

    #[tokio::test]
    async fn routes_post_to_named_service_without_stripping_its_path() {
        let service = Router::new().with_grpc_service(TestGrpcService);

        let response = service
            .serve(request(Method::POST, "/example.v1.TestService/Call"))
            .await
            .expect("router service");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-seen-path"],
            "/example.v1.TestService/Call"
        );
    }

    #[tokio::test]
    async fn only_routes_post_for_the_registered_service() {
        let service = Router::new().with_grpc_service(TestGrpcService);

        let wrong_method = service
            .serve(request(Method::GET, "/example.v1.TestService/Call"))
            .await;
        assert!(matches!(
            wrong_method,
            Err(RouterError::MethodNotAllowed(_))
        ));

        let unknown_service = service
            .serve(request(Method::POST, "/example.v1.OtherService/Call"))
            .await;
        assert!(matches!(unknown_service, Err(RouterError::NotFound)));
    }

    #[tokio::test]
    async fn supports_mutable_registration() {
        let mut service = Router::new();
        service.set_grpc_service(TestGrpcService);

        let response = service
            .serve(request(Method::POST, "/example.v1.TestService/Call"))
            .await
            .expect("router service");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn supports_named_grpc_middleware() {
        let service = Router::new()
            .with_grpc_service(TraceLayer::new_for_grpc().named_layer(TestGrpcService));

        let response = service
            .serve(request(Method::POST, "/example.v1.TestService/Call"))
            .await
            .expect("router service");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
