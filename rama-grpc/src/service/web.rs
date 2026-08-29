//! Integration between gRPC services and Rama's web [`Router`].

use rama_core::{Layer, Service, extensions::Extensions, matcher::Matcher};
use rama_http::{
    Body, Request, StatusCode,
    header::CONTENT_TYPE,
    matcher::{HttpMatcher, VersionMatcher},
    mime::Mime,
    service::web::Router,
};
use std::convert::Infallible;

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
    /// Native gRPC requests use HTTP/2, `Content-Type: application/grpc` (with
    /// an optional structured suffix and parameters), and
    /// `POST /<service-name>/<method>`. Unlike mounting a nested service, this
    /// route does not strip the service name from the URI before forwarding
    /// the request.
    #[must_use]
    fn with_grpc_service<S>(self, service: S) -> Self
    where
        S: Service<Request> + NamedService,
        L: Layer<S, Service: Service<Request, Output = O, Error = E>>
            + Layer<UnsupportedGrpcContentType, Service: Service<Request, Output = O, Error = E>>;

    /// Register a generated gRPC service on this router.
    ///
    /// Native gRPC requests use HTTP/2, `Content-Type: application/grpc` (with
    /// an optional structured suffix and parameters), and
    /// `POST /<service-name>/<method>`. Unlike mounting a nested service, this
    /// route does not strip the service name from the URI before forwarding
    /// the request.
    fn set_grpc_service<S>(&mut self, service: S) -> &mut Self
    where
        S: Service<Request> + NamedService,
        L: Layer<S, Service: Service<Request, Output = O, Error = E>>
            + Layer<UnsupportedGrpcContentType, Service: Service<Request, Output = O, Error = E>>;
}

impl<State, L, O, E> RouterExt<State, L, O, E> for Router<State, L, O, E>
where
    State: Send + Sync + Clone + 'static,
{
    #[inline]
    fn with_grpc_service<S>(self, service: S) -> Self
    where
        S: Service<Request> + NamedService,
        L: Layer<S, Service: Service<Request, Output = O, Error = E>>
            + Layer<UnsupportedGrpcContentType, Service: Service<Request, Output = O, Error = E>>,
    {
        let route = grpc_service_route::<S>();
        self.with_match_route::<S, (S,)>(&route, grpc_service_matcher(), service)
            .with_fallback_match_route::<UnsupportedGrpcContentType, (UnsupportedGrpcContentType,)>(
                route,
                grpc_transport_matcher(),
                UnsupportedGrpcContentType,
            )
    }

    #[inline]
    fn set_grpc_service<S>(&mut self, service: S) -> &mut Self
    where
        S: Service<Request> + NamedService,
        L: Layer<S, Service: Service<Request, Output = O, Error = E>>
            + Layer<UnsupportedGrpcContentType, Service: Service<Request, Output = O, Error = E>>,
    {
        let route = grpc_service_route::<S>();
        self.set_match_route::<S, (S,)>(&route, grpc_service_matcher(), service)
            .set_fallback_match_route::<UnsupportedGrpcContentType, (UnsupportedGrpcContentType,)>(
                route,
                grpc_transport_matcher(),
                UnsupportedGrpcContentType,
            )
    }
}

#[inline]
fn grpc_service_route<S: NamedService>() -> String {
    format!("/{}/{{method}}", S::NAME)
}

#[inline]
fn grpc_service_matcher() -> HttpMatcher<Body> {
    grpc_transport_matcher().and_custom(GrpcContentTypeMatcher)
}

#[inline]
fn grpc_transport_matcher() -> HttpMatcher<Body> {
    HttpMatcher::method_post().and_version(VersionMatcher::HTTP_2)
}

#[derive(Debug, Clone, Copy)]
struct GrpcContentTypeMatcher;

impl<B> Matcher<Request<B>> for GrpcContentTypeMatcher {
    fn matches(&self, _ext: Option<&Extensions>, request: &Request<B>) -> bool {
        let mut values = request.headers().get_all(CONTENT_TYPE).iter();
        let Some(value) = values.next() else {
            return false;
        };
        values.next().is_none() && is_grpc_content_type(value.as_bytes())
    }
}

fn is_grpc_content_type(value: &[u8]) -> bool {
    let Ok(value) = core::str::from_utf8(value.trim_ascii()) else {
        return false;
    };
    // TODO: solve stricter RFC 9110 quoted-string and parameter-tail handling
    // centrally (upstream in `mime` or in Rama's MIME abstraction), rather
    // than growing a second media-type parser in this router.
    let Ok(media_type) = value.parse::<Mime>() else {
        return false;
    };

    media_type.type_() == "application"
        && media_type.subtype() == "grpc"
        && media_type
            .suffix()
            .is_none_or(|suffix| !suffix.as_str().is_empty())
}

/// Internal endpoint used to turn a native gRPC request with an invalid or
/// missing content type into the protocol-mandated 415 response.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct UnsupportedGrpcContentType;

impl Service<Request> for UnsupportedGrpcContentType {
    type Output = StatusCode;
    type Error = Infallible;

    async fn serve(&self, _request: Request) -> Result<Self::Output, Self::Error> {
        Ok(StatusCode::UNSUPPORTED_MEDIA_TYPE)
    }
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
        Body, HeaderValue, Method, Response, StatusCode, Version, layer::trace::TraceLayer,
        service::web::router::RouterError,
    };

    use crate::{metadata::GRPC_CONTENT_TYPE, service::LayerExt as _};

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

    #[derive(Debug, Clone, Copy)]
    struct AlternateService(StatusCode);

    impl Service<Request> for AlternateService {
        type Output = StatusCode;
        type Error = Infallible;

        async fn serve(&self, _request: Request) -> Result<Self::Output, Self::Error> {
            Ok(self.0)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct MountedService;

    impl Service<Request> for MountedService {
        type Output = Response;
        type Error = RouterError;

        async fn serve(&self, _request: Request) -> Result<Self::Output, Self::Error> {
            Ok(Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(Body::empty())
                .unwrap())
        }
    }

    fn request(method: Method, path: &'static str) -> Request {
        Request::builder()
            .method(method)
            .uri(path)
            .version(Version::HTTP_2)
            .header(CONTENT_TYPE, GRPC_CONTENT_TYPE)
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
    async fn accepts_grpc_content_type_suffixes_and_parameters() {
        let service = Router::new().with_grpc_service(TestGrpcService);

        for content_type in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+json; charset=utf-8",
            "application/grpc+json; charset=\"utf-8\"",
            "Application/Grpc+custom",
        ] {
            let response = service
                .serve(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/example.v1.TestService/Call")
                        .version(Version::HTTP_2)
                        .header(CONTENT_TYPE, content_type)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("router service");
            assert_eq!(response.status(), StatusCode::OK, "{content_type}");
        }
    }

    #[tokio::test]
    async fn invalid_grpc_content_type_falls_through_before_415() {
        let same_path = Router::new()
            .with_grpc_service(TestGrpcService)
            .with_match_route(
                "/example.v1.TestService/{method}",
                grpc_transport_matcher().and_header(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/grpc-web+proto"),
                ),
                AlternateService(StatusCode::ACCEPTED),
            );
        let request = Request::builder()
            .method(Method::POST)
            .uri("/example.v1.TestService/Call")
            .version(Version::HTTP_2)
            .header(CONTENT_TYPE, "application/grpc-web+proto")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            same_path.serve(request).await.unwrap().status(),
            StatusCode::ACCEPTED
        );

        let mounted = Router::new()
            .with_grpc_service(TestGrpcService)
            .with_sub_service("/example.v1.TestService", MountedService);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/example.v1.TestService/Call")
            .version(Version::HTTP_2)
            .header(CONTENT_TYPE, "application/grpc-web+proto")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            mounted.serve(request).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
    }

    #[tokio::test]
    async fn rejects_non_native_grpc_transport_and_content_type() {
        let service = Router::new().with_grpc_service(TestGrpcService);

        let http_1 = service
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri("/example.v1.TestService/Call")
                    .version(Version::HTTP_11)
                    .header(CONTENT_TYPE, GRPC_CONTENT_TYPE)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert!(matches!(http_1, Err(RouterError::MethodNotAllowed(_))));

        for content_type in [
            None,
            Some("text/plain"),
            Some("application/grpc-web"),
            Some("text/grpc"),
            Some("application/grpc+"),
            Some("application/grpc+bad+suffix"),
            Some("application/grpc+bad/suffix"),
            Some("application/grpc; charset"),
            Some("application/grpc; =utf-8"),
            Some("application/grpc; charset =utf-8"),
            Some("application/grpc; charset= utf-8"),
            Some("application/grpc; x=\"unterminated"),
            Some("application/grpc; x=\"closed\"tail"),
            Some("application /grpc"),
        ] {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/example.v1.TestService/Call")
                .version(Version::HTTP_2);
            if let Some(content_type) = content_type {
                request = request.header(CONTENT_TYPE, content_type);
            }
            let response = service
                .serve(request.body(Body::empty()).unwrap())
                .await
                .expect("invalid content type is a protocol response");
            assert_eq!(
                response.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{content_type:?}",
            );
        }

        let invalid_bytes = Request::builder()
            .method(Method::POST)
            .uri("/example.v1.TestService/Call")
            .version(Version::HTTP_2)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_bytes(b"application/grpc; x=\xff").unwrap(),
            )
            .body(Body::empty())
            .unwrap();
        let response = service
            .serve(invalid_bytes)
            .await
            .expect("invalid parameter bytes are a protocol response");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let mut duplicate = request(Method::POST, "/example.v1.TestService/Call");
        duplicate.headers_mut().append(
            CONTENT_TYPE,
            HeaderValue::from_static("application/grpc+proto"),
        );
        let response = service
            .serve(duplicate)
            .await
            .expect("duplicate content type is a protocol response");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
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
