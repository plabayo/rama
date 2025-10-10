use crate::{
    Body, Request, Response, StatusCode, Uri,
    matcher::{HttpMatcher, UriParams},
    mime::Mime,
    service::{
        fs::{DirectoryServeMode, ServeDir},
        web::endpoint::response::IntoResponse,
    },
};
use rama_core::{
    extensions::Extensions,
    extensions::ExtensionsMut,
    matcher::Matcher,
    service::{BoxService, Service, service_fn},
};
use rama_utils::include_dir;

use std::{convert::Infallible, fmt, path::Path, sync::Arc};

use super::{IntoEndpointService, endpoint::Endpoint};

/// A basic web service that can be used to serve HTTP requests.
///
/// Note that this service boxes all the internal services, so it is not as efficient as it could be.
/// For those locations where you need do not desire the convenience over performance,
/// you can instead use a tuple of `(M, S)` tuples, where M is a matcher and S is a service,
/// e.g. `((MethodMatcher::GET, service_a), (MethodMatcher::POST, service_b), service_fallback)`.
pub struct WebService {
    endpoints: Vec<Arc<Endpoint>>,
    not_found: Arc<BoxService<Request, Response, Infallible>>,
}

impl std::fmt::Debug for WebService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebService").finish()
    }
}

impl Clone for WebService {
    fn clone(&self) -> Self {
        Self {
            endpoints: self.endpoints.clone(),
            not_found: self.not_found.clone(),
        }
    }
}

impl WebService {
    /// create a new web service
    pub(crate) fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            not_found: Arc::new(
                service_fn(async || Ok(StatusCode::NOT_FOUND.into_response())).boxed(),
            ),
        }
    }

    /// add a GET route to the web service, using the given service.
    #[must_use]
    pub fn get<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method_get().and_path(path);
        self.on(matcher, service)
    }

    /// add a POST route to the web service, using the given service.
    #[must_use]
    pub fn post<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method_post().and_path(path);
        self.on(matcher, service)
    }

    /// add a PUT route to the web service, using the given service.
    #[must_use]
    pub fn put<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method_put().and_path(path);
        self.on(matcher, service)
    }

    /// add a DELETE route to the web service, using the given service.
    #[must_use]
    pub fn delete<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method_delete().and_path(path);
        self.on(matcher, service)
    }

    /// add a PATCH route to the web service, using the given service.
    #[must_use]
    pub fn patch<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method_patch().and_path(path);
        self.on(matcher, service)
    }

    /// add a HEAD route to the web service, using the given service.
    #[must_use]
    pub fn head<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method_head().and_path(path);
        self.on(matcher, service)
    }

    /// add a OPTIONS route to the web service, using the given service.
    #[must_use]
    pub fn options<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method_options().and_path(path);
        self.on(matcher, service)
    }

    /// add a TRACE route to the web service, using the given service.
    #[must_use]
    pub fn trace<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method_trace().and_path(path);
        self.on(matcher, service)
    }

    /// nest a web service under the given path.
    ///
    /// The nested service will receive a request with the path prefix removed.
    #[must_use]
    pub fn nest<I, T>(self, prefix: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let prefix = format!("{}/*", prefix.trim_end_matches(['/', '*']));
        let matcher = HttpMatcher::path(prefix);
        let service = NestedService(service.into_endpoint_service());
        self.on(matcher, service)
    }

    /// serve the given file under the given path.
    #[must_use]
    pub fn file(self, prefix: &str, path: impl AsRef<Path>, mime: Mime) -> Self {
        let service = ServeDir::new_single_file(path, mime).fallback(self.not_found.clone());
        self.nest(prefix, service)
    }

    /// serve the given directory under the given path.
    #[inline]
    #[must_use]
    pub fn dir(self, prefix: &str, path: impl AsRef<Path>) -> Self {
        self.dir_with_serve_mode(prefix, path, Default::default())
    }

    /// serve the given directory under the given path,
    /// with a custom serve move.
    #[must_use]
    pub fn dir_with_serve_mode(
        self,
        prefix: &str,
        path: impl AsRef<Path>,
        mode: DirectoryServeMode,
    ) -> Self {
        let service = ServeDir::new(path)
            .fallback(self.not_found.clone())
            .with_directory_serve_mode(mode);
        self.nest(prefix, service)
    }

    /// serve the given embedded directory under the given path.
    #[inline]
    #[must_use]
    pub fn dir_embed(self, prefix: &str, dir: include_dir::Dir<'static>) -> Self {
        self.dir_embed_with_serve_mode(prefix, dir, Default::default())
    }

    /// serve the given embedded directory under the given path
    /// with a custom serve move.
    #[must_use]
    pub fn dir_embed_with_serve_mode(
        self,
        prefix: &str,
        dir: include_dir::Dir<'static>,
        mode: DirectoryServeMode,
    ) -> Self {
        let service = ServeDir::new_embedded(dir)
            .fallback(self.not_found.clone())
            .with_directory_serve_mode(mode);
        self.nest(prefix, service)
    }

    /// add a route to the web service which matches the given matcher, using the given service.
    #[must_use]
    pub fn on<I, T>(mut self, matcher: HttpMatcher<Body>, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let endpoint = Endpoint {
            matcher,
            service: service.into_endpoint_service().boxed(),
        };
        self.endpoints.push(Arc::new(endpoint));
        self
    }

    /// use the given service in case no match could be found.
    #[must_use]
    pub fn not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        self.not_found = Arc::new(service.into_endpoint_service().boxed());
        self
    }
}

struct NestedService<S>(S);

impl<S: fmt::Debug> fmt::Debug for NestedService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NestedService").field(&self.0).finish()
    }
}

impl<S: Clone> Clone for NestedService<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S> Service<Request> for NestedService<S>
where
    S: Service<Request>,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,

        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        // set the nested path
        let (mut parts, body) = req.into_parts();
        // get nested path
        let path = parts.extensions.get::<UriParams>().unwrap().glob().unwrap();

        let mut uri_parts = parts.uri.into_parts();
        let path_and_query = uri_parts.path_and_query.take().unwrap();
        match path_and_query.query() {
            Some(query) => {
                uri_parts.path_and_query = Some(format!("{path}?{query}").parse().unwrap());
            }
            None => {
                uri_parts.path_and_query = Some(path.parse().unwrap());
            }
        }
        parts.uri = Uri::from_parts(uri_parts).unwrap();
        let req = Request::from_parts(parts, body);

        // make the actual request
        self.0.serve(req)
    }
}

impl Default for WebService {
    fn default() -> Self {
        Self::new()
    }
}

impl Service<Request> for WebService {
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, mut req: Request) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();
        for endpoint in &self.endpoints {
            if endpoint.matcher.matches(Some(&mut ext), &req) {
                // insert the extensions that might be generated by the matcher(s) into the context
                req.extensions_mut().extend(ext);
                return endpoint.service.serve(req).await;
            }
            // clear the extensions for the next matcher
            ext.clear();
        }
        self.not_found.serve(req).await
    }
}

#[doc(hidden)]
#[macro_export]
/// Create a new [`Service`] from a chain of matcher-service tuples.
///
/// Think of it like the Rust match statement, but for http services.
/// Which is nothing more then a convenient wrapper to create a tuple of matcher-service tuples,
/// with the last tuple being the fallback service. And all services implement
/// the [`IntoEndpointService`] trait.
///
/// # Example
///
/// ```rust
/// use rama_http::matcher::{HttpMatcher, MethodMatcher};
/// use rama_http::{Body, Request, Response, StatusCode};
/// use rama_http::body::util::BodyExt;
/// use rama_core::{Service};
///
/// #[tokio::main]
/// async fn main() {
///   let svc = rama_http::service::web::match_service! {
///     HttpMatcher::get("/hello") => "hello",
///     HttpMatcher::post("/world") => "world",
///     MethodMatcher::CONNECT => "connect",
///     _ => StatusCode::NOT_FOUND,
///   };
///
///   let resp = svc.serve(
///
///       Request::post("https://www.test.io/world").body(Body::empty()).unwrap(),
///   ).await.unwrap();
///   assert_eq!(resp.status(), StatusCode::OK);
///   let body = resp.into_body().collect().await.unwrap().to_bytes();
///   assert_eq!(body, "world");
/// }
/// ```
///
/// Which is short for the following:
///
/// ```rust
/// use rama_http::matcher::{HttpMatcher, MethodMatcher};
/// use rama_http::{Body, Request, Response, StatusCode};
/// use rama_http::body::util::BodyExt;
/// use rama_http::service::web::IntoEndpointService;
/// use rama_core::{Service};
/// use rama_core::matcher::MatcherRouter;
///
/// #[tokio::main]
/// async fn main() {
///   let svc = MatcherRouter((
///     (HttpMatcher::get("/hello"), "hello".into_endpoint_service()),
///     (HttpMatcher::post("/world"), "world".into_endpoint_service()),
///     (MethodMatcher::CONNECT, "connect".into_endpoint_service()),
///     StatusCode::NOT_FOUND.into_endpoint_service(),
///   ));
///
///   let resp = svc.serve(
///
///      Request::post("https://www.test.io/world").body(Body::empty()).unwrap(),
///   ).await.unwrap();
///   assert_eq!(resp.status(), StatusCode::OK);
///   let body = resp.into_body().collect().await.unwrap().to_bytes();
///   assert_eq!(body, "world");
/// }
/// ```
///
/// As you can see it is pretty much the same, except that you need to explicitly ensure
/// that each service is an actual Endpoint service.
macro_rules! __match_service {
    ($($M:expr_2021 => $S:expr_2021),+, _ => $F:expr $(,)?) => {{
        use $crate::service::web::IntoEndpointService;
        use $crate::__macro_dep::__core::matcher::MatcherRouter;
        MatcherRouter(($(($M, $S.into_endpoint_service())),+, $F.into_endpoint_service()))
    }};
}

#[doc(inline)]
pub use crate::__match_service as match_service;

#[cfg(test)]
mod test {
    use crate::matcher::MethodMatcher;
    use crate::{Body, body::util::BodyExt};

    use super::*;

    async fn get_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<Request, Response = Response, Error = Infallible>,
    {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        service.serve(req).await.unwrap()
    }

    async fn post_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<Request, Response = Response, Error = Infallible>,
    {
        let req = Request::post(uri).body(Body::empty()).unwrap();
        service.serve(req).await.unwrap()
    }

    async fn connect_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<Request, Response = Response, Error = Infallible>,
    {
        let req = Request::connect(uri).body(Body::empty()).unwrap();
        service.serve(req).await.unwrap()
    }

    #[tokio::test]
    async fn test_web_service() {
        let svc = WebService::new()
            .get("/hello", "hello")
            .post("/world", "world");

        let res = get_response(&svc, "https://www.test.io/hello").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "hello");

        let res = post_response(&svc, "https://www.test.io/world").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "world");

        let res = get_response(&svc, "https://www.test.io/world").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res = get_response(&svc, "https://www.test.io").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_web_service_not_found() {
        let svc = WebService::new().not_found("not found");

        let res = get_response(&svc, "https://www.test.io/hello").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "not found");
    }

    #[tokio::test]
    async fn test_web_service_nest() {
        let svc = WebService::new().nest(
            "/api",
            WebService::new()
                .get("/hello", "hello")
                .post("/world", "world"),
        );

        let res = get_response(&svc, "https://www.test.io/api/hello").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "hello");

        let res = post_response(&svc, "https://www.test.io/api/world").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "world");

        let res = get_response(&svc, "https://www.test.io/api/world").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res = get_response(&svc, "https://www.test.io").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_web_service_dir() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let file_path = tmp_dir.path().join("index.html");
        std::fs::write(&file_path, "<h1>Hello, World!</h1>").unwrap();
        let style_dir = tmp_dir.path().join("style");
        std::fs::create_dir(&style_dir).unwrap();
        let file_path = style_dir.join("main.css");
        std::fs::write(&file_path, "body { background-color: red }").unwrap();

        let svc = WebService::new()
            .get("/api/version", "v1")
            .post("/api", StatusCode::FORBIDDEN)
            .dir("/", tmp_dir.path().to_str().unwrap());

        let res = get_response(&svc, "https://www.test.io/index.html").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "<h1>Hello, World!</h1>");

        let res = get_response(&svc, "https://www.test.io/style/main.css").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "body { background-color: red }");

        let res = get_response(&svc, "https://www.test.io/api/version").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "v1");

        let res = post_response(&svc, "https://www.test.io/api").await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = get_response(&svc, "https://www.test.io/notfound.html").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res = get_response(&svc, "https://www.test.io/").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "<h1>Hello, World!</h1>");
    }

    #[tokio::test]
    async fn test_matcher_service_tuples() {
        let svc = match_service! {
            HttpMatcher::get("/hello") => "hello",
            HttpMatcher::post("/world") => "world",
            MethodMatcher::CONNECT => "connect",
            _ => StatusCode::NOT_FOUND,
        };

        let res = get_response(&svc, "https://www.test.io/hello").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "hello");

        let res = post_response(&svc, "https://www.test.io/world").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "world");

        let res = connect_response(&svc, "https://www.test.io").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "connect");

        let res = get_response(&svc, "https://www.test.io/world").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res = get_response(&svc, "https://www.test.io").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
