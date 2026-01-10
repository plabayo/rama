use crate::{
    Body, Request, Response, StatusCode,
    matcher::HttpMatcher,
    mime::Mime,
    service::{
        fs::{DirectoryServeMode, ServeDir},
        web::{IntoEndpointServiceWithState, endpoint::response::IntoResponse},
    },
    uri::try_to_strip_path_prefix_from_uri,
};

use rama_core::{
    extensions::Extensions,
    extensions::ExtensionsMut,
    matcher::Matcher,
    service::{BoxService, Service, service_fn},
    telemetry::tracing,
};
use rama_http_types::OriginalRouterUri;
use rama_utils::{include_dir, str::arcstr::ArcStr};

use std::{convert::Infallible, path::Path, sync::Arc};

use super::{IntoEndpointService, endpoint::Endpoint};

/// A basic web service that can be used to serve HTTP requests.
///
/// Note that this service boxes all the internal services, so it is not as efficient as it could be.
/// For those locations where you need do not desire the convenience over performance,
/// you can instead use a tuple of `(M, S)` tuples, where M is a matcher and S is a service,
/// e.g. `((MethodMatcher::GET, service_a), (MethodMatcher::POST, service_b), service_fallback)`.
#[derive(Debug, Clone)]
pub struct WebService<State = ()> {
    endpoints: Vec<Arc<Endpoint>>,
    not_found: BoxService<Request, Response, Infallible>,
    state: State,
}

impl WebService {
    #[must_use]
    /// create a new web service
    pub fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            not_found: service_fn(async || Ok(StatusCode::NOT_FOUND.into_response())).boxed(),
            state: (),
        }
    }
}

impl<State> WebService<State>
where
    State: Send + Sync + Clone + 'static,
{
    pub fn new_with_state(state: State) -> Self {
        Self {
            endpoints: Vec::new(),
            not_found: service_fn(async || Ok(StatusCode::NOT_FOUND.into_response())).boxed(),
            state,
        }
    }

    /// add a GET route to the web service, using the given service.
    #[must_use]
    #[inline]
    pub fn with_get<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_get().and_path(path);
        self.with_matcher(matcher, service)
    }

    /// add a GET route to the web service, using the given service.
    #[inline]
    pub fn set_get<I, T>(&mut self, path: &str, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_get().and_path(path);
        self.set_matcher(matcher, service)
    }

    /// add a POST route to the web service, using the given service.
    #[must_use]
    #[inline]
    pub fn with_post<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_post().and_path(path);
        self.with_matcher(matcher, service)
    }

    /// add a POST route to the web service, using the given service.
    #[inline]
    pub fn set_post<I, T>(&mut self, path: &str, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_post().and_path(path);
        self.set_matcher(matcher, service)
    }

    /// add a PUT route to the web service, using the given service.
    #[must_use]
    #[inline]
    pub fn with_put<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_put().and_path(path);
        self.with_matcher(matcher, service)
    }

    /// add a PUT route to the web service, using the given service.
    #[inline]
    pub fn set_put<I, T>(&mut self, path: &str, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_put().and_path(path);
        self.set_matcher(matcher, service)
    }

    /// add a DELETE route to the web service, using the given service.
    #[must_use]
    #[inline]
    pub fn with_delete<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_delete().and_path(path);
        self.with_matcher(matcher, service)
    }

    /// add a DELETE route to the web service, using the given service.
    #[inline]
    pub fn set_delete<I, T>(&mut self, path: &str, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_delete().and_path(path);
        self.set_matcher(matcher, service)
    }

    /// add a PATCH route to the web service, using the given service.
    #[must_use]
    #[inline]
    pub fn with_patch<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_patch().and_path(path);
        self.with_matcher(matcher, service)
    }

    /// add a PATCH route to the web service, using the given service.
    #[inline]
    pub fn set_patch<I, T>(&mut self, path: &str, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_patch().and_path(path);
        self.set_matcher(matcher, service)
    }

    /// add a HEAD route to the web service, using the given service.
    #[must_use]
    #[inline]
    pub fn with_head<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_head().and_path(path);
        self.with_matcher(matcher, service)
    }

    /// add a HEAD route to the web service, using the given service.
    #[inline]
    pub fn set_head<I, T>(&mut self, path: &str, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_head().and_path(path);
        self.set_matcher(matcher, service)
    }

    /// add a OPTIONS route to the web service, using the given service.
    #[must_use]
    #[inline]
    pub fn with_options<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_options().and_path(path);
        self.with_matcher(matcher, service)
    }

    /// add a OPTIONS route to the web service, using the given service.
    #[inline]
    pub fn set_options<I, T>(&mut self, path: &str, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_options().and_path(path);
        self.set_matcher(matcher, service)
    }

    /// add a TRACE route to the web service, using the given service.
    #[must_use]
    #[inline]
    pub fn with_trace<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_trace().and_path(path);
        self.with_matcher(matcher, service)
    }

    /// add a TRACE route to the web service, using the given service.
    #[inline]
    pub fn set_trace<I, T>(&mut self, path: &str, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_trace().and_path(path);
        self.set_matcher(matcher, service)
    }

    /// Nest a web service under the given path.
    ///
    /// The nested service will receive a request with the path prefix removed.
    ///
    /// Note: this sub-webservice is configured with the same State this router has.
    #[must_use]
    pub fn with_nest_make_fn(self, prefix: &str, configure_svc: impl FnOnce(Self) -> Self) -> Self {
        let web_service = Self::new_with_state(self.state.clone());
        let web_service = configure_svc(web_service);
        self.with_nest_inner(prefix, web_service)
    }

    /// Nest a web service under the given path.
    ///
    /// The nested service will receive a request with the path prefix removed.
    ///
    /// Note: this sub-webservice is configured with the same State this router has.
    pub fn set_nest_make_fn(
        &mut self,
        prefix: &str,
        configure_svc: impl FnOnce(Self) -> Self,
    ) -> &mut Self {
        let web_service = Self::new_with_state(self.state.clone());
        let web_service = configure_svc(web_service);
        self.set_nest_inner(prefix, web_service)
    }

    /// Nest a web service under the given path.
    ///
    /// The nested service will receive a request with the path prefix removed.
    ///
    /// Warning: This sub-service has no notion of the state this webservice has. If you want
    /// to create a nested-service that shares the same state this webservice has, use [WebService::set_nest_make_fn] instead.
    #[must_use]
    #[inline(always)]
    pub fn with_nest_service<I, T>(self, prefix: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        self.with_nest_inner(prefix, service.into_endpoint_service())
    }

    /// Nest a web service under the given path.
    ///
    /// The nested service will receive a request with the path prefix removed.
    ///
    /// Warning: This sub-service has no notion of the state this webservice has. If you want
    /// to create a nested-service that shares the same state this webservice has, use [WebService::set_nest_make_fn] instead.
    #[inline(always)]
    pub fn set_nest_service<I, T>(&mut self, prefix: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointService<T>,
    {
        self.set_nest_inner(prefix, service.into_endpoint_service())
    }

    #[inline]
    fn with_nest_inner<S>(mut self, prefix: impl AsRef<str>, inner: S) -> Self
    where
        S: Service<Request, Output = Response, Error = Infallible>,
    {
        self.set_nest_inner(prefix, inner);
        self
    }

    fn set_nest_inner<S>(&mut self, prefix: impl AsRef<str>, inner: S) -> &mut Self
    where
        S: Service<Request, Output = Response, Error = Infallible>,
    {
        let prefix = prefix
            .as_ref()
            .trim_end_matches(['/', '*'])
            .trim_start_matches('/');
        let matcher = HttpMatcher::path_prefix(prefix);
        let service = NestedService {
            inner,
            prefix: ArcStr::from(prefix),
        };
        self.set_matcher(matcher, service)
    }

    /// serve the given file under the given path.
    #[must_use]
    pub fn with_file(self, prefix: &str, path: impl AsRef<Path>, mime: Mime) -> Self {
        let service = ServeDir::new_single_file(path, mime).fallback(self.not_found.clone());
        self.with_nest_inner(prefix, service)
    }

    /// serve the given file under the given path.
    pub fn set_file(&mut self, prefix: &str, path: impl AsRef<Path>, mime: Mime) -> &mut Self {
        let service = ServeDir::new_single_file(path, mime).fallback(self.not_found.clone());
        self.set_nest_inner(prefix, service)
    }

    /// serve the given directory under the given path.
    #[inline]
    #[must_use]
    pub fn with_dir(self, prefix: &str, path: impl AsRef<Path>) -> Self {
        self.with_dir_with_serve_mode(prefix, path, Default::default())
    }

    /// serve the given directory under the given path.
    #[inline]
    pub fn set_dir(&mut self, prefix: &str, path: impl AsRef<Path>) -> &mut Self {
        self.set_dir_with_serve_mode(prefix, path, Default::default())
    }

    /// serve the given directory under the given path,
    /// with a custom serve move.
    #[must_use]
    pub fn with_dir_with_serve_mode(
        self,
        prefix: &str,
        path: impl AsRef<Path>,
        mode: DirectoryServeMode,
    ) -> Self {
        let service = ServeDir::new(path)
            .fallback(self.not_found.clone())
            .with_directory_serve_mode(mode);
        self.with_nest_service(prefix, service)
    }

    /// serve the given directory under the given path,
    /// with a custom serve move.
    pub fn set_dir_with_serve_mode(
        &mut self,
        prefix: &str,
        path: impl AsRef<Path>,
        mode: DirectoryServeMode,
    ) -> &mut Self {
        let service = ServeDir::new(path)
            .fallback(self.not_found.clone())
            .with_directory_serve_mode(mode);
        self.set_nest_service(prefix, service)
    }

    /// serve the given embedded directory under the given path.
    #[inline]
    #[must_use]
    pub fn with_dir_embed(self, prefix: &str, dir: include_dir::Dir<'static>) -> Self {
        self.with_dir_embed_with_serve_mode(prefix, dir, Default::default())
    }

    /// serve the given embedded directory under the given path.
    #[inline]
    pub fn set_dir_embed(&mut self, prefix: &str, dir: include_dir::Dir<'static>) -> &mut Self {
        self.set_dir_embed_with_serve_mode(prefix, dir, Default::default())
    }

    /// serve the given embedded directory under the given path
    /// with a custom serve move.
    #[must_use]
    pub fn with_dir_embed_with_serve_mode(
        self,
        prefix: &str,
        dir: include_dir::Dir<'static>,
        mode: DirectoryServeMode,
    ) -> Self {
        let service = ServeDir::new_embedded(dir)
            .fallback(self.not_found.clone())
            .with_directory_serve_mode(mode);
        self.with_nest_service(prefix, service)
    }

    /// serve the given embedded directory under the given path
    /// with a custom serve move.
    pub fn set_dir_embed_with_serve_mode(
        &mut self,
        prefix: &str,
        dir: include_dir::Dir<'static>,
        mode: DirectoryServeMode,
    ) -> &mut Self {
        let service = ServeDir::new_embedded(dir)
            .fallback(self.not_found.clone())
            .with_directory_serve_mode(mode);
        self.set_nest_service(prefix, service)
    }

    /// add a route to the web service which matches the given matcher, using the given service.
    #[must_use]
    pub fn with_matcher<I, T>(mut self, matcher: HttpMatcher<Body>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let endpoint = Endpoint {
            matcher,
            service: service
                .into_endpoint_service_with_state(self.state.clone())
                .boxed(),
        };
        self.endpoints.push(Arc::new(endpoint));
        self
    }

    /// add a route to the web service which matches the given matcher, using the given service.
    pub fn set_matcher<I, T>(&mut self, matcher: HttpMatcher<Body>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let endpoint = Endpoint {
            matcher,
            service: service
                .into_endpoint_service_with_state(self.state.clone())
                .boxed(),
        };
        self.endpoints.push(Arc::new(endpoint));
        self
    }

    /// use the given service in case no match could be found.
    #[must_use]
    pub fn with_not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        self.not_found = service
            .into_endpoint_service_with_state(self.state.clone())
            .boxed();
        self
    }

    /// use the given service in case no match could be found.
    pub fn set_not_found<I, T>(&mut self, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        self.not_found = service
            .into_endpoint_service_with_state(self.state.clone())
            .boxed();
        self
    }
}

#[derive(Debug, Clone)]
struct NestedService<S> {
    inner: S,
    prefix: ArcStr,
}

impl<S> Service<Request> for NestedService<S>
where
    S: Service<Request>,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        // set the nested path
        let (mut parts, body) = req.into_parts();

        match try_to_strip_path_prefix_from_uri(&parts.uri, &self.prefix) {
            Ok(modified_uri) => {
                if !parts.extensions.contains::<OriginalRouterUri>() {
                    parts
                        .extensions
                        .insert(OriginalRouterUri(Arc::new(parts.uri)));
                }
                parts.uri = modified_uri;
            }
            Err(err) => {
                tracing::debug!(
                    "failed to strip prefix '{}' from Uri (bug??) preserve og uri as is; err = {err}",
                    self.prefix,
                );
            }
        }

        let req = Request::from_parts(parts, body);

        // make the actual request
        self.inner.serve(req)
    }
}

impl Default for WebService {
    fn default() -> Self {
        Self::new()
    }
}

impl<State> Service<Request> for WebService<State>
where
    State: Send + Sync + Clone + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, mut req: Request) -> Result<Self::Output, Self::Error> {
        for endpoint in &self.endpoints {
            let mut ext = Extensions::new();
            if endpoint.matcher.matches(Some(&mut ext), &req) {
                // insert the extensions that might be generated by the matcher(s) into the context
                req.extensions_mut().extend(ext);
                return endpoint.service.serve(req).await;
            }
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
    use crate::service::web::extract::State;
    use crate::{Body, body::util::BodyExt};

    use super::*;

    async fn get_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<Request, Output = Response, Error = Infallible>,
    {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        service.serve(req).await.unwrap()
    }

    async fn post_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<Request, Output = Response, Error = Infallible>,
    {
        let req = Request::post(uri).body(Body::empty()).unwrap();
        service.serve(req).await.unwrap()
    }

    async fn connect_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<Request, Output = Response, Error = Infallible>,
    {
        let req = Request::connect(uri).body(Body::empty()).unwrap();
        service.serve(req).await.unwrap()
    }

    #[tokio::test]
    async fn test_web_service() {
        let svc = WebService::new()
            .with_get("/hello", "hello")
            .with_post("/world", "world");

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
        let svc = WebService::new().with_not_found("not found");

        let res = get_response(&svc, "https://www.test.io/hello").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "not found");
    }

    #[tokio::test]
    async fn test_web_service_nest() {
        let state = "state".to_owned();

        let svc = WebService::new_with_state(state)
            .with_get("/state", async |State(state): State<String>| state)
            .with_nest_make_fn("/api", |web| {
                web.with_get("/hello", "hello")
                    .with_post("/world", "world")
                    .with_get("/state", async |State(state): State<String>| state)
            });

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

        let res = get_response(&svc, "https://www.test.io/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "state");

        let res = get_response(&svc, "https://www.test.io/api/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "state");
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
            .with_get("/api/version", "v1")
            .with_post("/api", StatusCode::FORBIDDEN)
            .with_dir("/", tmp_dir.path().to_str().unwrap());

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
