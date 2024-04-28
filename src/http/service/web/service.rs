use super::{endpoint::Endpoint, IntoEndpointService};
use crate::{
    http::{
        matcher::{HttpMatcher, UriParams},
        service::fs::ServeDir,
        Body, IntoResponse, Request, Response, StatusCode, Uri,
    },
    service::{context::Extensions, service_fn, BoxService, Context, Matcher, Service},
};
use paste::paste;
use std::{convert::Infallible, future::Future, marker::PhantomData, sync::Arc};

/// A basic web service that can be used to serve HTTP requests.
///
/// Note that this service boxes all the internal services, so it is not as efficient as it could be.
/// For those locations where you need do not desire the convenience over performance,
/// you can instead use a tuple of `(M, S)` tuples, where M is a matcher and S is a service,
/// e.g. `((MethodMatcher::GET, service_a), (MethodMatcher::POST, service_b), service_fallback)`.
pub struct WebService<State> {
    endpoints: Vec<Arc<Endpoint<State>>>,
    not_found: Arc<BoxService<State, Request, Response, Infallible>>,
    _phantom: PhantomData<State>,
}

impl<State> std::fmt::Debug for WebService<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebService").finish()
    }
}

impl<State> Clone for WebService<State> {
    fn clone(&self) -> Self {
        Self {
            endpoints: self.endpoints.clone(),
            not_found: self.not_found.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<State> WebService<State>
where
    State: Send + Sync + 'static,
{
    /// create a new web service
    pub(crate) fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            not_found: Arc::new(
                service_fn(|| async { Ok(StatusCode::NOT_FOUND.into_response()) }).boxed(),
            ),
            _phantom: PhantomData,
        }
    }

    /// add a GET route to the web service, using the given service.
    pub fn get<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::method_get().and_path(path);
        self.on(matcher, service)
    }

    /// add a POST route to the web service, using the given service.
    pub fn post<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::method_post().and_path(path);
        self.on(matcher, service)
    }

    /// add a PUT route to the web service, using the given service.
    pub fn put<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::method_put().and_path(path);
        self.on(matcher, service)
    }

    /// add a DELETE route to the web service, using the given service.
    pub fn delete<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::method_delete().and_path(path);
        self.on(matcher, service)
    }

    /// add a PATCH route to the web service, using the given service.
    pub fn patch<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::method_patch().and_path(path);
        self.on(matcher, service)
    }

    /// add a HEAD route to the web service, using the given service.
    pub fn head<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::method_head().and_path(path);
        self.on(matcher, service)
    }

    /// add a OPTIONS route to the web service, using the given service.
    pub fn options<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::method_options().and_path(path);
        self.on(matcher, service)
    }

    /// add a TRACE route to the web service, using the given service.
    pub fn trace<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::method_trace().and_path(path);
        self.on(matcher, service)
    }

    /// nest a web service under the given path.
    ///
    /// The nested service will receive a request with the path prefix removed.
    pub fn nest<I, T>(self, prefix: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let prefix = format!("{}/*", prefix.trim_end_matches(['/', '*']));
        let matcher = HttpMatcher::path(prefix);
        let service = NestedService(service.into_endpoint_service());
        self.on(matcher, service)
    }

    /// serve the given directory under the given path.
    pub fn dir(self, prefix: &str, dir: &str) -> Self {
        let service = ServeDir::new(dir).fallback(self.not_found.clone());
        self.nest(prefix, service)
    }

    /// add a route to the web service which matches the given matcher, using the given service.
    pub fn on<I, T>(mut self, matcher: HttpMatcher<State, Body>, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let endpoint = Endpoint {
            matcher,
            service: service.into_endpoint_service().boxed(),
        };
        self.endpoints.push(Arc::new(endpoint));
        self
    }

    /// use the given service in case no match could be found.
    pub fn not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.not_found = Arc::new(service.into_endpoint_service().boxed());
        self
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
struct NestedService<S>(S);

impl<S, State> Service<State, Request> for NestedService<S>
where
    S: Service<State, Request>,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        // get nested path
        let path = ctx.get::<UriParams>().unwrap().glob().unwrap();

        // set the nested path
        let (mut parts, body) = req.into_parts();
        let mut uri_parts = parts.uri.into_parts();
        let path_and_query = uri_parts.path_and_query.take().unwrap();
        match path_and_query.query() {
            Some(query) => {
                uri_parts.path_and_query = Some(format!("{}?{}", path, query).parse().unwrap());
            }
            None => {
                uri_parts.path_and_query = Some(path.parse().unwrap());
            }
        }
        parts.uri = Uri::from_parts(uri_parts).unwrap();
        let req = Request::from_parts(parts, body);

        // make the actual request
        self.0.serve(ctx, req)
    }
}

impl<State> Default for WebService<State>
where
    State: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<State> Service<State, Request> for WebService<State>
where
    State: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();
        for endpoint in &self.endpoints {
            if endpoint.matcher.matches(Some(&mut ext), &ctx, &req) {
                // insert the extensions that might be generated by the matcher(s) into the context
                ctx.extend(ext);
                return endpoint.service.serve(ctx, req).await;
            }
            // clear the extensions for the next matcher
            ext.clear();
        }
        self.not_found.serve(ctx, req).await
    }
}

macro_rules! impl_matcher_service_tuple {
    ($($T:ident),+ $(,)?) => {
        paste!{
            #[allow(non_camel_case_types)]
            #[allow(non_snake_case)]
            impl<State, $([<M_ $T>], $T),+, S, Error> Service<State, Request> for ($(([<M_ $T>], $T)),+, S)
            where
                State: Send + Sync + 'static,
                $(
                    [<M_ $T>]: Matcher<State, Request>,
                    $T: Service<State, Request, Response = Response, Error = Error>,
                )+
                S: Service<State, Request, Response = Response, Error = Error>,
                Error: Send + Sync + 'static,
            {
                type Response = Response;
                type Error = Error;

                async fn serve(
                    &self,
                    mut ctx: Context<State>,
                    req: Request,
                ) -> Result<Self::Response, Self::Error> {
                    let ($(([<M_ $T>], $T)),+, S) = self;
                    let mut ext = Extensions::new();
                    $(
                        if [<M_ $T>].matches(Some(&mut ext), &ctx, &req) {
                            ctx.extend(ext);
                            return $T.serve(ctx, req).await;
                        }
                        ext.clear();
                    )+
                    S.serve(ctx, req).await
                }
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_matcher_service_tuple);

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
/// use rama::http::matcher::{HttpMatcher, MethodMatcher};
/// use rama::http::{Body, Request, Response, StatusCode};
/// use rama::http::dep::http_body_util::BodyExt;
/// use rama::service::{Context, Service};
///
/// #[tokio::main]
/// async fn main() {
///   let svc = rama::http::service::web::match_service! {
///     HttpMatcher::get("/hello") => "hello",
///     HttpMatcher::post("/world") => "world",
///     MethodMatcher::CONNECT => "connect",
///     _ => StatusCode::NOT_FOUND,
///   };
///
///   let resp = svc.serve(
///       Context::default(),
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
/// use rama::http::matcher::{HttpMatcher, MethodMatcher};
/// use rama::http::{Body, Request, Response, StatusCode};
/// use rama::http::dep::http_body_util::BodyExt;
/// use rama::http::service::web::IntoEndpointService;
/// use rama::service::{Context, Service};
///
/// #[tokio::main]
/// async fn main() {
///   let svc = (
///     (HttpMatcher::get("/hello"), "hello".into_endpoint_service()),
///     (HttpMatcher::post("/world"), "world".into_endpoint_service()),
///     (MethodMatcher::CONNECT, "connect".into_endpoint_service()),
///     StatusCode::NOT_FOUND.into_endpoint_service(),
///   );
///
///   let resp = svc.serve(
///      Context::default(),
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
    ($($M:expr => $S:expr),+, _ => $F:expr $(,)?) => {{
        use $crate::http::service::web::IntoEndpointService;
        ($(($M, $S.into_endpoint_service())),+, $F.into_endpoint_service())
    }};
}

#[doc(inline)]
pub use __match_service as match_service;

#[cfg(test)]
mod test {
    use crate::http::dep::http_body_util::BodyExt;
    use crate::http::matcher::MethodMatcher;
    use crate::http::Body;

    use super::*;

    async fn get_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<(), Request, Response = Response, Error = Infallible>,
    {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        service.serve(Context::default(), req).await.unwrap()
    }

    async fn post_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<(), Request, Response = Response, Error = Infallible>,
    {
        let req = Request::post(uri).body(Body::empty()).unwrap();
        service.serve(Context::default(), req).await.unwrap()
    }

    async fn connect_response<S>(service: &S, uri: &str) -> Response
    where
        S: Service<(), Request, Response = Response, Error = Infallible>,
    {
        let req = Request::connect(uri).body(Body::empty()).unwrap();
        service.serve(Context::default(), req).await.unwrap()
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
