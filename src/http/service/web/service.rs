use super::{
    endpoint::Endpoint,
    matcher::{Matcher, MethodFilter, PathFilter, UriParams},
    IntoEndpointService,
};
use crate::{
    http::{service::fs::ServeDir, IntoResponse, Request, Response, StatusCode, Uri},
    service::{service_fn, BoxService, Context, Service},
};
use std::{convert::Infallible, future::Future, marker::PhantomData, sync::Arc};

/// a basic web service
pub struct WebService<State> {
    endpoints: Vec<Arc<Endpoint<State>>>,
    not_found: BoxService<State, Request, Response, Infallible>,
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
            not_found: service_fn(|| async { Ok(StatusCode::NOT_FOUND.into_response()) }).boxed(),
            _phantom: PhantomData,
        }
    }

    /// add a GET route to the web service, using the given service.
    pub fn get<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = (MethodFilter::GET, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a POST route to the web service, using the given service.
    pub fn post<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = (MethodFilter::POST, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a PUT route to the web service, using the given service.
    pub fn put<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = (MethodFilter::PUT, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a DELETE route to the web service, using the given service.
    pub fn delete<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = (MethodFilter::DELETE, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a PATCH route to the web service, using the given service.
    pub fn patch<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = (MethodFilter::PATCH, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a HEAD route to the web service, using the given service.
    pub fn head<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = (MethodFilter::HEAD, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a OPTIONS route to the web service, using the given service.
    pub fn options<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = (MethodFilter::OPTIONS, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a TRACE route to the web service, using the given service.
    pub fn trace<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = (MethodFilter::TRACE, PathFilter::new(path));
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
        let matcher = PathFilter::new(prefix);
        let service = NestedService(service.into_endpoint_service());
        self.on(matcher, service)
    }

    /// serve the given directory under the given path.
    pub fn dir(self, prefix: &str, dir: &str) -> Self {
        let service = ServeDir::new(dir).fallback(self.not_found.clone());
        self.nest(prefix, service)
    }

    /// add a route to the web service which matches the given matcher, using the given service.
    pub fn on<I, T, M>(mut self, matcher: M, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
        M: Matcher<State>,
    {
        let endpoint = Endpoint {
            matcher: Box::new(matcher),
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
        self.not_found = service.into_endpoint_service().boxed();
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
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let ctx = ctx.into_parent();
        for endpoint in &self.endpoints {
            let mut ctx = ctx.clone();
            if endpoint.matcher.matches(&mut ctx, &req) {
                return endpoint.service.serve(ctx, req).await;
            }
        }
        self.not_found.serve(ctx, req).await
    }
}

#[cfg(test)]
mod test {
    use crate::http::dep::http_body_util::BodyExt;
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
        let tmp_dir = tempdir::TempDir::new("test_web_service_dir").unwrap();
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
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
