use crate::{
    http::{IntoResponse, Request, Response, StatusCode},
    service::{
        handler::{Factory, FromContextRequest},
        service_fn, BoxService, Context, Service, ServiceBuilder,
    },
};
use std::{convert::Infallible, future::Future, marker::PhantomData, sync::Arc};

use super::matcher::{Matcher, MethodFilter, PathFilter};

/// a basic web service
pub struct WebService<State> {
    endpoints: Vec<Arc<Endpoint<State>>>,
    not_found: BoxService<State, Request, Response, Infallible>,
    _phantom: PhantomData<State>,
}

struct Endpoint<State> {
    matcher: Box<dyn Matcher<State>>,
    service: BoxService<State, Request, Response, Infallible>,
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
    pub fn get<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let matcher = (MethodFilter::GET, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a GET route to the web service, using the given service function.
    pub fn get_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.get(path, service_fn(f))
    }

    /// add a POST route to the web service, using the given service.
    pub fn post<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let matcher = (MethodFilter::POST, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a POST route to the web service, using the given service function.
    pub fn post_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.post(path, service_fn(f))
    }

    /// add a PUT route to the web service, using the given service.
    pub fn put<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let matcher = (MethodFilter::PUT, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a PUT route to the web service, using the given service function.
    pub fn put_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.put(path, service_fn(f))
    }

    /// add a DELETE route to the web service, using the given service.
    pub fn delete<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let matcher = (MethodFilter::DELETE, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a DELETE route to the web service, using the given service function.
    pub fn delete_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.delete(path, service_fn(f))
    }

    /// add a PATCH route to the web service, using the given service.
    pub fn patch<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let matcher = (MethodFilter::PATCH, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a PATCH route to the web service, using the given service function.
    pub fn patch_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.patch(path, service_fn(f))
    }

    /// add a HEAD route to the web service, using the given service.
    pub fn head<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let matcher = (MethodFilter::HEAD, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a HEAD route to the web service, using the given service function.
    pub fn head_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.head(path, service_fn(f))
    }

    /// add a OPTIONS route to the web service, using the given service.
    pub fn options<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let matcher = (MethodFilter::OPTIONS, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a OPTIONS route to the web service, using the given service function.
    pub fn options_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.options(path, service_fn(f))
    }

    /// add a TRACE route to the web service, using the given service.
    pub fn trace<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let matcher = (MethodFilter::TRACE, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a TRACE route to the web service, using the given service function.
    pub fn trace_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.trace(path, service_fn(f))
    }

    /// add a route to the web service which matches the given matcher, using the given service.
    pub fn on<S, R, M>(mut self, matcher: M, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
        M: Matcher<State>,
    {
        let service = ServiceBuilder::new()
            .map_response(|resp: R| resp.into_response())
            .service(service);
        let endpoint = Endpoint {
            matcher: Box::new(matcher),
            service: service.boxed(),
        };
        self.endpoints.push(Arc::new(endpoint));
        self
    }

    /// add a route to the web service which matches the given matcher, using the given service function.
    pub fn on_fn<F, T, R, O, M>(self, matcher: M, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
        M: Matcher<State>,
    {
        self.on(matcher, service_fn(f))
    }

    /// use the given service in case no match could be found.
    pub fn not_found<S, R>(mut self, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        R: IntoResponse + Send + Sync + 'static,
    {
        let service = ServiceBuilder::new()
            .map_response(|resp: R| resp.into_response())
            .service(service);
        self.not_found = service.boxed();
        self
    }

    /// use the given service function in case no match could be found.
    pub fn not_found_fn<F, T, R, O>(self, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.not_found(service_fn(f))
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
