use crate::{
    http::{IntoResponse, Request, Response, StatusCode},
    service::{service_fn, BoxService, Context, Service},
};
use std::{convert::Infallible, marker::PhantomData, sync::Arc};

use super::{
    endpoint::Endpoint,
    matcher::{Matcher, MethodFilter, PathFilter},
    IntoBoxedService,
};

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
        I: IntoBoxedService<State, T>,
    {
        let matcher = (MethodFilter::GET, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a POST route to the web service, using the given service.
    pub fn post<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
    {
        let matcher = (MethodFilter::POST, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a PUT route to the web service, using the given service.
    pub fn put<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
    {
        let matcher = (MethodFilter::PUT, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a DELETE route to the web service, using the given service.
    pub fn delete<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
    {
        let matcher = (MethodFilter::DELETE, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a PATCH route to the web service, using the given service.
    pub fn patch<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
    {
        let matcher = (MethodFilter::PATCH, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a HEAD route to the web service, using the given service.
    pub fn head<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
    {
        let matcher = (MethodFilter::HEAD, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a OPTIONS route to the web service, using the given service.
    pub fn options<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
    {
        let matcher = (MethodFilter::OPTIONS, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a TRACE route to the web service, using the given service.
    pub fn trace<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
    {
        let matcher = (MethodFilter::TRACE, PathFilter::new(path));
        self.on(matcher, service)
    }

    /// add a route to the web service which matches the given matcher, using the given service.
    pub fn on<I, T, M>(mut self, matcher: M, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
        M: Matcher<State>,
    {
        let endpoint = Endpoint {
            matcher: Box::new(matcher),
            service: service.into_boxed_service(),
        };
        self.endpoints.push(Arc::new(endpoint));
        self
    }

    /// use the given service in case no match could be found.
    pub fn not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoBoxedService<State, T>,
    {
        self.not_found = service.into_boxed_service();
        self
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
