use super::{IntoEndpointService};
use crate::{Request, Response, StatusCode};
use rama_core::{service::{BoxService, Service, service_fn}, Context};
use std::{convert::Infallible, sync::Arc};
use std::collections::HashMap;
use http::{Method};

use matchit::Router as MatchitRouter;
use rama_http_types::IntoResponse;

/// A basic web router that can be used to serve HTTP requests based on path matching.
/// It will also provide extraction of path parameters and wildcards out of the box so
/// you can define your paths accordingly.

pub struct Router<State> {
    routes: MatchitRouter<HashMap<Method, Arc<BoxService<State, Request, Response, Infallible>>>>,
    not_found: Arc<BoxService<State, Request, Response, Infallible>>,
}

impl<State> std::fmt::Debug for Router<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").finish()
    }
}

impl<State> Clone for Router<State> {
    fn clone(&self) -> Self {
        Self {
            routes: self.routes.clone(),
            not_found: self.not_found.clone(),
        }
    }
}

/// default trait
impl<State> Default for Router<State>
where
    State: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<State> Router<State>
where
    State: Clone + Send + Sync + 'static,
{
    /// create a new web router
    pub(crate) fn new() -> Self {
        Self {
            routes: MatchitRouter::new(),
            not_found: Arc::new(
                service_fn(|| async { Ok(StatusCode::NOT_FOUND.into_response()) }).boxed(),
            ),
        }
    }

    pub fn route<I, T>(mut self, method: Method, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let boxed_service = Arc::new(BoxService::new(service.into_endpoint_service()));
        match self.routes.insert(path.to_string(), HashMap::new()) {
            Ok(_) => {
                if let Some(entry) = self.routes.at_mut(path).ok() {
                    entry.value.insert(method, boxed_service);
                }
            },
            Err(_err) => {
                if let Some(existing) = self.routes.at_mut(path).ok() {
                    existing.value.insert(method, boxed_service);
                }
            }
        };
        self
    }

    pub fn get<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.route(Method::GET, path, service)
    }

    pub fn post<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.route(Method::POST, path, service)
    }

    pub fn put<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.route(Method::PUT, path, service)
    }

    pub fn delete<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.route(Method::DELETE, path, service)
    }

    pub fn patch<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.route(Method::PATCH, path, service)
    }

    pub fn head<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.route(Method::HEAD, path, service)
    }

    pub fn options<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.route(Method::OPTIONS, path, service)
    }

    pub fn trace<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.route(Method::TRACE, path, service)
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

impl<State> Service<State, Request> for Router<State>
where
    State: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<>,
    ) -> Result<Self::Response, Self::Error> {
        let uri_string = req.uri().to_string();
        match &self.routes.at(uri_string.as_str()) {
            Ok(matched) => {
                let params: HashMap<String, String> = matched.params.clone().iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                ctx.insert(params);
                if let Some(service) = matched.value.get(&req.method()) {
                    service.boxed().serve(ctx, req).await
                } else {
                    self.not_found.serve(ctx, req).await
                }
            },
            Err(_err) => {
                self.not_found.serve(ctx, req).await
            }
        }
    }
}
