use crate::{
    http::{IntoResponse, Request, Response, StatusCode},
    service::{
        handler::{Factory, FromContextRequest},
        service_fn, Context, Service,
    },
};
use std::{convert::Infallible, future::Future, marker::PhantomData};

use super::matcher::{Matcher, MethodFilter};

/// a basic web service
pub struct WebService<State> {
    _phantom: PhantomData<State>,
}

impl<State> std::fmt::Debug for WebService<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebService").finish()
    }
}

impl<State> WebService<State> {
    /// create a new web service
    pub(crate) fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    /// add a GET route to the web service, using the given service.
    pub fn get<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        self.on(path, MethodFilter::GET, service)
    }

    /// add a GET route to the web service, using the given service function.
    pub fn get_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.on_fn(path, MethodFilter::GET, f)
    }

    /// add a POST route to the web service, using the given service.
    pub fn post<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        self.on(path, MethodFilter::POST, service)
    }

    /// add a POST route to the web service, using the given service function.
    pub fn post_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.on_fn(path, MethodFilter::POST, f)
    }

    /// add a PUT route to the web service, using the given service.
    pub fn put<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        self.on(path, MethodFilter::PUT, service)
    }

    /// add a PUT route to the web service, using the given service function.
    pub fn put_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.on_fn(path, MethodFilter::PUT, f)
    }

    /// add a DELETE route to the web service, using the given service.
    pub fn delete<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        self.on(path, MethodFilter::DELETE, service)
    }

    /// add a DELETE route to the web service, using the given service function.
    pub fn delete_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.on_fn(path, MethodFilter::DELETE, f)
    }

    /// add a PATCH route to the web service, using the given service.
    pub fn patch<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        self.on(path, MethodFilter::PATCH, service)
    }

    /// add a PATCH route to the web service, using the given service function.
    pub fn patch_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.on_fn(path, MethodFilter::PATCH, f)
    }

    /// add a HEAD route to the web service, using the given service.
    pub fn head<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        self.on(path, MethodFilter::HEAD, service)
    }

    /// add a HEAD route to the web service, using the given service function.
    pub fn head_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.on_fn(path, MethodFilter::HEAD, f)
    }

    /// add a OPTIONS route to the web service, using the given service.
    pub fn options<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        self.on(path, MethodFilter::OPTIONS, service)
    }

    /// add a OPTIONS route to the web service, using the given service function.
    pub fn options_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.on_fn(path, MethodFilter::OPTIONS, f)
    }

    /// add a TRACE route to the web service, using the given service.
    pub fn trace<S, R>(self, path: &str, service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        self.on(path, MethodFilter::TRACE, service)
    }

    /// add a TRACE route to the web service, using the given service function.
    pub fn trace_fn<F, T, R, O>(self, path: &str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.on_fn(path, MethodFilter::TRACE, f)
    }

    /// add a route to the web service which matches the given matcher, using the given service.
    pub fn on<S, R, M>(self, _path: &str, _matcher: M, _service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse,
        M: Matcher<State>,
    {
        Self {
            _phantom: PhantomData,
        }
    }

    /// add a route to the web service which matches the given matcher, using the given service function.
    pub fn on_fn<F, T, R, O, M>(self, path: &str, matcher: M, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
        M: Matcher<State>,
    {
        self.on(path, matcher, service_fn(f))
    }

    /// use the given service in case no match could be found.
    pub fn not_found<S, R>(self, _service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        Self {
            _phantom: PhantomData,
        }
    }

    /// use the given service function in case no match could be found.
    pub fn not_found_fn<F, T, R, O>(self, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.not_found(service_fn(f))
    }
}

impl<State> Default for WebService<State> {
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
        _ctx: Context<State>,
        _req: Request,
    ) -> Result<Self::Response, Self::Error> {
        Ok(StatusCode::OK.into_response())
    }
}
