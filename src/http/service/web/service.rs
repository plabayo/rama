use crate::{
    http::{IntoResponse, Request, Response, StatusCode},
    service::{
        handler::{Factory, FromContextRequest},
        service_fn, Context, Service,
    },
};
use std::{convert::Infallible, future::Future, marker::PhantomData};

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
    pub fn get<S, R>(self, _path: &'static str, _service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        Self {
            _phantom: PhantomData,
        }
    }

    /// add a GET route to the web service, using the given service function.
    pub fn get_fn<F, T, R, O>(self, path: &'static str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.get(path, service_fn(f))
    }

    /// add a POST route to the web service, using the given service.
    pub fn post<S, R>(self, _path: &'static str, _service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        Self {
            _phantom: PhantomData,
        }
    }

    /// add a POST route to the web service, using the given service function.
    pub fn post_fn<F, T, R, O>(self, path: &'static str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.post(path, service_fn(f))
    }

    /// add a PUT route to the web service, using the given service.
    pub fn put<S, R>(self, _path: &'static str, _service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        Self {
            _phantom: PhantomData,
        }
    }

    /// add a PUT route to the web service, using the given service function.
    pub fn put_fn<F, T, R, O>(self, path: &'static str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.put(path, service_fn(f))
    }

    /// add a DELETE route to the web service, using the given service.
    pub fn delete<S, R>(self, _path: &'static str, _service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        Self {
            _phantom: PhantomData,
        }
    }

    /// add a DELETE route to the web service, using the given service function.
    pub fn delete_fn<F, T, R, O>(self, path: &'static str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.delete(path, service_fn(f))
    }

    /// add a PATCH route to the web service, using the given service.
    pub fn patch<S, R>(self, _path: &'static str, _service: S) -> Self
    where
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
        Self {
            _phantom: PhantomData,
        }
    }

    /// add a PATCH route to the web service, using the given service function.
    pub fn patch_fn<F, T, R, O>(self, path: &'static str, f: F) -> Self
    where
        F: Factory<T, R, O, Infallible>,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
        self.patch(path, service_fn(f))
    }

    // pub fn on<S, R>(self, path: &'static str, service: S) -> Self
    // where
    //     S: Service<State, Request, Response = R, Error = Infallible>,
    //     R: IntoResponse,
    // {
    //     Self {
    //         _phantom: PhantomData,
    //     }
    // }
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
