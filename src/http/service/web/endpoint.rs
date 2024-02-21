use super::matcher::Matcher;
use crate::{
    http::{IntoResponse, Request, Response},
    service::{
        handler::{Factory, FromContextRequest},
        BoxService, Context, Service, ServiceBuilder,
    },
};
use std::{convert::Infallible, future::Future};

pub(crate) struct Endpoint<State> {
    pub(crate) matcher: Box<dyn Matcher<State>>,
    pub(crate) service: BoxService<State, Request, Response, Infallible>,
}

/// utility trait to accept multiple types as an endpoint service for [`super::WebService`]
pub trait IntoBoxedService<State, T>: private::Sealed<T> {
    /// convert the type into a [`crate::service::BoxService`].
    fn into_boxed_service(self) -> BoxService<State, Request, Response, Infallible>;
}

impl<State, F, T, R, O> IntoBoxedService<State, (State, F, T, R, O)> for F
where
    State: Send + Sync + 'static,
    F: Factory<T, R, O, Infallible> + Clone,
    R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
    O: IntoResponse + Send + Sync + 'static,
    T: FromContextRequest<State, Request>,
{
    fn into_boxed_service(self) -> BoxService<State, Request, Response, Infallible> {
        ServiceBuilder::new()
            .map_response(|resp: O| resp.into_response())
            .service_fn(self)
            .boxed()
    }
}

impl<State, S, R> IntoBoxedService<State, (State, R)> for S
where
    State: Send + Sync + 'static,
    S: Service<State, Request, Response = R, Error = Infallible> + Clone,
    R: IntoResponse + Send + Sync + 'static,
{
    fn into_boxed_service(self) -> BoxService<State, Request, Response, Infallible> {
        ServiceBuilder::new()
            .map_response(|resp: R| resp.into_response())
            .service(self)
            .boxed()
    }
}

impl<State, R> IntoBoxedService<State, ()> for R
where
    State: Send + Sync + 'static,
    R: IntoResponse + Clone + Send + Sync + 'static,
{
    fn into_boxed_service(self) -> BoxService<State, Request, Response, Infallible> {
        StaticService(self).boxed()
    }
}

#[derive(Debug, Clone)]
struct StaticService<R>(R);

impl<R, State> Service<State, Request> for StaticService<R>
where
    R: IntoResponse + Clone + Send + Sync + 'static,
    State: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, _: Context<State>, _: Request) -> Result<Self::Response, Self::Error> {
        Ok(self.0.clone().into_response())
    }
}

mod private {
    use super::*;

    pub trait Sealed<T> {}

    impl<State, F, T, R, O> Sealed<(State, F, T, R, O)> for F
    where
        State: Send + Sync + 'static,
        F: Factory<T, R, O, Infallible> + Clone,
        R: Future<Output = Result<O, Infallible>> + Send + Sync + 'static,
        O: IntoResponse + Send + Sync + 'static,
        T: FromContextRequest<State, Request>,
    {
    }

    impl<State, S, R> Sealed<(State, R)> for S
    where
        State: Send + Sync + 'static,
        S: Service<State, Request, Response = R, Error = Infallible>,
        R: IntoResponse + Send + Sync + 'static,
    {
    }

    impl<R> Sealed<()> for R where R: IntoResponse + Clone + Send + Sync + 'static {}
}
