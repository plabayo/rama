//! k8s web service

use std::{convert::Infallible, marker::PhantomData, sync::Arc};

use http::StatusCode;

use crate::{
    http::{matcher::HttpMatcher, IntoResponse, Request, Response},
    service::{service_fn, BoxService, Context, Service},
};

use super::match_service;

/// create a k8s web health service builder
pub fn k8s_health_builder<S>() -> K8sHealthServiceBuilder<(), (), S> {
    K8sHealthServiceBuilder::new()
}

/// create a default k8s web health service
pub fn k8s_health<S>() -> impl Service<S, Request, Response = Response, Error = Infallible> + Clone
where
    S: Send + Sync + 'static,
{
    k8s_health_builder().build()
}

#[derive(Debug)]
/// builder to easily create a k8s web service
///
/// by default its endpoints will always return 200 (OK),
/// but this can be made conditional by providing
/// a ready condition ([`K8sHealthServiceBuilder::ready`], liveness)
/// and/or alive condition ([`K8sHealthServiceBuilder::alive`], readiness).
///
/// In case a conditional is provided and it returns `false`,
/// a 503 (Service Unavailable) will be returned instead.
pub struct K8sHealthServiceBuilder<A, R, S> {
    alive: A,
    ready: R,
    _phantom: PhantomData<S>,
}

impl<S> K8sHealthServiceBuilder<(), (), S> {
    pub(crate) fn new() -> Self {
        Self {
            alive: (),
            ready: (),
            _phantom: PhantomData,
        }
    }
}

impl<R, S> K8sHealthServiceBuilder<(), R, S> {
    /// define an alive condition to be used by the k8s health web service for the liveness check
    pub fn alive<A: Fn() -> bool>(self, alive: A) -> K8sHealthServiceBuilder<A, R, S> {
        K8sHealthServiceBuilder {
            alive,
            ready: self.ready,
            _phantom: self._phantom,
        }
    }
}

impl<A, S> K8sHealthServiceBuilder<A, (), S> {
    /// define an ready condition to be used by the k8s health web service for the readiness check
    pub fn ready<R: Fn() -> bool>(self, ready: R) -> K8sHealthServiceBuilder<A, R, S> {
        K8sHealthServiceBuilder {
            alive: self.alive,
            ready,
            _phantom: self._phantom,
        }
    }
}

impl<A, R, S> K8sHealthServiceBuilder<A, R, S>
where
    A: ToK8sService<S>,
    R: ToK8sService<S>,
    S: Send + Sync + 'static,
{
    /// build the k8s health web server
    pub fn build(
        self,
    ) -> impl Service<S, Request, Response = Response, Error = Infallible> + Clone {
        Arc::new(match_service! {
            HttpMatcher::get("/k8s/alive") => self.alive.to_k8s_service(),
            HttpMatcher::get("/k8s/ready") => self.ready.to_k8s_service(),
            _ => StatusCode::NOT_FOUND,
        })
    }
}

/// Utility internal trait to create service endpoints for the different checks
pub trait ToK8sService<S>: private::Sealed {
    /// create a boxed web service by consuming self
    fn to_k8s_service(self) -> BoxService<S, Request, Response, Infallible>;
}

impl<S: Send + Sync + 'static> ToK8sService<S> for () {
    fn to_k8s_service(self) -> BoxService<S, Request, Response, Infallible> {
        service_fn(|| async { Ok(StatusCode::OK.into_response()) }).boxed()
    }
}

impl<S, F> ToK8sService<S> for F
where
    F: Fn() -> bool + Clone + Send + Sync + 'static,
    S: Send + Sync + 'static,
{
    fn to_k8s_service(self) -> BoxService<S, Request, Response, Infallible> {
        K8sService::new(self).boxed()
    }
}

#[derive(Debug)]
struct K8sService<F> {
    f: F,
}

impl<F: Clone> Clone for K8sService<F> {
    fn clone(&self) -> Self {
        Self { f: self.f.clone() }
    }
}

impl<F> K8sService<F> {
    fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F, State> Service<State, Request> for K8sService<F>
where
    F: Fn() -> bool + Send + Sync + 'static,
    State: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, _: Context<State>, _: Request) -> Result<Self::Response, Self::Error> {
        Ok(if (self.f)() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
        .into_response())
    }
}

mod private {
    pub trait Sealed {}

    impl Sealed for () {}
    impl<F: Fn() -> bool + Clone + Send + Sync + 'static> Sealed for F {}
}
