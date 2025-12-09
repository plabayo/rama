//! k8s web service

use crate::{
    Request, Response, StatusCode, matcher::HttpMatcher,
    service::web::endpoint::response::IntoResponse,
};
use rama_core::{
    Service,
    service::{BoxService, service_fn},
};
use std::{convert::Infallible, sync::Arc};

use super::match_service;

/// create a k8s web health service builder
#[must_use]
pub fn k8s_health_builder() -> K8sHealthServiceBuilder<(), ()> {
    K8sHealthServiceBuilder::new()
}

/// create a default k8s web health service
#[must_use]
pub fn k8s_health() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    k8s_health_builder().build()
}

/// builder to easily create a k8s web service
///
/// by default its endpoints will always return 200 (OK),
/// but this can be made conditional by providing
/// a ready condition ([`K8sHealthServiceBuilder::ready`], liveness)
/// and/or alive condition ([`K8sHealthServiceBuilder::alive`], readiness).
///
/// In case a conditional is provided and it returns `false`,
/// a 503 (Service Unavailable) will be returned instead.
#[derive(Debug, Clone)]
pub struct K8sHealthServiceBuilder<A, R> {
    alive: A,
    ready: R,
}

impl K8sHealthServiceBuilder<(), ()> {
    pub(crate) fn new() -> Self {
        Self {
            alive: (),
            ready: (),
        }
    }
}

impl<R> K8sHealthServiceBuilder<(), R> {
    /// define an alive condition to be used by the k8s health web service for the liveness check
    pub fn alive<A: Fn() -> bool>(self, alive: A) -> K8sHealthServiceBuilder<A, R> {
        K8sHealthServiceBuilder {
            alive,
            ready: self.ready,
        }
    }
}

impl<A> K8sHealthServiceBuilder<A, ()> {
    /// define an ready condition to be used by the k8s health web service for the readiness check
    pub fn ready<R: Fn() -> bool>(self, ready: R) -> K8sHealthServiceBuilder<A, R> {
        K8sHealthServiceBuilder {
            alive: self.alive,
            ready,
        }
    }
}

impl<A, R> K8sHealthServiceBuilder<A, R>
where
    A: ToK8sService,
    R: ToK8sService,
{
    /// build the k8s health web server
    pub fn build(self) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
        Arc::new(match_service! {
            HttpMatcher::get("/k8s/alive") => self.alive.to_k8s_service(),
            HttpMatcher::get("/k8s/ready") => self.ready.to_k8s_service(),
            _ => StatusCode::NOT_FOUND,
        })
    }
}

/// Utility internal trait to create service endpoints for the different checks
pub trait ToK8sService: private::Sealed {}

impl ToK8sService for () {}

impl<F> ToK8sService for F where F: Fn() -> bool + Clone + Send + Sync + 'static {}

#[derive(Debug, Clone)]
struct K8sService<F> {
    f: F,
}

impl<F> K8sService<F> {
    fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F> Service<Request> for K8sService<F>
where
    F: Fn() -> bool + Send + Sync + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, _: Request) -> Result<Self::Output, Self::Error> {
        Ok(if (self.f)() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
        .into_response())
    }
}

mod private {
    use super::*;

    pub trait Sealed {
        /// create a boxed web service by consuming self
        fn to_k8s_service(self) -> BoxService<Request, Response, Infallible>;
    }

    impl Sealed for () {
        fn to_k8s_service(self) -> BoxService<Request, Response, Infallible> {
            service_fn(async || Ok(StatusCode::OK.into_response())).boxed()
        }
    }

    impl<F: Fn() -> bool + Clone + Send + Sync + 'static> Sealed for F {
        fn to_k8s_service(self) -> BoxService<Request, Response, Infallible> {
            K8sService::new(self).boxed()
        }
    }
}
