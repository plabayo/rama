//! k8s web service

use crate::{
    Request, Response, StatusCode, matcher::HttpMatcher,
    service::web::endpoint::response::IntoResponse,
};
use rama_core::{
    Context, Service,
    service::{BoxService, service_fn},
};
use std::{convert::Infallible, fmt, marker::PhantomData, sync::Arc};

use super::match_service;

/// create a k8s web health service builder
#[must_use]
pub fn k8s_health_builder<S>() -> K8sHealthServiceBuilder<(), (), S> {
    K8sHealthServiceBuilder::new()
}

/// create a default k8s web health service
#[must_use]
pub fn k8s_health<S>() -> impl Service<S, Request, Response = Response, Error = Infallible> + Clone
where
    S: Clone + Send + Sync + 'static,
{
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
pub struct K8sHealthServiceBuilder<A, R, S> {
    alive: A,
    ready: R,
    _phantom: PhantomData<fn(S) -> ()>,
}

impl<A: fmt::Debug, R: fmt::Debug, S> std::fmt::Debug for K8sHealthServiceBuilder<A, R, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sHealthServiceBuilder")
            .field("alive", &self.alive)
            .field("ready", &self.ready)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(S) -> ()>()),
            )
            .finish()
    }
}

impl<A: Clone, R: Clone, S> Clone for K8sHealthServiceBuilder<A, R, S> {
    fn clone(&self) -> Self {
        Self {
            alive: self.alive.clone(),
            ready: self.ready.clone(),
            _phantom: PhantomData,
        }
    }
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
    S: Clone + Send + Sync + 'static,
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
pub trait ToK8sService<S>: private::Sealed<S> {}

impl<S: Clone + Send + Sync + 'static> ToK8sService<S> for () {}

impl<S, F> ToK8sService<S> for F
where
    F: Fn() -> bool + Clone + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
}

struct K8sService<F> {
    f: F,
}

impl<F: fmt::Debug> std::fmt::Debug for K8sService<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sService").field("f", &self.f).finish()
    }
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
    State: Clone + Send + Sync + 'static,
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
    use super::*;

    pub trait Sealed<S> {
        /// create a boxed web service by consuming self
        fn to_k8s_service(self) -> BoxService<S, Request, Response, Infallible>;
    }

    impl<S> Sealed<S> for () {
        fn to_k8s_service(self) -> BoxService<S, Request, Response, Infallible> {
            service_fn(async || Ok(StatusCode::OK.into_response())).boxed()
        }
    }

    impl<S: Clone + Send + Sync + 'static, F: Fn() -> bool + Clone + Send + Sync + 'static>
        Sealed<S> for F
    {
        fn to_k8s_service(self) -> BoxService<S, Request, Response, Infallible> {
            K8sService::new(self).boxed()
        }
    }
}
