use std::fmt;
use std::sync::Arc;

use rama_core::{Layer, Service};
use rama_http_types::{Request, Response, request, response};

use super::{request_host_class, response_host_class};
use crate::{JsEngine, JsError, JsHostClass, JsRuntime, JsScript};

const REQUEST_HOOK: &str = "onRequest";
const REQUEST_HOOK_CALL: &str = "onRequest(request)";
const RESPONSE_HOOK: &str = "onResponse";
const RESPONSE_HOOK_CALL: &str = "onResponse(response)";

/// Select JavaScript for one HTTP exchange.
///
/// The provider is consulted once, before the request hook runs. Returning
/// `None` bypasses JavaScript for both the request and response. The selected
/// script may define `onRequest(request)` and `onResponse(response)` functions.
/// Each hook receives its corresponding native object. The source is evaluated
/// in a fresh runtime for each phase, so JavaScript globals created by the
/// request hook do not carry over to the response hook.
pub trait JsHttpScriptProvider: Send + Sync + 'static {
    /// Select a script using the original request head.
    fn script(&self, request: &request::Parts) -> Result<Option<JsScript>, JsError>;
}

impl<T> JsHttpScriptProvider for Arc<T>
where
    T: JsHttpScriptProvider + ?Sized,
{
    fn script(&self, request: &request::Parts) -> Result<Option<JsScript>, JsError> {
        self.as_ref().script(request)
    }
}

impl JsHttpScriptProvider for JsScript {
    fn script(&self, _request: &request::Parts) -> Result<Option<JsScript>, JsError> {
        Ok(Some(self.clone()))
    }
}

/// An error produced by [`JsHttpService`].
pub enum JsHttpError<E> {
    /// Script selection or execution failed.
    JavaScript(JsError),
    /// The inner service failed.
    Inner(E),
}

impl<E: fmt::Debug> fmt::Debug for JsHttpError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JavaScript(error) => f.debug_tuple("JavaScript").field(error).finish(),
            Self::Inner(error) => f.debug_tuple("Inner").field(error).finish(),
        }
    }
}

impl<E: fmt::Display> fmt::Display for JsHttpError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JavaScript(error) => fmt::Display::fmt(error, f),
            Self::Inner(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl<E> std::error::Error for JsHttpError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::JavaScript(error) => Some(error),
            Self::Inner(error) => Some(error),
        }
    }
}

impl<E> From<JsError> for JsHttpError<E> {
    fn from(value: JsError) -> Self {
        Self::JavaScript(value)
    }
}

/// Layer which applies JavaScript request and response hooks.
#[derive(Debug, Clone)]
pub struct JsHttpLayer<P = JsScript> {
    engine: JsEngine,
    provider: P,
    request_class: JsHostClass<request::Parts>,
    response_class: JsHostClass<response::Parts>,
}

impl JsHttpLayer<JsScript> {
    /// Create a layer which uses the same script for every request.
    pub fn new(script: impl Into<JsScript>) -> Self {
        Self::with_provider(script.into())
    }
}

impl<P: JsHttpScriptProvider> JsHttpLayer<P> {
    /// Create a layer using a custom per-request script provider.
    pub fn with_provider(provider: P) -> Self {
        Self {
            engine: JsEngine::new(JsRuntime::builder()),
            provider,
            request_class: request_host_class(),
            response_class: response_host_class(),
        }
    }

    /// Use a custom JavaScript engine blueprint.
    #[must_use]
    pub fn with_engine(mut self, engine: JsEngine) -> Self {
        self.engine = engine;
        self
    }
}

impl<S, P> Layer<S> for JsHttpLayer<P>
where
    P: JsHttpScriptProvider + Clone,
{
    type Service = JsHttpService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        JsHttpService {
            inner,
            engine: self.engine.clone(),
            provider: self.provider.clone(),
            request_class: self.request_class.clone(),
            response_class: self.response_class.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        JsHttpService {
            inner,
            engine: self.engine,
            provider: self.provider,
            request_class: self.request_class,
            response_class: self.response_class,
        }
    }
}

/// Service which applies JavaScript request and response hooks around an HTTP
/// inner service.
#[derive(Debug, Clone)]
pub struct JsHttpService<S, P = JsScript> {
    inner: S,
    engine: JsEngine,
    provider: P,
    request_class: JsHostClass<request::Parts>,
    response_class: JsHostClass<response::Parts>,
}

impl<S> JsHttpService<S, JsScript> {
    /// Wrap a service with one static script.
    pub fn new(inner: S, script: impl Into<JsScript>) -> Self {
        JsHttpLayer::new(script).into_layer(inner)
    }
}

impl<S, P: JsHttpScriptProvider> JsHttpService<S, P> {
    /// Wrap a service with a custom per-request script provider.
    pub fn with_provider(inner: S, provider: P) -> Self {
        Self {
            inner,
            engine: JsEngine::new(JsRuntime::builder()),
            provider,
            request_class: request_host_class(),
            response_class: response_host_class(),
        }
    }

    /// Use a custom JavaScript engine blueprint.
    #[must_use]
    pub fn with_engine(mut self, engine: JsEngine) -> Self {
        self.engine = engine;
        self
    }

    /// Borrow the inner service.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Mutably borrow the inner service.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume this middleware and return the inner service.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S, P, ReqBody, ResBody> Service<Request<ReqBody>> for JsHttpService<S, P>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    P: JsHttpScriptProvider,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = JsHttpError<S::Error>;

    async fn serve(&self, request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let (request_parts, request_body) = request.into_parts();
        let Some(script) = self.provider.script(&request_parts)? else {
            return self
                .inner
                .serve(Request::from_parts(request_parts, request_body))
                .await
                .map_err(JsHttpError::Inner);
        };

        let request_parts = execute_hook(
            &self.engine,
            &self.request_class,
            script.clone(),
            REQUEST_HOOK,
            REQUEST_HOOK_CALL,
            "request",
            request_parts,
        )
        .await?;
        let response = self
            .inner
            .serve(Request::from_parts(request_parts, request_body))
            .await
            .map_err(JsHttpError::Inner)?;

        let (response_parts, response_body) = response.into_parts();
        let response_parts = execute_hook(
            &self.engine,
            &self.response_class,
            script,
            RESPONSE_HOOK,
            RESPONSE_HOOK_CALL,
            "response",
            response_parts,
        )
        .await?;
        Ok(Response::from_parts(response_parts, response_body))
    }
}

async fn execute_hook<T>(
    engine: &JsEngine,
    class: &JsHostClass<T>,
    script: JsScript,
    hook: &'static str,
    hook_call: &'static str,
    global: &'static str,
    value: T,
) -> Result<T, JsError>
where
    T: Send + 'static,
{
    let class = class.clone();
    engine
        .run(move |runtime| {
            let (object, handle) = class.bind(value);
            runtime.set_host_global(global, object)?;
            runtime.exec(script.as_str())?;
            if runtime.has_global_fn(hook) {
                runtime.exec(hook_call)?;
            }
            handle.take()
        })
        .await
}
