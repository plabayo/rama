//! Middleware that runs every input in its own child [`Scope`].
//!
//! The child is made in the scope the input runs in, merged with the layer's parent if it has
//! one (a new root without either, see [`enter_scope_with`]), and is the scope the inner service
//! sees. It is cancelled after `max_age` and aborted
//! `grace` later or at `hard_max_age`. The inner service decides what the graceful phase
//! means for it; at the hard phase its future is dropped.

use std::{error, fmt, time::Duration};

use rama_error::{BoxError, ErrorContext, ErrorExt};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use crate::{
    Layer, Service,
    extensions::ExtensionsRef,
    graceful::{Cause, Scope, ScopeClosed, WeakScope, enter_scope, enter_scope_with},
};

/// Runs every input in its own child [`Scope`], see the [module docs](self).
#[derive(Debug, Clone, Default)]
pub struct ScopeLayer {
    parent: Option<WeakScope>,
    max_age: Option<Duration>,
    grace: Option<Duration>,
    hard_max_age: Option<Duration>,
}

impl ScopeLayer {
    /// A layer that only gives every input its own child scope.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            parent: None,
            max_age: None,
            grace: None,
            hard_max_age: None,
        }
    }

    generate_set_and_with! {
        /// Also run every input in `parent`, such as the scope of the server that serves
        /// it, besides the scope the input already runs in. The layer does not hold it: an
        /// input arriving once it is closed is refused.
        pub fn parent(mut self, parent: Option<WeakScope>) -> Self {
            self.parent = parent;
            self
        }
    }

    generate_set_and_with! {
        /// Cancel the scope of an input this long after it started.
        pub fn max_age(mut self, max_age: Option<Duration>) -> Self {
            self.max_age = max_age;
            self
        }
    }

    generate_set_and_with! {
        /// Abort the scope of an input this long after it is cancelled, for any cause.
        pub fn grace(mut self, grace: Option<Duration>) -> Self {
            self.grace = grace;
            self
        }
    }

    generate_set_and_with! {
        /// Abort the scope of an input this long after it started.
        pub fn hard_max_age(mut self, hard_max_age: Option<Duration>) -> Self {
            self.hard_max_age = hard_max_age;
            self
        }
    }

    /// The scope of an input: a new one in the scope it runs in.
    fn scope_for(&self, input: &impl ExtensionsRef) -> Result<Scope, ScopeClosed> {
        let scope = match &self.parent {
            Some(parent) => enter_scope_with(input.extensions(), parent)?,
            None => enter_scope(input.extensions())?,
        };
        Ok(scope
            .maybe_with_timeout(self.max_age)
            .maybe_with_grace(self.grace)
            .maybe_with_hard_timeout(self.hard_max_age))
    }
}

impl<S> Layer<S> for ScopeLayer {
    type Service = ScopeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ScopeService {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ScopeService { inner, layer: self }
    }
}

/// The [`Service`] made by [`ScopeLayer`].
#[derive(Debug, Clone, ExtensionsRef)]
pub struct ScopeService<S> {
    inner: S,
    layer: ScopeLayer,
}

impl<S> ScopeService<S> {
    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for ScopeService<S>
where
    Input: ExtensionsRef + Send + 'static,
    S: Service<Input, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let scope = self.layer.scope_for(&input)?;
        match scope.run_until_aborted(self.inner.serve(input)).await {
            Some(result) => result.into_box_error(),
            None => Err(ScopeAborted {
                cause: scope.abort_cause(),
            }
            .into_box_error()),
        }
    }
}

/// The scope of an input was aborted before its service finished.
#[derive(Debug, Clone)]
pub struct ScopeAborted {
    cause: Option<Cause>,
}

impl ScopeAborted {
    /// Why the scope was aborted.
    #[must_use]
    pub fn cause(&self) -> Option<&Cause> {
        self.cause.as_ref()
    }
}

impl fmt::Display for ScopeAborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Some(cause) => write!(f, "scope aborted: {cause}"),
            None => f.write_str("scope aborted"),
        }
    }
}

impl error::Error for ScopeAborted {}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use crate::{extensions::Extensions, service::service_fn};

    use crate::graceful::{WeakScope, attach_scope, scope_context};

    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn input_gets_a_child_of_the_scope_in_its_extensions() {
        let parent = Scope::new();
        let input = Extensions::new();
        attach_scope(&input, &parent);
        let service = ScopeLayer::new().into_layer(service_fn(async |input: Extensions| {
            let scope = scope_context(&input)
                .and_then(WeakScope::into_scope)
                .unwrap();
            Ok::<_, Infallible>(scope)
        }));
        let scope = service.serve(input).await.unwrap();
        assert!(!scope.is_cancelled());
        parent.cancel(Cause::Owner);
        assert!(scope.is_cancelled());
    }

    #[tokio::test]
    async fn child_cancel_stays_below_the_parent() {
        let parent = Scope::new();
        let input = Extensions::new();
        attach_scope(&input, &parent);
        let service = ScopeLayer::new().into_layer(service_fn(async |input: Extensions| {
            scope_context(&input)
                .unwrap()
                .cancel(Cause::Reason("inner"));
            Ok::<_, Infallible>(())
        }));
        service.serve(input).await.unwrap();
        assert!(!parent.is_cancelled());
    }

    #[tokio::test]
    async fn without_a_scope_the_input_gets_a_root() {
        let service = ScopeLayer::new().into_layer(service_fn(async |input: Extensions| {
            let scope = scope_context(&input).and_then(WeakScope::into_scope);
            Ok::<_, Infallible>(scope)
        }));
        let scope = service.serve(Extensions::new()).await.unwrap().unwrap();
        assert!(!scope.is_detached());
        assert!(!scope.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn max_age_cancels_and_grace_aborts_the_inner_future() {
        let service = ScopeLayer::new()
            .with_max_age(3 * SEC)
            .with_grace(2 * SEC)
            .into_layer(service_fn(async |input: Extensions| {
                let scope = scope_context(&input)
                    .and_then(WeakScope::into_scope)
                    .unwrap();
                scope.cancelled().await;
                assert!(matches!(scope.cause(), Some(Cause::Deadline)));
                std::future::pending::<()>().await;
                Ok::<_, Infallible>(())
            }));
        let start = tokio::time::Instant::now();
        let err = service.serve(Extensions::new()).await.unwrap_err();
        assert_eq!(start.elapsed(), 5 * SEC);
        let aborted = err.downcast_ref::<ScopeAborted>().unwrap();
        assert!(matches!(aborted.cause(), Some(Cause::GraceElapsed)));
        assert!(aborted.to_string().contains("grace"));
    }

    #[tokio::test(start_paused = true)]
    async fn hard_max_age_aborts_without_a_graceful_deadline() {
        let service = ScopeLayer::new()
            .with_hard_max_age(4 * SEC)
            .into_layer(service_fn(async |_: Extensions| {
                std::future::pending::<()>().await;
                Ok::<_, Infallible>(())
            }));
        let start = tokio::time::Instant::now();
        let err = service.serve(Extensions::new()).await.unwrap_err();
        assert_eq!(start.elapsed(), 4 * SEC);
        assert!(matches!(
            err.downcast_ref::<ScopeAborted>().unwrap().cause(),
            Some(Cause::Deadline)
        ));
    }

    #[tokio::test]
    async fn parent_abort_reaches_the_inner_future() {
        let parent = Scope::new();
        let input = Extensions::new();
        attach_scope(&input, &parent);
        let service = ScopeLayer::new().into_layer(service_fn(async |_: Extensions| {
            std::future::pending::<()>().await;
            Ok::<_, Infallible>(())
        }));
        let serving = tokio::spawn(async move { service.serve(input).await });
        tokio::task::yield_now().await;
        parent.abort(Cause::Reason("stop"));
        let err = serving.await.unwrap().unwrap_err();
        let aborted = err.downcast_ref::<ScopeAborted>().unwrap();
        assert!(matches!(aborted.cause(), Some(Cause::Reason("stop"))));
    }

    #[tokio::test]
    async fn inner_errors_pass_through() {
        let service = ScopeLayer::new().into_layer(service_fn(async |_: Extensions| {
            Err::<(), _>(std::io::Error::other("inner"))
        }));
        let err = service.serve(Extensions::new()).await.unwrap_err();
        assert_eq!(err.to_string(), "inner");
    }
}
