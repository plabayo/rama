//! Middleware that allows a user to cancel an operation using a controller.
//!
//! This is similar to a timeout but based on any kind of external condition.

use super::{LayerErrorFn, LayerErrorStatic, MakeLayerError};
use crate::{Service, extensions::ExtensionsMut};
use rama_utils::macros::define_inner_service_accessors;
use tokio::sync::{mpsc, oneshot};

mod error;
#[doc(inline)]
pub use error::Aborted;

mod layer;
#[doc(inline)]
pub use layer::AbortableLayer;

#[derive(Debug, Clone)]
/// Controller used to abort a connected [`Abortable`].
///
/// Use [`AbortController::abort`] to abort the connected [`Abortable`].
pub struct AbortController {
    abort_tx: mpsc::Sender<oneshot::Sender<()>>,
}

impl AbortController {
    #[inline(always)]
    /// Abort the connected [`Abortable`]
    pub async fn abort(&self) {
        let (tx, rx) = oneshot::channel();
        if self.abort_tx.send(tx).await.is_err() {
            tracing::trace!("abortable already aborted");
        }
        if let Err(err) = rx.await {
            tracing::debug!("abortable notify recv error: {err}");
        }
    }
}

/// Applies the option to abort an inner service.
#[derive(Debug, Clone)]
pub struct Abortable<S, F> {
    inner: S,
    into_error: F,
}

impl<S, F> Abortable<S, F> {
    define_inner_service_accessors!();
}

/// default [`Abortable`]
pub type DefaultAbortable<S> = Abortable<S, LayerErrorStatic<Aborted>>;

// ===== impl Abortable =====

impl<S> DefaultAbortable<S> {
    /// Creates a new [`Abortable`]
    #[inline(always)]
    pub fn new(inner: S) -> Self {
        Self::with_error(inner, Aborted::new())
    }
}

impl<S, E> Abortable<S, LayerErrorStatic<E>> {
    /// Creates a new [`Abortable`] with a custom error
    /// value.
    pub fn with_error(inner: S, error: E) -> Self
    where
        E: Clone + Send + Sync + 'static,
    {
        Self {
            inner,
            into_error: LayerErrorStatic::new(error),
        }
    }
}

impl<S, F> Abortable<S, LayerErrorFn<F>> {
    /// Creates a new [`Abortable`] with a custom error
    /// function.
    pub fn with_error_fn<E>(inner: S, error_fn: F) -> Self
    where
        F: Fn() -> E + Send + Sync + 'static,
        E: Send + 'static,
    {
        Self {
            inner,
            into_error: LayerErrorFn::new(error_fn),
        }
    }
}

impl<S, F> Abortable<S, F>
where
    F: MakeLayerError,
{
    /// Creates a new [`Abortable`] with a custom error
    /// value.
    pub(crate) fn with(inner: S, into_error: F) -> Self {
        Self { inner, into_error }
    }
}

impl<T, F, Input, E> Service<Input> for Abortable<T, F>
where
    Input: ExtensionsMut + Send + 'static,
    F: MakeLayerError<Error = E>,
    E: Into<T::Error> + Send + 'static,
    T: Service<Input>,
{
    type Output = T::Output;
    type Error = T::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let (abort_tx, mut abort_rx) = mpsc::channel(1);
        input.extensions_mut().insert(AbortController {
            // clone so that we ensure we never abort due to no more controller...
            abort_tx: abort_tx.clone(),
        });
        tokio::select! {
            res = self.inner.serve(input) => res,
            maybe_notify = abort_rx.recv() => {
                if let Some(notify) = maybe_notify {
                    let _ = notify.send(());
                }
                tracing::debug!("abortable svc aborted by controller");
                Err(self.into_error.make_layer_error().into())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use rama_error::BoxError;

    use crate::{ServiceInput, extensions::ExtensionsRef as _, service::service_fn};

    use super::*;

    #[tokio::test]
    async fn test_abortable_in_flight() {
        let abortable_svc = Abortable::new(service_fn(async move |input: ServiceInput<()>| {
            input
                .extensions()
                .get::<AbortController>()
                .unwrap()
                .abort()
                .await;
            Ok::<_, BoxError>(())
        }));

        assert!(abortable_svc.serve(ServiceInput::new(())).await.is_err());
    }
}
