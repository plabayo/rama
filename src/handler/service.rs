use super::{Handler, IntoMakeService};
use http::Request;
use std::{
    convert::Infallible,
    fmt,
    marker::PhantomData,
    task::{Context, Poll},
};
use tower_service::Service;

/// An adapter that makes a [`Handler`] into a [`Service`].
///
/// Created with [`Handler::with_state`] or [`HandlerWithoutStateExt::into_service`].
///
/// [`HandlerWithoutStateExt::into_service`]: super::HandlerWithoutStateExt::into_service
pub struct HandlerService<H, T, S> {
    handler: H,
    state: S,
    _marker: PhantomData<fn() -> T>,
}

impl<H, T, S> HandlerService<H, T, S> {
    /// Get a reference to the state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Convert the handler into a [`MakeService`].
    ///
    /// [`MakeService`]: tower::make::MakeService
    pub fn into_make_service(self) -> IntoMakeService<HandlerService<H, T, S>> {
        IntoMakeService::new(self)
    }
}

#[test]
fn traits() {
    use crate::test_helpers::*;
    assert_send::<HandlerService<(), NotSendSync, ()>>();
    assert_sync::<HandlerService<(), NotSendSync, ()>>();
}

impl<H, T, S> HandlerService<H, T, S> {
    pub(super) fn new(handler: H, state: S) -> Self {
        Self {
            handler,
            state,
            _marker: PhantomData,
        }
    }
}

impl<H, T, S> fmt::Debug for HandlerService<H, T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntoService").finish_non_exhaustive()
    }
}

impl<H, T, S> Clone for HandlerService<H, T, S>
where
    H: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            state: self.state.clone(),
            _marker: PhantomData,
        }
    }
}
