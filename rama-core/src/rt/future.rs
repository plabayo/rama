//! `std::future` extension

use std::task::{Context, Poll};

/// Poll the future once and return `Some` if it is ready, else `None`.
///
/// If the future wasn't ready, it future likely can't be driven to completion any more: the polling
/// uses a no-op waker, so knowledge of what the pending future was waiting for is lost.
pub fn now_or_never<F: Future>(fut: F) -> Option<F::Output> {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let fut = std::pin::pin!(fut);
    match fut.poll(&mut cx) {
        Poll::Ready(res) => Some(res),
        Poll::Pending => None,
    }
}
