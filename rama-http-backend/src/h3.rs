//! Shared HTTP/3 dispatch completion: received input still belongs to accepted work.

use rama_core::{
    error::BoxError,
    futures::{StreamExt as _, stream::FuturesUnordered, try_zip},
    graceful::{Scope, WeakScope},
    telemetry::tracing,
};
use rama_http_core::h3::{Error, qpack::ErrorScope};
use rama_http_types::proto::h3::Code;
use std::{io, time::Duration};

pub(crate) fn clean_close(error: Error) -> bool {
    error.scope() == ErrorScope::Connection && error.code() == Code::H3_NO_ERROR
}

/// Wait for `drained` at most `limit`: a peer that stopped acknowledging the GOAWAY and the
/// last responses does not hold the connection once its requests ended.
pub(crate) async fn drained_within(
    drained: impl Future<Output = Result<(), Error>>,
    limit: Option<Duration>,
) -> Result<(), Error> {
    match limit {
        Some(limit) => tokio::time::timeout(limit, drained)
            .await
            .unwrap_or_else(|_elapsed| {
                tracing::debug!("HTTP/3 GOAWAY drain timed out: closing the connection");
                Ok(())
            }),
        None => drained.await,
    }
}

pub(crate) fn completed(result: Result<(), Error>) -> Result<(), BoxError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if clean_close(error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Poll the driver and accepted requests together after transport closure. A service
/// can own its tunnel inside its request future, so awaiting the driver alone loses input.
///
/// Runs in `scope` for `timeout` at most: accepted work outlives a graceful phase and ends
/// at the hard phase of `scope` or at the timeout, whichever comes first.
pub(crate) async fn drain<F>(
    driver: impl Future<Output = Result<(), Error>>,
    requests: &mut FuturesUnordered<F>,
    timeout: Duration,
    scope: &WeakScope,
) -> Result<(), BoxError>
where
    F: Future<Output = Result<(), Error>>,
{
    let work = try_zip(async { completed(driver.await) }, async {
        while let Some(result) = requests.next().await {
            if let Err(error) = result {
                if error.scope() == ErrorScope::Connection {
                    completed(Err(error))?;
                } else {
                    tracing::debug!(%error, "HTTP/3 request ended during connection drain");
                }
            }
        }
        Ok(())
    });
    // A closed scope takes no holder: the drain then runs below no parent.
    let held = scope.try_hold().unwrap_or_else(|_closed| Scope::detached());
    // The hard phase is watched on the scope itself too: a scope that took no holder still
    // reaches it.
    let ended = tokio::select! {
        biased;
        () = scope.aborted() => None,
        ended = held.run_until_aborted_within(timeout, work) => ended,
    };
    match ended {
        Some(result) => result.map(|((), ())| ()),
        None if scope.is_aborted() => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "HTTP/3 connection drain cancelled",
        )
        .into()),
        None => {
            Err(io::Error::new(io::ErrorKind::TimedOut, "HTTP/3 connection drain timeout").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::graceful::Cause;
    use std::{
        future::{pending, ready},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::time::Instant;
    use tokio::time::sleep;

    const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
    const REQUEST: Duration = Duration::from_secs(2);

    type Request = Pin<Box<dyn Future<Output = Result<(), Error>>>>;

    /// One accepted request that takes `REQUEST`, or never ends, and whether it finished.
    fn accepted(ends: bool) -> (FuturesUnordered<Request>, Arc<AtomicBool>) {
        let finished = Arc::new(AtomicBool::new(false));
        let done = finished.clone();
        let requests = FuturesUnordered::new();
        requests.push(Box::pin(async move {
            if !ends {
                pending::<()>().await;
            }
            sleep(REQUEST).await;
            done.store(true, Ordering::Release);
            Ok(())
        }) as Request);
        (requests, finished)
    }

    fn kind(result: Result<(), BoxError>) -> io::ErrorKind {
        result
            .unwrap_err()
            .downcast_ref::<io::Error>()
            .expect("a drain ends with an I/O error")
            .kind()
    }

    #[tokio::test(start_paused = true)]
    async fn a_graceful_phase_lets_an_accepted_request_finish() {
        let scope = Scope::new();
        let weak = scope.clone_weak();
        let (mut requests, finished) = accepted(true);
        let start = Instant::now();
        let (drained, ()) = tokio::join!(
            drain(ready(Ok(())), &mut requests, CLOSE_TIMEOUT, &weak),
            async {
                sleep(REQUEST / 2).await;
                scope.cancel(Cause::Reason("test"));
            }
        );
        drained.unwrap();
        assert!(finished.load(Ordering::Acquire));
        assert_eq!(start.elapsed(), REQUEST);
    }

    #[tokio::test(start_paused = true)]
    async fn the_hard_phase_cuts_an_accepted_request() {
        for cancelled_first in [false, true] {
            let scope = Scope::new();
            if cancelled_first {
                scope.cancel(Cause::Reason("test"));
            }
            let weak = scope.clone_weak();
            let (mut requests, finished) = accepted(true);
            let start = Instant::now();
            let (drained, ()) = tokio::join!(
                drain(ready(Ok(())), &mut requests, CLOSE_TIMEOUT, &weak),
                async {
                    sleep(REQUEST / 2).await;
                    scope.abort(Cause::Reason("test"));
                }
            );
            assert_eq!(kind(drained), io::ErrorKind::Interrupted);
            assert!(!finished.load(Ordering::Acquire));
            assert_eq!(start.elapsed(), REQUEST / 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_its_peer_holds_is_released_at_the_close_timeout() {
        let scope = Scope::new();
        let (mut requests, _finished) = accepted(false);
        let start = Instant::now();
        let drained = drain(
            ready(Ok(())),
            &mut requests,
            CLOSE_TIMEOUT,
            &scope.clone_weak(),
        )
        .await;
        assert_eq!(kind(drained), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), CLOSE_TIMEOUT);
        assert!(!scope.is_cancelled(), "the timeout ends the drain alone");
    }

    #[tokio::test(start_paused = true)]
    async fn a_close_timeout_beyond_the_clock_waits_for_the_request() {
        let (mut requests, finished) = accepted(true);
        drain(
            ready(Ok(())),
            &mut requests,
            Duration::MAX,
            &WeakScope::detached(),
        )
        .await
        .unwrap();
        assert!(finished.load(Ordering::Acquire));
    }
}
