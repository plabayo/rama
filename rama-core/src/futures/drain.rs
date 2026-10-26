use std::{pin::pin, time::Duration};

/// Drive two fallible directions, bounding the remaining work after either succeeds.
///
/// An error cancels the sibling immediately. Callers translate their protocol's normal
/// directional ends (including a closed destination) into success before joining.
/// `timeout` starts only after the first success; `None` permits an unbounded drain.
/// No task is spawned and dropping this future drops both directions.
pub async fn try_join_with_drain<A, B, E>(
    left: impl Future<Output = Result<A, E>>,
    right: impl Future<Output = Result<B, E>>,
    timeout: Option<Duration>,
    on_timeout: impl FnOnce() -> E,
) -> Result<(A, B), E> {
    let mut left = pin!(left);
    let mut right = pin!(right);
    tokio::select! {
        result = &mut left => {
            let left = result?;
            Ok((left, drain(right, timeout, on_timeout).await?))
        }
        result = &mut right => {
            let right = result?;
            Ok((drain(left, timeout, on_timeout).await?, right))
        }
    }
}

async fn drain<T, E>(
    future: impl Future<Output = Result<T, E>>,
    timeout: Option<Duration>,
    on_timeout: impl FnOnce() -> E,
) -> Result<T, E> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, future)
            .await
            .map_err(|_elapsed| on_timeout())?,
        None => future.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::futures::{FutureExt as _, future, poll};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test(start_paused = true)]
    async fn the_first_success_starts_the_drain_deadline() {
        for left_first in [false, true] {
            let direction = |first| async move {
                tokio::time::sleep(Duration::from_secs(if first { 10 } else { 12 })).await;
                Ok::<_, &str>(first)
            };
            assert_eq!(
                try_join_with_drain(
                    direction(left_first),
                    direction(!left_first),
                    Some(Duration::from_secs(3)),
                    || "timeout"
                )
                .await,
                Ok((left_first, !left_first))
            );
        }
    }

    struct Pending(Arc<AtomicUsize>);
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl Future for Pending {
        type Output = Result<(), &'static str>;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn errors_timeouts_and_cancellation_release_both_directions() {
        let dropped = Arc::new(AtomicUsize::new(0));
        for left_first in [false, true] {
            for error in [false, true] {
                let completed = future::ready(if error { Err("failed") } else { Ok(()) });
                let pending = Pending(dropped.clone());
                let result = if left_first {
                    try_join_with_drain(
                        completed,
                        pending,
                        Some(Duration::from_secs(2)),
                        || "timeout",
                    )
                    .await
                } else {
                    try_join_with_drain(
                        pending,
                        completed,
                        Some(Duration::from_secs(2)),
                        || "timeout",
                    )
                    .await
                };
                assert_eq!(result, Err(if error { "failed" } else { "timeout" }));
            }
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
        let mut joining = Box::pin(try_join_with_drain(
            Pending(dropped.clone()),
            Pending(dropped.clone()),
            None,
            || "timeout",
        ));
        assert!(poll!(&mut joining).is_pending());
        drop(joining);
        assert_eq!(dropped.load(Ordering::Relaxed), 6);
        assert!(
            try_join_with_drain(
                Pending(dropped.clone()),
                Pending(dropped.clone()),
                None,
                || "timeout"
            )
            .now_or_never()
            .is_none()
        );
        assert_eq!(dropped.load(Ordering::Relaxed), 8);
    }
}
