use std::{io, pin::pin, task::Poll, time::Duration};

use tokio::io::{AsyncWrite, AsyncWriteExt as _};

use crate::{
    futures::poll,
    graceful::{RunCutoff, WeakScope},
};

/// Shut `writer` down in order, bounded by the hard phase of `scope` and by `grace`.
///
/// An aborted scope skips the shutdown. A shutdown that is ready on its first poll needs no
/// peer and ends there, with nothing to bound. Otherwise it runs as
/// [`WeakScope::run_until_aborted_within`] does, and the [`RunCutoff`] that came first is
/// returned when the peer still holds it.
pub async fn shutdown_within<W>(
    writer: &mut W,
    scope: &WeakScope,
    grace: Duration,
) -> Result<io::Result<()>, RunCutoff>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if scope.is_aborted() {
        return Err(RunCutoff::Aborted);
    }
    let mut shutdown = pin!(writer.shutdown());
    if let Poll::Ready(closed) = poll!(shutdown.as_mut()) {
        return Ok(closed);
    }
    scope.run_until_aborted_within(grace, shutdown).await
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::{io::AsyncWrite, time::sleep};

    use super::*;
    use crate::graceful::{Cause, Scope};

    /// A writer whose shutdown completes only after `held` polls.
    struct HeldShutdown {
        held: usize,
        polls: usize,
    }

    impl HeldShutdown {
        fn new(held: usize) -> Self {
            Self { held, polls: 0 }
        }
    }

    impl AsyncWrite for HeldShutdown {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.polls += 1;
            if self.polls > self.held {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    const GRACE: Duration = Duration::from_secs(5);

    #[tokio::test(start_paused = true)]
    async fn ready_on_first_poll_needs_no_scope() {
        let scope = Scope::new();
        let weak = scope.clone_weak();
        let mut writer = HeldShutdown::new(0);
        assert!(matches!(
            shutdown_within(&mut writer, &weak, GRACE).await,
            Ok(Ok(()))
        ));
        assert_eq!(writer.polls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn aborted_scope_skips_the_shutdown() {
        let scope = Scope::new();
        scope.abort(Cause::Owner);
        let mut writer = HeldShutdown::new(0);
        assert!(matches!(
            shutdown_within(&mut writer, &scope.clone_weak(), GRACE).await,
            Err(RunCutoff::Aborted)
        ));
        assert_eq!(
            writer.polls, 0,
            "an aborted scope never starts the shutdown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn held_shutdown_times_out_after_grace() {
        let scope = Scope::new();
        let mut writer = HeldShutdown::new(usize::MAX);
        let start = tokio::time::Instant::now();
        assert!(matches!(
            shutdown_within(&mut writer, &scope.clone_weak(), GRACE).await,
            Err(RunCutoff::TimedOut)
        ));
        assert_eq!(start.elapsed(), GRACE);
    }

    #[tokio::test(start_paused = true)]
    async fn abort_after_start_cuts_a_held_shutdown() {
        let scope = Scope::new();
        let weak = scope.clone_weak();
        let mut writer = HeldShutdown::new(usize::MAX);
        let abort = async {
            sleep(Duration::from_secs(1)).await;
            scope.abort(Cause::Owner);
        };
        let (closed, ()) = tokio::join!(shutdown_within(&mut writer, &weak, GRACE), abort);
        assert!(matches!(closed, Err(RunCutoff::Aborted)));
    }
}
