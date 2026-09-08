//! Subscriptions deliver the initial query result and refreshed content.

use rama_core::{
    Service,
    futures::{Stream, async_stream::stream_fn},
};
use tokio::sync::watch;

/// Subscribe before evaluating the initial query. Slow consumers coalesce revisions
/// and receive fresh content instead of accumulating an unbounded event queue.
/// Closing the change source ends the subscription after its last refreshed result.
pub fn subscribe<S, Q>(
    mut changes: watch::Receiver<u64>,
    service: S,
    query: Q,
) -> impl Stream<Item = Result<S::Output, S::Error>> + Send + 'static
where
    S: Service<Q>,
    Q: Clone + Send + 'static,
{
    stream_fn(move |mut output| async move {
        loop {
            // Mark before querying: a change during the query must trigger another read.
            changes.borrow_and_update();
            output.yield_item(service.serve(query.clone()).await).await;
            if changes.changed().await.is_err() {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use rama_core::{futures::StreamExt, service::service_fn};

    use super::*;
    #[tokio::test]
    async fn initial_content_slow_consumers_and_changes_during_query() {
        let (changes, receiver) = watch::channel(0);
        let data = Arc::new(AtomicU64::new(0));
        let query_data = data.clone();
        let query_changes = changes.clone();
        let mut stream = Box::pin(subscribe(
            receiver,
            service_fn(move |()| {
                let current = query_data.load(Ordering::Relaxed);
                if current == 0 {
                    query_data.store(1, Ordering::Relaxed);
                    query_changes.send_replace(1);
                }
                async move { Ok::<_, Infallible>(current) }
            }),
            (),
        ));
        assert_eq!(stream.next().await, Some(Ok(0)));
        assert_eq!(stream.next().await, Some(Ok(1)));
        for revision in 2..100 {
            data.store(revision, Ordering::Relaxed);
            changes.send_replace(revision);
        }
        assert_eq!(stream.next().await, Some(Ok(99)));
    }

    #[tokio::test]
    async fn closed_source_delivers_unseen_content_and_then_ends() {
        let (changes, receiver) = watch::channel(0);
        let mut stream = Box::pin(subscribe(
            receiver,
            service_fn(|()| async { Ok::<_, Infallible>(42) }),
            (),
        ));
        assert_eq!(stream.next().await, Some(Ok(42)));
        changes.send_replace(1);
        drop(changes);
        assert_eq!(stream.next().await, Some(Ok(42)));
        assert_eq!(stream.next().await, None);
    }
}
