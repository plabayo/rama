use super::{BodyExt, CollectOptions, LengthLimitError};
use bytes::Buf;
use rama_core::error::BoxError;
use std::pin::pin;

pub(super) async fn drain<B: BodyExt<Error: Into<BoxError>>>(
    body: B,
    options: CollectOptions,
) -> Result<(), BoxError> {
    let consume = async move {
        let mut body = pin!(body);
        let mut remaining = options.max_size;
        let mut frames = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(Into::into)?;
            if let (Some(left), Some(data)) = (&mut remaining, frame.data_ref()) {
                *left = left.checked_sub(data.remaining()).ok_or(LengthLimitError)?;
            }
            drop(frame);
            frames += 1;
            if frames == 16 {
                // Always-ready producers (including empty frames) must allow
                // cancellation and the absolute deadline to make progress.
                tokio::task::yield_now().await;
                frames = 0;
            }
        }
        Ok(())
    };
    match options.timeout {
        Some(timeout) => tokio::time::timeout(timeout, consume).await?,
        None => consume.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, HeaderMap, body::Frame};
    use bytes::Bytes;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[tokio::test]
    async fn drains_data_trailers_and_eof_at_exact_limit() {
        let polls = Arc::new(AtomicUsize::new(0));
        let count = polls.clone();
        let mut frames = [
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::trailers(HeaderMap::new())),
        ]
        .into_iter();
        let body = Body::from_frame_stream(rama_core::futures::stream::poll_fn(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
            std::task::Poll::Ready(frames.next())
        }));
        body.drain_with(CollectOptions::new().with_max_size(3))
            .await
            .unwrap();
        assert_eq!(polls.load(Ordering::Relaxed), 3);
        Body::empty()
            .drain_with(CollectOptions::new().with_max_size(0))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn supports_pinned_streams_and_releases_each_frame_before_reading_next() {
        struct Owner(Arc<AtomicUsize>);
        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                b"payload"
            }
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let count = dropped.clone();
        let frames = rama_core::futures::stream::unfold(0, move |index| {
            let count = count.clone();
            async move {
                assert_eq!(count.load(Ordering::Relaxed), index);
                (index < 3).then(|| {
                    (
                        Ok::<_, Infallible>(Frame::data(Bytes::from_owner(Owner(count)))),
                        index + 1,
                    )
                })
            }
        });
        // unfold's async state is !Unpin: the utility must pin it safely.
        super::super::StreamBody::new(frames).drain().await.unwrap();
        assert_eq!(dropped.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn reports_limits_and_original_body_errors() {
        assert!(
            Body::from("abc")
                .drain_with(CollectOptions::new().with_max_size(2))
                .await
                .unwrap_err()
                .is::<LengthLimitError>()
        );
        assert!(
            Body::from("abc")
                .limited(2)
                .drain()
                .await
                .unwrap_err()
                .is::<LengthLimitError>()
        );
        let body = Body::from_frame_stream(rama_core::stream::iter([Err::<Frame<Bytes>, _>(
            std::io::Error::other("failed"),
        )]));
        assert!(body.drain().await.unwrap_err().is::<std::io::Error>());
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_bounds_pending_and_always_ready_bodies() {
        // A timer must still win when an adversarial body yields empty frames forever.
        for ready in [false, true] {
            let body = Body::from_frame_stream(rama_core::futures::stream::poll_fn(move |_| {
                if ready {
                    std::task::Poll::Ready(Some(Ok::<_, Infallible>(Frame::data(Bytes::new()))))
                } else {
                    std::task::Poll::Pending
                }
            }));
            let task = tokio::spawn(
                body.drain_with(CollectOptions::new().with_timeout(Duration::from_secs(1))),
            );
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(
                task.await
                    .unwrap()
                    .unwrap_err()
                    .is::<tokio::time::error::Elapsed>()
            );
        }
    }
}
