use super::{DelayStream, FutureExt as _, GracefulStream, StreamExt as _, stream};

use std::time::Duration;
use tokio::time;

#[tokio::test]
async fn delays_first_item_only() {
    time::pause();

    let dur = Duration::from_millis(10);
    let mut s = std::pin::pin!(DelayStream::new(dur, stream::iter([1u8, 2, 3])));

    tokio::time::sleep(Duration::from_micros(100)).await;
    assert_eq!(s.next().now_or_never(), None);

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(s.next().await, Some(1));
    assert_eq!(s.next().await, Some(2));
    assert_eq!(s.next().await, Some(3));
    assert_eq!(s.next().await, None);
}

#[tokio::test]
async fn immediate_when_duration_zero() {
    let mut s = std::pin::pin!(DelayStream::new(Duration::ZERO, stream::iter([10u8, 20])));

    assert_eq!(s.next().now_or_never().unwrap(), Some(10));
    assert_eq!(s.next().now_or_never().unwrap(), Some(20));
    assert_eq!(s.next().now_or_never().unwrap(), None);
}

#[tokio::test]
async fn graceful_stream_cancels_pending_stream() {
    time::pause();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let cancel = async move {
        let _ = rx.await;
    };

    let delayed = DelayStream::new(Duration::from_secs(10), stream::iter([1u8, 2, 3]));
    let mut s = std::pin::pin!(GracefulStream::new(cancel, delayed));

    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(s.next().now_or_never(), None);

    let _ = tx.send(());
    assert_eq!(s.next().await, None);
    assert_eq!(s.next().await, None);
}

#[tokio::test]
async fn graceful_stream_stops_after_cancel_even_if_stream_has_more_items() {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let cancel = async move {
        let _ = rx.await;
    };
    let mut s = std::pin::pin!(GracefulStream::new(cancel, stream::iter([1u8, 2, 3])));

    assert_eq!(s.next().await, Some(1));
    let _ = tx.send(());
    assert_eq!(s.next().await, None);
    assert_eq!(s.next().await, None);
}
