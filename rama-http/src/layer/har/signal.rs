use rama_core::futures::Future;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Spawns a task that toggles an `Arc<AtomicBool>` whenever the signal is read.
/// Returns the `Arc<AtomicBool>` and the `mpsc::Sender<()>` for signaling.
/// # Example
/// ```
/// use rama_http::layer::har::signal::signal_toggle;
/// use std::sync::atomic::Ordering;
///
/// # tokio_test::block_on(async {
/// let (flag, tx, _task) = signal_toggle();
///
/// // Send a signal to toggle the flag
/// tx.send(()).await.unwrap();
///
/// assert_eq!(flag.load(Ordering::Relaxed), false);
/// # });
/// ```
pub fn signal_toggle() -> (Arc<AtomicBool>, mpsc::Sender<()>, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<()>(16);
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = Arc::clone(&flag);

    let handle = tokio::spawn(async move {
        while let Some(_) = rx.recv().await {
            let current = flag_clone.load(Ordering::Acquire);
            flag_clone.store(!current, Ordering::Release);
        }
    });

    (flag, tx, handle)
}

/// Like `signal_toggle` but takes a cancel future to break out of the loop.
/// Useful for graceful shutdown.
/// Example:
/// ```
/// use std::sync::atomic::Ordering;
/// use tokio::sync::oneshot;
/// use rama_http::layer::har::signal::signal_toggle_with_cancel;
///
/// # tokio_test::block_on(async {
/// let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
/// let (flag, tx, handle) = signal_toggle_with_cancel(async {
///     let _ = cancel_rx.await;
/// });
///
/// // First signal flips to true
/// tx.send(()).await.unwrap();
/// assert_eq!(flag.load(Ordering::Relaxed), false);
///
/// // Cancel the background task
/// cancel_tx.send(()).unwrap();
/// let _ = handle.await;
///
/// // Sending after cancel won't flip again
/// let _ = tx.send(()).await;
/// assert_eq!(flag.load(Ordering::Relaxed), false);
/// # });
/// ```
pub fn signal_toggle_with_cancel<C, O>(
    cancel: C,
) -> (Arc<AtomicBool>, mpsc::Sender<()>, JoinHandle<()>)
where
    C: Future<Output = O> + Send + 'static,
    O: Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<()>(16);
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = Arc::clone(&flag);

    let handle = tokio::spawn(async move {
        tokio::select! {
            _ = async {
                while let Some(_) = rx.recv().await {
                    let current = flag_clone.load(Ordering::Acquire);
                    flag_clone.store(!current, Ordering::Release);
                }
            } => {},
            _ = cancel => {
                // graceful exit
            }
        }
    });

    (flag, tx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time;

    #[tokio::test]
    async fn test_signal_toggle_basic() {
        let (flag, tx, _task) = signal_toggle();

        // Initial value should be false
        assert_eq!(flag.load(Ordering::Relaxed), false);

        // First signal => true
        tx.send(()).await.unwrap();
        time::sleep(Duration::from_millis(10)).await;
        assert_eq!(flag.load(Ordering::Relaxed), true);

        // Second signal => false
        tx.send(()).await.unwrap();
        time::sleep(Duration::from_millis(10)).await;
        assert_eq!(flag.load(Ordering::Relaxed), false);
    }

    #[tokio::test]
    async fn test_signal_toggle_with_cancel() {
        use tokio::sync::oneshot;

        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let (flag, tx, handle) = signal_toggle_with_cancel(cancel_rx);

        // Toggle once before cancellation
        tx.send(()).await.unwrap();
        time::sleep(Duration::from_millis(10)).await;
        assert_eq!(flag.load(Ordering::Relaxed), true);

        // Cancel the loop
        cancel_tx.send(()).unwrap();
        let _ = handle.await;

        // Sending after cancel should not flip value
        let _ = tx.send(()).await;
        time::sleep(Duration::from_millis(10)).await;
        assert_eq!(flag.load(Ordering::Relaxed), true);
    }
}
