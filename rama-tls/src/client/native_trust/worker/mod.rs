use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
    time::Duration,
};

use rama_core::{futures::Stream, telemetry::tracing::warn};
use rama_crypto::native_certs::{NativeCertsChanges, NativeCertsWake};

/// Requests a refresh after the operating system's native trust store changes.
///
/// macOS watches the certificate-trust notification posted by securityd.
/// Windows watches the current-user and local-machine ROOT stores. File-backed
/// stores, including `SSL_CERT_FILE`, `SSL_CERT_DIR` and the corresponding
/// `SSL_CERT_EXTRA_*` settings, are checked using file metadata.
///
/// A reported notification failure requests a refresh and retries the watch at
/// the file probe interval. A missed notification on an apparently healthy
/// watch can leave a snapshot stale. Set
/// [`NativeTrustPolicy::with_max_age`](crate::client::NativeTrustPolicy::with_max_age)
/// to require a fresh native trust read on the first handshake at the age limit.
pub struct NativeTrustStoreChanges {
    interval: Duration,
    extra_only: bool,
    worker: Option<NativeChangesWorker>,
}

impl NativeTrustStoreChanges {
    /// Set the file metadata polling interval, with a minimum of 10 ms.
    ///
    /// The first poll starts a monitor thread, which sleeps until a store
    /// notification or the next file probe. Once its initial probe completes
    /// it asks the next handshake to recheck trust. Dropping the stream stops
    /// its monitor. If the monitor cannot start, the stream ends.
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            extra_only: false,
            worker: None,
        }
    }

    /// Monitor only the file and directory named by `SSL_CERT_EXTRA_FILE`
    /// and `SSL_CERT_EXTRA_DIR`, using a polling interval of at least 10 ms.
    ///
    /// Use this when refreshing extra roots for an active platform verifier.
    /// The monitor does not register for OS trust store notifications or
    /// discover replacement root paths. Its events request a refresh, while
    /// the configured TLS trust source determines which roots to read.
    pub const fn extra_roots(interval: Duration) -> Self {
        Self {
            interval,
            extra_only: true,
            worker: None,
        }
    }
}

impl Default for NativeTrustStoreChanges {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl Stream for NativeTrustStoreChanges {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        let interval = self.interval;
        let extra_only = self.extra_only;
        let worker = self
            .worker
            .get_or_insert_with(|| NativeChangesWorker::new(interval, extra_only));
        Pin::new(&mut worker.events).poll_next(cx)
    }
}

const MIN_INTERVAL: Duration = Duration::from_millis(10);

type MonitorTask = Box<dyn FnOnce() + Send + 'static>;

struct NativeChangesWorker {
    events: flume::r#async::RecvStream<'static, ()>,
    monitor: Option<Monitor>,
}

struct Monitor {
    wake: Arc<NativeCertsWake>,
    stop: Arc<AtomicBool>,
}

impl NativeChangesWorker {
    fn new(interval: Duration, extra_only: bool) -> Self {
        Self::start(interval, extra_only, |task| {
            thread::Builder::new()
                .name("rama-native-trust-probe".into())
                .spawn(task)
        })
    }

    // Without a monitor the event sender is gone, so the stream ends and the
    // reload controller stops polling it.
    fn start(
        interval: Duration,
        extra_only: bool,
        spawn: impl FnOnce(MonitorTask) -> io::Result<JoinHandle<()>>,
    ) -> Self {
        // One queued event is enough to tell the next handshake to read trust.
        let (changes, events) = flume::bounded(1);
        let monitor = NativeCertsWake::new()
            .and_then(|wake| {
                let wake = Arc::new(wake);
                let stop = Arc::new(AtomicBool::new(false));
                let task = {
                    let (wake, stop) = (wake.clone(), stop.clone());
                    Box::new(move || monitor_changes(interval, extra_only, &changes, &wake, &stop))
                };
                // The monitor is detached: dropping the stream stops it via `stop` and `wake`.
                spawn(task).map(drop)?;
                Ok(Monitor { wake, stop })
            })
            .inspect_err(|error| {
                warn!(
                    %error,
                    "could not start native trust store monitor; store changes will not trigger reloads"
                );
            })
            .ok();
        Self {
            events: events.into_stream(),
            monitor,
        }
    }
}

impl Drop for NativeChangesWorker {
    fn drop(&mut self) {
        if let Some(monitor) = &self.monitor {
            monitor.stop.store(true, Ordering::Release);
            monitor.wake.wake();
        }
    }
}

fn monitor_changes(
    interval: Duration,
    extra_only: bool,
    events: &flume::Sender<()>,
    wake: &NativeCertsWake,
    stop: &AtomicBool,
) {
    let interval = interval.max(MIN_INTERVAL);
    let mut changes = if extra_only {
        NativeCertsChanges::extra_only(interval)
    } else {
        NativeCertsChanges::new(interval)
    };

    // Request a fresh read after registration because the initial handshake
    // can read the store while the worker is establishing its baseline.
    changes.changed();
    let mut changed = true;
    while !stop.load(Ordering::Acquire) {
        if changed
            && matches!(
                events.try_send(()),
                Err(flume::TrySendError::Disconnected(()))
            )
        {
            break;
        }
        // Blocks until a store notification, the next file probe, or a stop request.
        changed = changes.wait_changed(wake);
    }
}

#[cfg(test)]
mod tests;
