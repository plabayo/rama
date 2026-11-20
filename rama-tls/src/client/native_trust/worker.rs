use rama_core::{futures::Stream, telemetry::tracing::warn};
use rama_crypto::native_certs::NativeCertsChanges;
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
    time::Duration,
};

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
    /// The first poll starts a monitor thread. Once its initial probe completes
    /// it asks the next handshake to recheck trust. Dropping the stream stops
    /// its monitor.
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

struct NativeChangesWorker {
    events: flume::r#async::RecvStream<'static, ()>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl NativeChangesWorker {
    fn new(interval: Duration, extra_only: bool) -> Self {
        // One queued event is enough to tell the next handshake to read trust.
        let (changes, events) = flume::bounded(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = thread::Builder::new()
            .name("rama-native-trust-probe".into())
            .spawn(move || monitor_changes(interval, extra_only, &changes, &worker_stop))
            .inspect_err(|error| warn!(%error, "could not start native trust store monitor"))
            .ok();
        Self {
            events: events.into_stream(),
            stop,
            thread,
        }
    }
}

impl Drop for NativeChangesWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }
}

fn monitor_changes(
    interval: Duration,
    extra_only: bool,
    events: &flume::Sender<()>,
    stop: &AtomicBool,
) {
    let file_interval = interval.max(Duration::from_millis(10));
    let mut changes = if extra_only {
        NativeCertsChanges::extra_only(file_interval)
    } else {
        NativeCertsChanges::new(file_interval)
    };
    // macOS and Windows can report store notifications between file probes.
    let probe_interval = if !extra_only && cfg!(any(target_os = "macos", windows)) {
        file_interval.min(Duration::from_millis(250))
    } else {
        file_interval
    };

    // Request a fresh read after registration because the initial handshake
    // can read the store while the worker is establishing its baseline.
    let mut first_probe = true;
    while !stop.load(Ordering::Acquire) {
        let changed = changes.changed();
        if (first_probe || changed)
            && matches!(
                events.try_send(()),
                Err(flume::TrySendError::Disconnected(()))
            )
        {
            break;
        }
        first_probe = false;
        thread::park_timeout(probe_interval);
    }
}
