use std::{
    env, fs,
    path::PathBuf,
    process::{self, Command},
    sync::mpsc,
    task::Waker,
};

use rama_core::futures::StreamExt as _;
use tokio::{task::spawn_blocking, time::timeout};

use super::*;
use crate::client::native_trust::warn_capture::WarnCapture;

#[tokio::test]
async fn dropping_the_stream_stops_the_monitor_promptly() {
    let (finished, monitor_done) = mpsc::channel();
    let mut worker = NativeChangesWorker::start(Duration::from_hours(1), true, |task| {
        thread::Builder::new().spawn(move || {
            task();
            _ = finished.send(());
        })
    });
    // The first event arrives once the monitor has its baseline and is about to wait.
    assert_eq!(worker.events.next().await, Some(()));
    drop(worker);
    spawn_blocking(move || monitor_done.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .expect("monitor must stop when its stream is dropped");
}

#[test]
fn a_monitor_that_cannot_start_ends_the_stream_with_one_warning() {
    let capture = WarnCapture::default();
    let mut spawns = 0;
    let mut worker = capture.record(|| {
        NativeChangesWorker::start(Duration::from_hours(1), true, |_task| {
            spawns += 1;
            Err(io::Error::from(io::ErrorKind::OutOfMemory))
        })
    });
    let cx = &mut Context::from_waker(Waker::noop());
    for _ in 0..4 {
        assert_eq!(
            Pin::new(&mut worker.events).poll_next(cx),
            Poll::Ready(None)
        );
    }
    assert_eq!(spawns, 1);
    assert_eq!(capture.warnings(), 1);
}

#[test]
fn an_extra_root_file_change_requests_a_reload() {
    const CHILD: &str = "RAMA_TEST_NATIVE_TRUST_WORKER_FILE";
    if let Some(file) = env::var_os(CHILD) {
        let file = PathBuf::from(file);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut changes = NativeTrustStoreChanges::extra_roots(Duration::from_millis(10));
            assert_eq!(changes.next().await, Some(()));
            fs::write(&file, b"a different, longer extra root bundle").unwrap();
            let event = timeout(Duration::from_secs(10), changes.next())
                .await
                .expect("a changed extra root file must request a reload");
            assert_eq!(event, Some(()));
        });
        return;
    }

    let file = env::temp_dir().join(format!(
        "rama-tls-native-trust-worker-{}.pem",
        process::id()
    ));
    fs::write(&file, b"first").unwrap();
    let status = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "client::native_trust::worker::tests::an_extra_root_file_change_requests_a_reload",
        ])
        .env(CHILD, &file)
        .env("SSL_CERT_EXTRA_FILE", &file)
        .status()
        .unwrap();
    _ = fs::remove_file(&file);
    assert!(status.success());
}
