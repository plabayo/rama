//! A listener out of file descriptors pauses accepting instead of spinning on `EMFILE`,
//! and serves the waiting connection once descriptors free up.

#![cfg(target_os = "linux")]
#![expect(
    clippy::unwrap_used,
    unsafe_code,
    reason = "test fixture lowers the fd limit and exhausts it through libc"
)]

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{graceful::WeakScope, service::service_fn};
use rama_unix::{UnixStream, server::UnixListener};

fn cpu_time() -> Duration {
    // SAFETY: getrusage only writes into the zeroed struct we own.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut usage), 0);
        usage
    };
    let tv = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec.unsigned_abs())
            + Duration::from_micros(t.tv_usec.unsigned_abs())
    };
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

/// Duplicate stdin until the process hits its descriptor limit.
fn exhaust_fds() -> Vec<libc::c_int> {
    let mut fds = Vec::with_capacity(256);
    loop {
        // SAFETY: dup on a valid descriptor; failures are returned, not UB.
        let fd = unsafe { libc::dup(0) };
        if fd < 0 {
            return fds;
        }
        fds.push(fd);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn exhausted_fds_pause_accept_instead_of_spinning() {
    let limit = libc::rlimit {
        rlim_cur: 256,
        rlim_max: 256,
    };
    // SAFETY: lowers this test binary's own descriptor limit.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

    let dir = std::env::temp_dir().join(format!("rama-unix-emfile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("emfile.sock");
    _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind_path(&path, WeakScope::detached())
        .await
        .unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();
    let serving = tokio::spawn(listener.serve(service_fn(move |_stream: UnixStream| {
        counter.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok::<_, Infallible>(()))
    })));

    let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();
    let fds = exhaust_fds();

    let before = cpu_time();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let spent = cpu_time() - before;

    for fd in fds {
        // SAFETY: closes descriptors this test opened.
        unsafe { libc::close(fd) };
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while served.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the waiting connection is served once descriptors free up");

    serving.abort();
    _ = std::fs::remove_dir_all(&dir);
    assert!(
        spent < Duration::from_millis(150),
        "accept loop used {spent:?} of CPU in 500ms while out of descriptors"
    );
}
