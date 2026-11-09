//! A listener out of file descriptors pauses accepting instead of spinning on `EMFILE`,
//! and serves the waiting connection once descriptors free up.

#![cfg(target_os = "linux")]
#![expect(
    unsafe_code,
    reason = "test fixture lowers the fd limit and exhausts it through libc"
)]

use std::{
    convert::Infallible,
    os::fd::AsRawFd as _,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{graceful::WeakScope, service::service_fn};
use rama_unix::{UnixStream, server::UnixListener};

fn cpu_time() -> Duration {
    // SAFETY: `rusage` is a plain C struct of integers, for which all-zero bytes are valid.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a live, writable `rusage` this frame owns, as getrusage(2) requires.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) };
    assert_eq!(rc, 0);
    let tv = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec.unsigned_abs())
            + Duration::from_micros(t.tv_usec.unsigned_abs())
    };
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

/// Duplicate `file` until the process hits its descriptor limit.
fn exhaust_fds(file: &std::fs::File) -> Vec<libc::c_int> {
    let mut fds = Vec::with_capacity(256);
    loop {
        // SAFETY: dup(2) on a descriptor kept open by `file`; failure is reported via -1.
        let fd = unsafe { libc::dup(file.as_raw_fd()) };
        if fd < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EMFILE)
            );
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
    // SAFETY: the pointer is to a live, initialized `rlimit`, as setrlimit(2) requires.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) };
    assert_eq!(rc, 0);

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
    let null = std::fs::File::open("/dev/null").unwrap();
    let fds = exhaust_fds(&null);

    let before = cpu_time();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let spent = cpu_time().saturating_sub(before);

    for fd in fds {
        // SAFETY: `fd` came from dup(2) above and is closed exactly once.
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
