use std::{
    env, fs,
    process::Command,
    sync::{Arc, mpsc},
    thread,
    time::Instant,
};
#[cfg(target_os = "macos")]
use std::{
    ffi::{CStr, CString, c_char},
    os::fd::AsRawFd as _,
    process,
};

use super::*;
#[cfg(target_os = "macos")]
use crate::native_certs::notifications::{StoreNotifications, WaitError, WaitToken};
use crate::native_certs::{NativeCertsChanges, tests::TestDir};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn notify_post(name: *const c_char) -> u32;
}

/// One operating system wait without store notifications.
fn os_wait(wake: &NativeCertsWake, timeout: Duration) -> bool {
    #[cfg(any(target_os = "macos", windows))]
    return wake.os.wait(None, timeout).unwrap();
    #[cfg(not(any(target_os = "macos", windows)))]
    return wake.os.wait(timeout).unwrap();
}

#[test]
fn wake_ends_a_long_wait_promptly() {
    let wake = Arc::new(NativeCertsWake::new().unwrap());
    let (done, finished) = mpsc::channel();
    let (ready, waiting) = mpsc::channel();
    let waiter = thread::spawn({
        let wake = wake.clone();
        move || {
            let mut changes = NativeCertsChanges::extra_only(Duration::from_hours(1));
            changes.changed();
            ready.send(()).unwrap();
            changes.wait_changed(&wake);
            done.send(()).unwrap();
        }
    });
    waiting.recv().unwrap();
    wake.wake();
    finished.recv_timeout(Duration::from_secs(10)).unwrap();
    waiter.join().unwrap();
}

#[test]
fn pending_wakes_coalesce_into_one_early_return() {
    let wake = NativeCertsWake::new().unwrap();
    for _ in 0..200 {
        wake.wake();
    }
    assert!(os_wait(&wake, Duration::from_hours(1)));
    assert!(!os_wait(&wake, Duration::from_millis(10)));
}

#[test]
fn a_wake_ends_the_backoff_of_a_wait_that_cannot_block() {
    let wake = Arc::new(NativeCertsWake::new().unwrap());
    let (entered, entering) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let waiter = thread::spawn({
        let wake = wake.clone();
        move || {
            let mut changes = NativeCertsChanges::extra_only(Duration::from_hours(1));
            changes.changed();
            changes.wait_then_probe(&wake, Duration::from_hours(1), |_, _| {
                entered.send(()).unwrap();
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            });
            done.send(()).unwrap();
        }
    });
    entering.recv().unwrap();
    wake.wake();
    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("a wake must end the backoff");
    waiter.join().unwrap();
}

#[test]
fn a_backoff_wake_is_not_consumed_again_after_wait_recovery() {
    let wake = NativeCertsWake::new().unwrap();
    let mut changes = NativeCertsChanges::extra_only(Duration::from_hours(1));
    changes.changed();
    changes.wait_then_probe(&wake, Duration::from_hours(1), |_, _| {
        wake.wake();
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    });
    let mut waits = 0;
    changes.wait_then_probe(&wake, Duration::from_hours(1), |_, timeout| {
        assert!(!timeout.is_zero());
        waits += 1;
        Ok(waits == 1)
    });
    assert_eq!(waits, 2);
}

#[test]
fn a_backoff_without_a_wake_lasts_until_the_next_probe() {
    let wake = NativeCertsWake::new().unwrap();
    let mut changes = NativeCertsChanges::extra_only(Duration::from_hours(1));
    changes.changed();
    let started = Instant::now();
    changes.wait_then_probe(&wake, Duration::from_millis(100), |_, _| {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    });
    assert!(started.elapsed() >= Duration::from_millis(100));
}

#[test]
fn windows_wait_millis_round_up_and_stay_below_infinite() {
    assert_eq!(windows_wait_millis(Duration::ZERO), 0);
    assert_eq!(windows_wait_millis(Duration::from_nanos(1)), 1);
    assert_eq!(windows_wait_millis(Duration::from_millis(1500)), 1500);
    let infinite = u64::from(u32::MAX);
    assert_eq!(
        windows_wait_millis(Duration::from_millis(infinite - 1)),
        u32::MAX - 1
    );
    assert_eq!(
        windows_wait_millis(Duration::from_millis(infinite)),
        u32::MAX - 1
    );
    assert_eq!(windows_wait_millis(Duration::MAX), u32::MAX - 1);
}

#[test]
fn an_idle_monitor_waits_for_its_source() {
    let wake = NativeCertsWake::new().unwrap();
    let mut changes = NativeCertsChanges::extra_only(Duration::MAX);
    changes.changed();
    let mut waited = false;
    changes.wait_changed_with(&wake, |_, timeout| {
        assert!(!timeout.is_zero());
        waited = true;
        Ok(false)
    });
    assert!(waited);
}

#[test]
fn idle_monitor_detects_an_extra_root_file_change_through_the_os_wait() {
    const CHILD: &str = "RAMA_TEST_NATIVE_IDLE_CHILD";
    let interval = Duration::from_millis(100);
    if env::var_os(CHILD).is_some() {
        let bundle = env::var_os("SSL_CERT_EXTRA_FILE").unwrap();
        let wake = NativeCertsWake::new().unwrap();
        let started = Instant::now();
        let mut changes = NativeCertsChanges::extra_only(interval);
        assert!(!changes.changed());
        fs::write(bundle, b"changed source of another length").unwrap();
        assert!(changes.wait_changed(&wake));
        assert!(started.elapsed() >= interval);
        assert!(!changes.wait_changed(&wake));
        return;
    }
    let dir = TestDir::new("idle-wait-extra-source");
    let bundle = dir.0.join("roots.pem");
    fs::write(&bundle, b"initial source").unwrap();
    let status = Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg("native_certs::changes::wake::tests::idle_monitor_detects_an_extra_root_file_change_through_the_os_wait")
        .env(CHILD, "1")
        .env("SSL_CERT_EXTRA_FILE", bundle)
        .env_remove("SSL_CERT_EXTRA_DIR")
        .status().unwrap();
    assert!(status.success());
}

#[cfg(target_os = "macos")]
#[test]
fn a_stale_wake_does_not_hide_a_ready_store_notification() {
    let name = CString::new(format!("test.native-trust.stale-wake.{}", process::id())).unwrap();
    let mut changes = NativeCertsChanges::new(Duration::from_hours(1));
    changes.probed_at = Some(Instant::now());
    changes.notifications = Some(StoreNotifications::watch(&name, WaitToken::register));
    assert_eq!(changes.notifications.as_mut().unwrap().poll(), Some(false));
    let wake = NativeCertsWake::new().unwrap();
    wake.wake();
    wake.backoff(Duration::ZERO);
    // SAFETY: `name` is a NUL-terminated `CString` alive until the end of the test.
    assert_eq!(unsafe { notify_post(name.as_ptr()) }, 0);
    // Both descriptors are ready before the wait starts.
    let mut store = libc::pollfd {
        fd: changes
            .notifications
            .as_ref()
            .unwrap()
            .wait_fd()
            .unwrap()
            .as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `store` is one initialised record for `nfds = 1`; its descriptor was borrowed
    // from `changes`, which is not mutated or dropped before this call, so it is open.
    assert_eq!(unsafe { libc::poll(&raw mut store, 1, 10_000) }, 1);
    let (done, finished) = mpsc::channel();
    let waiter = thread::spawn(move || {
        done.send(changes.wait_changed(&wake)).unwrap();
    });
    assert!(finished.recv_timeout(Duration::from_secs(10)).unwrap());
    waiter.join().unwrap();
}

#[cfg(target_os = "macos")]
fn refuse_wait(_: &CStr) -> Result<WaitToken, WaitError> {
    Err(WaitError::Register(1))
}

#[cfg(target_os = "macos")]
#[test]
fn a_degraded_notification_watch_is_polled_within_a_bounded_delay() {
    let name = CString::new(format!("org.ramaproxy.test.degraded.{}", process::id())).unwrap();
    let mut changes = NativeCertsChanges::new(Duration::from_hours(1));
    changes.probed_at = Some(Instant::now());
    changes.notifications = Some(StoreNotifications::watch(&name, refuse_wait));
    let wake = NativeCertsWake::new().unwrap();
    // SAFETY: `name` is a NUL-terminated `CString` alive until the end of the test.
    assert_eq!(unsafe { notify_post(name.as_ptr()) }, 0);

    let (done, finished) = mpsc::channel();
    let waiter = thread::spawn(move || {
        while !changes.wait_changed(&wake) {}
        done.send(()).unwrap();
    });
    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("polling must observe the notification without a wait descriptor");
    waiter.join().unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn wake_sockets_are_close_on_exec() {
    let wake = NativeCertsWake::new().unwrap();
    for fd in [wake.os.reader.as_raw_fd(), wake.os.writer.as_raw_fd()] {
        // SAFETY: `fd` belongs to a socket owned by `wake`, which lives unchanged until the
        // end of the test, so it is open; `F_GETFD` only reads flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(
            flags >= 0 && flags & libc::FD_CLOEXEC != 0,
            "fd {fd} flags {flags}"
        );
    }
}
