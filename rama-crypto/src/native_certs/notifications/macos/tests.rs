use std::{
    ffi::CString,
    os::fd::AsRawFd as _,
    thread,
    time::{Duration, Instant},
};

use super::*;
use crate::native_certs::NativeCertsWake;

unsafe extern "C" {
    fn notify_post(name: *const c_char) -> u32;
}

impl StoreNotifications {
    pub(crate) fn invalidate_token_for_test(&mut self) {
        // Drop the live registration and make the next notify_check return
        // NOTIFY_STATUS_INVALID_TOKEN, as it would after losing coverage.
        self.token = Some(Token {
            token: -1,
            _name: c"".into(),
        });
    }
}

#[test]
fn registers_for_certificate_trust_without_a_run_loop() {
    let mut observer = StoreNotifications::new();
    for _ in 0..6 {
        thread::sleep(Duration::from_millis(50));
        assert_eq!(observer.poll(), Some(false));
    }
}

#[test]
fn observers_consume_real_notifications_independently() {
    // Exercise notifyd without posting to the system trust channel.
    let name = CString::new(format!("org.ramaproxy.test.trust.{}", std::process::id())).unwrap();
    let first = Token::register(&name).unwrap();
    let second = Token::register(&name).unwrap();
    // SAFETY: `name` is a NUL-terminated `CString` alive until the end of the test.
    assert_eq!(unsafe { notify_post(name.as_ptr()) }, 0);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !first.check().unwrap() {
        assert!(
            Instant::now() < deadline,
            "notifyd did not deliver the post"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!first.check().unwrap());
    assert!(second.check().unwrap());
    assert!(!second.check().unwrap());
}

#[test]
fn a_notification_ends_a_blocking_wait() {
    let name = CString::new(format!("org.ramaproxy.test.wait.{}", std::process::id())).unwrap();
    let mut observer = StoreNotifications::watch(&name, WaitToken::register);
    assert!(observer.wait_fd().is_some());
    let wake = NativeCertsWake::new().unwrap();
    // SAFETY: `name` is a NUL-terminated `CString` alive until the end of the test.
    assert_eq!(unsafe { notify_post(name.as_ptr()) }, 0);
    let started = Instant::now();
    let woken = wake
        .os
        .wait(Some(&mut observer), Duration::from_secs(30))
        .unwrap();
    assert!(!woken);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(observer.poll(), Some(true));
    // A drained descriptor does not end a wait.
    let started = Instant::now();
    wake.os
        .wait(Some(&mut observer), Duration::from_millis(200))
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(observer.wait_fd().is_some());
}

#[test]
fn the_wait_descriptor_is_close_on_exec() {
    let name = CString::new(format!("org.ramaproxy.test.cloexec.{}", std::process::id())).unwrap();
    let observer = StoreNotifications::watch(&name, WaitToken::register);
    let fd = observer.wait_fd().unwrap();
    // SAFETY: `fd` borrows `observer`, which is not mutated or dropped before this call,
    // so the descriptor is open; `F_GETFD` only reads flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0, "flags {flags}");
}

fn refuse_wait(_: &CStr) -> Result<WaitToken, WaitError> {
    Err(WaitError::Register(1))
}

#[test]
fn a_failed_wait_registration_is_retried_at_a_bounded_rate() {
    let name = CString::new(format!("org.ramaproxy.test.retry.{}", std::process::id())).unwrap();
    let mut observer = StoreNotifications::watch(&name, refuse_wait);
    assert!(observer.wait_degraded());
    assert_eq!(observer.poll(), Some(false));

    observer.register_wait = WaitToken::register;
    observer.retry_wait();
    assert!(
        observer.wait_degraded(),
        "a retry must wait for its interval"
    );

    observer.wait_attempted_at -= WAIT_RETRY;
    observer.retry_wait();
    assert!(!observer.wait_degraded());
    assert!(observer.wait_fd().is_some());
}
