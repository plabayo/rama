use super::*;
use std::{ffi::CString, thread, time::Duration};

impl StoreNotifications {
    pub(crate) fn invalidate_token_for_test(&mut self) {
        // Drop the live registration and make the next notify_check return
        // NOTIFY_STATUS_INVALID_TOKEN, as it would after losing coverage.
        self.token = Some(Token(-1));
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
    unsafe extern "C" {
        fn notify_post(name: *const c_char) -> u32;
    }
    // Exercise notifyd without posting to the system trust channel.
    let name = CString::new(format!("org.ramaproxy.test.trust.{}", std::process::id())).unwrap();
    let first = Token::register(&name).unwrap();
    let second = Token::register(&name).unwrap();
    // SAFETY: name is a live NUL-terminated string.
    assert_eq!(unsafe { notify_post(name.as_ptr()) }, 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !first.check().unwrap() {
        assert!(
            std::time::Instant::now() < deadline,
            "notifyd did not deliver the post"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!first.check().unwrap());
    assert!(second.check().unwrap());
    assert!(!second.check().unwrap());
}
