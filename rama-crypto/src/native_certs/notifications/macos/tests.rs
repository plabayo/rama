use super::*;

#[test]
fn observers_consume_notifications_independently_and_detect_lost_coverage() {
    let available = Arc::new(AtomicBool::new(true));
    let seen = CHANGE.load(Ordering::Relaxed);
    let mut first = StoreNotifications {
        available: available.clone(),
        seen,
    };
    let mut second = StoreNotifications {
        available: available.clone(),
        seen,
    };
    keychain_changed(12, ptr::null_mut(), ptr::null_mut());
    assert_eq!(first.poll(), Some(true));
    assert_eq!(first.poll(), Some(false));
    assert_eq!(second.poll(), Some(true));
    available.store(false, Ordering::Relaxed);
    assert_eq!(second.poll(), None);
}
