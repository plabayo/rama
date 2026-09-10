use crate::proto::{Duration, connection::recovery::persistent_congestion_period};

#[test]
fn persistent_congestion_period_saturates() {
    assert_eq!(
        persistent_congestion_period(Duration::from_millis(500), 3),
        Duration::from_millis(1500)
    );
    assert_eq!(
        persistent_congestion_period(Duration::MAX, 0),
        Duration::ZERO
    );
    assert_eq!(
        persistent_congestion_period(Duration::MAX, 1),
        Duration::MAX
    );
    let pto = Duration::from_secs(u64::MAX / u64::from(u32::MAX) + 1);
    assert!(pto.checked_mul(u32::MAX).is_none());
    assert_eq!(persistent_congestion_period(pto, u32::MAX), Duration::MAX);
}
