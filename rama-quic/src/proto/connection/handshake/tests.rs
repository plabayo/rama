use crate::proto::{Duration, VarInt, connection::handshake::negotiate_max_idle_timeout};

#[test]
fn negotiate_max_idle_timeout_commutative() {
    let test_params = [
        (None, None, None),
        (None, Some(VarInt(0)), None),
        (None, Some(VarInt(2)), Some(Duration::from_millis(2))),
        (Some(VarInt(0)), Some(VarInt(0)), None),
        (
            Some(VarInt(2)),
            Some(VarInt(0)),
            Some(Duration::from_millis(2)),
        ),
        (
            Some(VarInt(1)),
            Some(VarInt(4)),
            Some(Duration::from_millis(1)),
        ),
    ];

    for (left, right, result) in test_params {
        assert_eq!(negotiate_max_idle_timeout(left, right), result);
        assert_eq!(negotiate_max_idle_timeout(right, left), result);
    }
}
