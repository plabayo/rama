use super::Upgrade;
use crate::common::test_decode;

#[test]
fn websocket_offer_can_contain_other_protocols() {
    for value in ["h2c, websocket", " WebSocket , other/1.0 "] {
        let upgrade: Upgrade = test_decode(&[value]).unwrap();
        assert!(upgrade.contains_websocket());
        assert!(!upgrade.is_websocket());
    }
    for value in ["websocket/13", "not-websocket", "websocket invalid"] {
        let upgrade: Upgrade = test_decode(&[value]).unwrap();
        assert!(!upgrade.contains_websocket());
    }
    assert!(Upgrade::websocket().contains_websocket());
    assert!(Upgrade::websocket().is_websocket());
}
