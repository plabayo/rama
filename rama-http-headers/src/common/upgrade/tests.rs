use super::Upgrade;
use crate::common::test_decode;
use rama_http_types::proto::ext::Protocol;

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

/// A list field's lines combine (RFC 9110 §5.3): a second line cannot hide behind the first.
#[test]
fn every_upgrade_line_counts() {
    let upgrade: Upgrade = test_decode(&["websocket", "h2c"]).unwrap();
    assert_eq!(upgrade.as_bytes(), b"websocket, h2c");
    assert!(!upgrade.is_websocket());
    assert!(upgrade.contains_websocket());
    let upgrade: Upgrade = test_decode(&["WebSocket"]).unwrap();
    assert!(upgrade.is_websocket());
}

#[test]
fn upgrade_for_a_protocol() {
    let upgrade = Upgrade::from_protocol(Protocol::CONNECT_UDP);
    assert_eq!(upgrade.as_bytes(), b"connect-udp");
    assert!(upgrade.is_protocol(&Protocol::CONNECT_UDP));
    assert!(!upgrade.is_protocol(&Protocol::WEBSOCKET));
    for value in [" Connect-UDP\t", "connect-udp"] {
        let upgrade: Upgrade = test_decode(&[value]).unwrap();
        assert!(upgrade.is_protocol(&Protocol::CONNECT_UDP), "{value:?}");
    }
    for value in ["connect-udp, websocket", "connect-udp/1"] {
        let upgrade: Upgrade = test_decode(&[value]).unwrap();
        assert!(!upgrade.is_protocol(&Protocol::CONNECT_UDP), "{value:?}");
    }
}
