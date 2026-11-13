use super::common::{TestHandler, build_engine};
use crate::tproxy::{TransparentProxyNetworkStatus, engine::TransparentProxyNetworkPath};

#[test]
fn network_observations_coalesce_and_do_not_queue_per_flow() {
    let engine = build_engine(TestHandler::passthrough());
    let mut changes = engine.network_path.subscribe();
    for index in 1..=1024 {
        engine.notify_network_change(1, index, 3);
    }
    assert!(changes.has_changed().unwrap());
    let latest = *changes.borrow_and_update();
    assert_eq!(latest.revision, 1024);
    assert_eq!(latest.preferred_interface, 1024);
    assert_eq!(latest.status, TransparentProxyNetworkStatus::Satisfied);
    assert!(latest.expensive && latest.constrained);
    assert!(!changes.has_changed().unwrap());
    engine.notify_network_change(2, 0, 0);
    assert_eq!(
        changes.borrow_and_update().status,
        TransparentProxyNetworkStatus::Unsatisfied
    );
    engine.stop(0);
    assert!(changes.changed().now_or_never().unwrap().is_err());
}

#[test]
fn flag_only_events_do_not_request_another_routing_change() {
    let engine = build_engine(TestHandler::passthrough());
    let mut changes = engine.network_path.subscribe();
    engine.notify_network_change(1, 4, 0);
    assert_eq!(changes.borrow_and_update().routing_revision, 1);
    for flags in [0, 1, 3, 0, 2] {
        engine.notify_network_change(1, 4, flags);
        assert_eq!(changes.borrow_and_update().routing_revision, 1);
    }
    // Even coalescing the outage and recovery retains the fact that routing changed.
    engine.notify_network_change(2, 4, 0);
    engine.notify_network_change(1, 4, 0);
    assert_eq!(changes.borrow_and_update().routing_revision, 3);
    engine.notify_network_change(1, 8, 0);
    assert_eq!(changes.borrow_and_update().routing_revision, 4);
    engine.stop(0);
}

#[test]
fn network_ffi_scalars_accept_unknown_values_without_invalid_enums() {
    let path = TransparentProxyNetworkPath::from_ffi(u32::MAX, u32::MAX, u32::MAX);
    assert_eq!(path.status, TransparentProxyNetworkStatus::Unknown);
    assert_eq!(path.preferred_interface, u32::MAX);
    assert!(path.expensive && path.constrained);
}

use rama_core::futures::FutureExt as _;
