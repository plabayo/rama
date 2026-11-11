//! Tests for [`TransparentProxyFlowMeta`] population by the engine —
//! flow-id generation, opened-at, the intercept_decision recorded after
//! the handler returns, and the meta extension visible inside services.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use parking_lot::Mutex;
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::graceful::{Cause, WeakScope, scope_context};
use rama_core::io::BridgeIo;
use rama_core::service::service_fn;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn tcp_flow_exposes_meta_extension() {
    let seen = Arc::new(Mutex::new(None::<Arc<TransparentProxyFlowMeta>>));
    let seen_clone = seen.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let seen_clone = seen_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let seen_clone = seen_clone.clone();
                        let notify_tx = notify_tx.clone();
                        async move {
                            let BridgeIo(stream, _egress) = bridge;
                            *seen_clone.lock() =
                                stream.extensions().get_arc::<TransparentProxyFlowMeta>();
                            _ = notify_tx.send(());
                            Ok(())
                        }
                    },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp).with_source_app_pid(777),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(
        seen.lock().clone().expect("tcp flow meta").source_app_pid,
        Some(777)
    );
}

#[test]
fn udp_flow_exposes_meta_extension() {
    let seen = Arc::new(Mutex::new(None::<Arc<TransparentProxyFlowMeta>>));
    let seen_clone = seen.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let seen_clone = seen_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |flow: crate::UdpFlow| {
                    let seen_clone = seen_clone.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        *seen_clone.lock() =
                            flow.extensions().get_arc::<TransparentProxyFlowMeta>();
                        _ = notify_tx.send(());
                        Ok(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp).with_source_app_pid(888),
        |_| {},
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate();
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(
        seen.lock().clone().expect("udp flow meta").source_app_pid,
        Some(888)
    );
}

#[test]
fn flow_meta_new_generates_unique_flow_ids_and_sets_opened_at() {
    let a = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    let b = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    assert_ne!(a.flow_id, 0);
    assert_ne!(b.flow_id, 0);
    assert_ne!(a.flow_id, b.flow_id);
    assert!(b.flow_id > a.flow_id);
    assert!(a.opened_at <= Instant::now());
    assert!(a.intercept_decision.is_none());
    assert!(b.intercept_decision.is_none());
}

#[test]
fn flow_meta_records_intercept_decision_after_handler() {
    let seen = Arc::new(Mutex::new(None::<Arc<TransparentProxyFlowMeta>>));
    let seen_clone = seen.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let seen_clone = seen_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let seen_clone = seen_clone.clone();
                        let notify_tx = notify_tx.clone();
                        async move {
                            let BridgeIo(stream, _egress) = bridge;
                            *seen_clone.lock() =
                                stream.extensions().get_arc::<TransparentProxyFlowMeta>();
                            _ = notify_tx.send(());
                            Ok(())
                        }
                    },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let seen_meta = seen.lock().clone().expect("tcp flow meta");
    assert_eq!(
        seen_meta.intercept_decision,
        Some(crate::tproxy::types::TransparentProxyFlowAction::Intercept),
        "intercept_decision should be populated by the engine"
    );
    assert_ne!(seen_meta.flow_id, 0);
}

#[test]
fn bound_interface_index_requires_an_explicit_bind() {
    let meta = |is_bound, index| {
        let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
        meta.is_bound = is_bound;
        meta.local_interface_index = index;
        meta
    };

    assert_eq!(
        meta(Some(true), Some(7)).bound_interface_index(),
        std::num::NonZeroU32::new(7)
    );
    // unbound: the index is only the kernel's current pick
    assert_eq!(meta(Some(false), Some(7)).bound_interface_index(), None);
    assert_eq!(meta(None, Some(7)).bound_interface_index(), None);
    // bound but no usable index
    assert_eq!(meta(Some(true), None).bound_interface_index(), None);
    assert_eq!(meta(Some(true), Some(0)).bound_interface_index(), None);
}

/// The scope found through the flow's extensions is the flow scope itself.
fn runs_in_flow_scope(extensions: &Extensions, flow: Option<&WeakScope>) -> bool {
    let Some(attached) = scope_context(extensions) else {
        return false;
    };
    attached.cancel(Cause::Owner);
    flow.is_some_and(WeakScope::is_cancelled)
}

#[test]
fn tcp_flow_runs_in_its_flow_scope() {
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<bool>();
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let notify_tx = notify_tx.clone();
                        async move {
                            let BridgeIo(stream, _egress) = bridge;
                            _ = notify_tx
                                .send(runs_in_flow_scope(stream.extensions(), stream.scope()));
                            Ok(())
                        }
                    },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    let runs_in_flow_scope = notify_rx.recv_timeout(Duration::from_secs(5));
    engine.stop(0);
    assert_eq!(Ok(true), runs_in_flow_scope);
}

#[test]
fn udp_flow_runs_in_its_flow_scope() {
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<bool>();
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |flow: crate::UdpFlow| {
                    let notify_tx = notify_tx.clone();
                    async move {
                        _ = notify_tx.send(runs_in_flow_scope(flow.extensions(), flow.scope()));
                        Ok(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate();
    let runs_in_flow_scope = notify_rx.recv_timeout(Duration::from_secs(5));
    engine.stop(0);
    assert_eq!(Ok(true), runs_in_flow_scope);
}
