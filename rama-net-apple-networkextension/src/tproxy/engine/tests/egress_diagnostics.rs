use super::common::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol, engine::*};
use rama_core::service::service_fn;
use std::sync::Arc;

#[test]
fn ffi_egress_report_logs_metadata_and_fields_after_activation_and_cancel() {
    let handler = TestHandler {
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|_bridge| async { Ok(()) }).boxed(),
        }),
        ..TestHandler::passthrough()
    };
    let engine = build_engine(handler);
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
        .with_remote_endpoint(rama_net::address::HostWithPort::example_domain_with_port(
            443,
        ))
        .with_source_app_pid(42);
    meta.source_app_bundle_identifier = Some("test.original.app".try_into().unwrap());
    meta.source_app_signing_identifier = Some("TEAM.test.original.app".try_into().unwrap());
    let SessionFlowAction::Intercept(mut session) =
        engine.new_tcp_session(meta, |_| TcpDeliverStatus::Accepted, || {}, || {})
    else {
        panic!("intercept");
    };
    let id = session.flow_id();
    assert_ne!(id, 0);
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    session.cancel();
    assert_eq!(session.flow_id(), id);
    let endpoint = "127.0.0.1:8888";
    let error = "POSIXErrorCode: ECONNREFUSED";
    let mut ffi = crate::ffi::tproxy::TcpEgressReport {
        ready: true,
        report_available: true,
        used_proxy: true,
        proxy_configured: true,
        allow_proxy: true,
        proxy_policy: 0,
        connect_duration_ms: 250,
        report_duration_ms: 245,
        proxy_endpoint_utf8: endpoint.as_ptr().cast(),
        proxy_endpoint_utf8_len: endpoint.len(),
        error_utf8: std::ptr::null(),
        error_utf8_len: 0,
    };
    let capture = Capture::default();
    tracing::subscriber::with_default(capture.clone(), || {
        assert!(tcp_egress_reporting_enabled());
        // The exact decoder and session entry used by the exported C function.
        session.report_egress(&unsafe { ffi.to_rust_type() });
        for (allow_proxy, proxy_policy) in [(true, 0), (false, 2), (false, 255)] {
            ffi.allow_proxy = allow_proxy;
            ffi.proxy_policy = proxy_policy;
            ffi.ready = false;
            ffi.report_available = false;
            ffi.proxy_endpoint_utf8 = std::ptr::null();
            ffi.proxy_endpoint_utf8_len = 0;
            ffi.error_utf8 = error.as_ptr().cast();
            ffi.error_utf8_len = error.len();
            session.report_egress(&unsafe { ffi.to_rust_type() });
        }
    });
    let events = capture.0.lock();
    let event = events.first().expect("establishment event");
    assert_eq!(event.get("flow_id"), Some(&id.to_string()));
    assert_eq!(event.get("pid").map(String::as_str), Some("42"));
    assert!(event.get("remote").unwrap().contains(":443"));
    for (key, expected) in [
        ("ready", "true"),
        ("allow_proxy", "true"),
        ("proxy_policy", "\"allowed\""),
        ("report_available", "true"),
        ("used_proxy", "true"),
        ("proxy_configured", "true"),
        ("connect_duration_ms", "250"),
        ("report_duration_ms", "245"),
        ("proxy_endpoint", "\"127.0.0.1:8888\""),
    ] {
        assert_eq!(event.get(key).map(String::as_str), Some(expected), "{key}");
    }
    for (event, policy) in events
        .iter()
        .skip(1)
        .zip(["allowed", "prefer_direct_only", "unknown"])
    {
        assert_eq!(event.get("proxy_policy"), Some(&format!("{policy:?}")));
        assert_eq!(
            event.get("allow_proxy").map(String::as_str),
            Some(if policy == "allowed" { "true" } else { "false" })
        );
        assert_eq!(event.get("ready").map(String::as_str), Some("false"));
        assert_eq!(
            event.get("error").map(String::as_str),
            Some("\"POSIXErrorCode: ECONNREFUSED\"")
        );
        assert!(!event.contains_key("proxy_endpoint"));
        assert!(!event.contains_key("report_duration_ms"));
        assert!(!event.contains_key("used_proxy"));
        assert!(!event.contains_key("proxy_configured"));
        assert_eq!(
            event.get("bundle_id").map(String::as_str),
            Some("\"test.original.app\"")
        );
        assert_eq!(
            event.get("signing_id").map(String::as_str),
            Some("\"TEAM.test.original.app\"")
        );
    }
    engine.stop(0);
}

#[test]
fn promoted_close_names_handoff_counters_and_preserves_ordinary_close_fields() {
    let meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    for promoted in [false, true] {
        let capture = Capture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            emit_tcp_bridge_close_event(
                BridgeDirection::Egress,
                BridgeCloseReason::PeerEofLeft,
                &meta,
                promoted,
                11,
                23,
            );
        });
        let events = capture.0.lock();
        let event = events.first().expect("bridge event");
        if promoted {
            assert_eq!(event.get("mode").map(String::as_str), Some("\"promoted\""));
            assert_eq!(
                event
                    .get("bytes_received_until_handoff")
                    .map(String::as_str),
                Some("11")
            );
            assert_eq!(
                event.get("bytes_sent_until_handoff").map(String::as_str),
                Some("23")
            );
            assert!(!event.contains_key("bytes_received"));
            assert!(!event.contains_key("bytes_sent"));
            assert!(event.get("message").unwrap().contains("handed off"));
        } else {
            assert_eq!(event.get("bytes_received").map(String::as_str), Some("11"));
            assert_eq!(event.get("bytes_sent").map(String::as_str), Some("23"));
            assert!(!event.contains_key("bytes_received_until_handoff"));
            assert!(event.get("message").unwrap().contains("flow closed"));
        }
    }
}

#[test]
fn disabled_egress_reporting_skips_collection() {
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        assert!(!tcp_egress_reporting_enabled());
    });
}
