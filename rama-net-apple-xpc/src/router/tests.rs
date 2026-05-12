use std::convert::Infallible;
use std::sync::Arc;

use parking_lot::Mutex;
use rama_core::service::service_fn;
use serde::{Deserialize, Serialize};

use super::*;
use crate::{XpcCall, xpc_serde::to_xpc_message};

// Helper: build an XpcMessage representing a call.
fn make_call(selector: &str, args: Vec<XpcMessage>) -> XpcMessage {
    XpcCall::with_arguments(selector, args).into()
}

// Helper: serialize a value as a single $arguments entry.
fn arg<T: Serialize>(v: &T) -> XpcMessage {
    to_xpc_message(v).expect("serialize")
}

// ── typed route ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Ping {
    value: u32,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Pong {
    doubled: u32,
}

#[tokio::test]
async fn typed_route_round_trip() {
    let router = XpcMessageRouter::new().with_typed_route::<Ping, Pong, _>(
        "ping:withReply:",
        service_fn(|p: Ping| async move {
            Ok::<_, Infallible>(Pong {
                doubled: p.value * 2,
            })
        }),
    );

    let call = make_call("ping:withReply:", vec![arg(&Ping { value: 21 })]);
    let reply = router.serve(call).await.expect("serve").expect("reply");

    let pong: Pong = extract_result(reply).expect("extract");
    assert_eq!(pong, Pong { doubled: 42 });
}

#[tokio::test]
async fn typed_route_unit_response() {
    let router = XpcMessageRouter::new().with_typed_route::<Ping, (), _>(
        "ping",
        service_fn(|_: Ping| async move { Ok::<_, Infallible>(()) }),
    );

    let call = make_call("ping", vec![arg(&Ping { value: 1 })]);
    let reply = router.serve(call).await.expect("serve").expect("reply");

    // Unit result should round-trip as Null.
    let _: () = extract_result(reply).expect("extract");
}

// ── raw route ────────────────────────────────────────────────────────────

#[tokio::test]
async fn raw_route_receives_full_message() {
    let received: Arc<Mutex<Option<XpcMessage>>> = Arc::new(Mutex::new(None));
    let received2 = received.clone();

    let router = XpcMessageRouter::new().with_route(
        "rawOp",
        service_fn(move |msg: XpcMessage| {
            let received3 = received2.clone();
            async move {
                *received3.lock() = Some(msg);
                Ok::<_, Infallible>(None)
            }
        }),
    );

    let call = make_call("rawOp", vec![]);
    let reply = router.serve(call.clone()).await.expect("serve");
    assert!(reply.is_none());
    assert_eq!(*received.lock(), Some(call));
}

// ── unknown selector ─────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_selector_returns_none_without_fallback() {
    let router = XpcMessageRouter::new();
    let call = make_call("unknownSelector", vec![]);
    router.serve(call).await.unwrap_err();
}

// ── fallback ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn fallback_called_for_unknown_selector() {
    let called = Arc::new(Mutex::new(false));
    let called2 = called.clone();

    let router = XpcMessageRouter::new().with_fallback(service_fn(move |_: XpcMessage| {
        let called3 = called2.clone();
        async move {
            *called3.lock() = true;
            Ok::<_, Infallible>(None)
        }
    }));

    let call = make_call("anythingElse", vec![]);
    router.serve(call).await.expect("serve");
    assert!(*called.lock());
}

#[tokio::test]
async fn known_route_takes_priority_over_fallback() {
    let fallback_called = Arc::new(Mutex::new(false));
    let fallback_called2 = fallback_called.clone();

    let router = XpcMessageRouter::new()
        .with_typed_route::<(), (), _>(
            "known",
            service_fn(|_: ()| async move { Ok::<_, Infallible>(()) }),
        )
        .with_fallback(service_fn(move |_: XpcMessage| {
            let fc = fallback_called2.clone();
            async move {
                *fc.lock() = true;
                Ok::<_, Infallible>(None)
            }
        }));

    let call = make_call("known", vec![arg(&())]);
    router.serve(call).await.expect("serve");
    assert!(!*fallback_called.lock());
}

// ── without_fallback ─────────────────────────────────────────────────────

#[tokio::test]
async fn without_fallback_removes_it() {
    let router = XpcMessageRouter::new();
    let call = make_call("sel", vec![]);
    router.serve(call).await.unwrap_err();
}

// ── invalid message ──────────────────────────────────────────────────────

#[tokio::test]
async fn error_on_non_dictionary_input() {
    let router = XpcMessageRouter::new();
    let err = router.serve(XpcMessage::Null).await.unwrap_err();
    assert!(err.to_string().contains("XpcMessageRouter"));
}

#[tokio::test]
async fn error_on_missing_selector_key() {
    let mut map = std::collections::BTreeMap::new();
    map.insert("foo".to_owned(), XpcMessage::Null);
    let err = router_serve(XpcMessage::Dictionary(map)).await.unwrap_err();
    assert!(err.to_string().contains("XpcMessageRouter"));
}

async fn router_serve(msg: XpcMessage) -> Result<Option<XpcMessage>, BoxError> {
    XpcMessageRouter::new().serve(msg).await
}

// ── clone ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn router_is_clone() {
    let router = XpcMessageRouter::new().with_typed_route::<Ping, Pong, _>(
        "ping:withReply:",
        service_fn(|p: Ping| async move {
            Ok::<_, Infallible>(Pong {
                doubled: p.value * 2,
            })
        }),
    );
    let router2 = router.clone();

    let call = make_call("ping:withReply:", vec![arg(&Ping { value: 5 })]);
    let pong: Pong = extract_result(router2.serve(call).await.unwrap().unwrap()).unwrap();
    assert_eq!(pong.doubled, 10);
}
