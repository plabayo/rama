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
async fn unknown_selector_returns_error_envelope_without_fallback() {
    let router = XpcMessageRouter::new();
    let call = make_call("unknownSelector", vec![]);
    // An error-envelope reply, not an Err (which would tear down the connection).
    let reply = router.serve(call).await.expect("serve").expect("reply");
    let err = extract_result::<()>(reply).unwrap_err();
    match err {
        XpcError::Remote { code, message } => {
            assert_eq!(code, ERROR_CODE_UNKNOWN_SELECTOR);
            assert!(message.contains("unknownSelector"), "message: {message}");
        }
        other => panic!("expected Remote error, got {other:?}"),
    }
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
async fn without_fallback_returns_unknown_selector_envelope() {
    let router = XpcMessageRouter::new().without_fallback();
    let call = make_call("sel", vec![]);
    let (code, _msg) = error_of(router.serve(call).await);
    assert_eq!(code, ERROR_CODE_UNKNOWN_SELECTOR);
}

// ── invalid message ──────────────────────────────────────────────────────
//
// A malformed call must NOT be an `Err` (which tears down the peer connection)
// — it resolves to an INVALID_MESSAGE error envelope.

#[tokio::test]
async fn non_dictionary_input_returns_invalid_message_envelope() {
    let router = XpcMessageRouter::new();
    let (code, _msg) = error_of(router.serve(XpcMessage::Null).await);
    assert_eq!(code, ERROR_CODE_INVALID_MESSAGE);
}

#[tokio::test]
async fn missing_selector_key_returns_invalid_message_envelope() {
    let mut map = std::collections::BTreeMap::new();
    map.insert("foo".to_owned(), XpcMessage::Null);
    let (code, _msg) = error_of(router_serve(XpcMessage::Dictionary(map)).await);
    assert_eq!(code, ERROR_CODE_INVALID_MESSAGE);
}

#[tokio::test]
async fn non_string_selector_returns_invalid_message_envelope() {
    let mut map = std::collections::BTreeMap::new();
    map.insert("$selector".to_owned(), XpcMessage::Int64(7));
    let (code, _msg) = error_of(router_serve(XpcMessage::Dictionary(map)).await);
    assert_eq!(code, ERROR_CODE_INVALID_MESSAGE);
}

// ── error envelope round-trip ────────────────────────────────────────────

#[tokio::test]
async fn error_envelope_round_trips_via_extract_result() {
    let env = error_envelope(ERROR_CODE_HANDLER_FAILED, "boom");
    let err = extract_result::<Pong>(env).unwrap_err();
    match err {
        XpcError::Remote { code, message } => {
            assert_eq!(code, ERROR_CODE_HANDLER_FAILED);
            assert_eq!(&*message, "boom");
        }
        other => panic!("expected Remote, got {other:?}"),
    }
}

async fn router_serve(msg: XpcMessage) -> Result<Option<XpcMessage>, BoxError> {
    XpcMessageRouter::new().serve(msg).await
}

// Decode a router reply that is expected to be an error envelope, returning (code, message).
fn error_of(reply: Result<Option<XpcMessage>, BoxError>) -> (i64, String) {
    let reply = reply
        .expect("serve should not Err")
        .expect("expected a reply");
    match extract_result::<()>(reply).unwrap_err() {
        XpcError::Remote { code, message } => (code, message.to_string()),
        other => panic!("expected Remote error, got {other:?}"),
    }
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
