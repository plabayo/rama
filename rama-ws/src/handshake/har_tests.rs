use super::*;
use rama_core::extensions::Extensions;
use rama_http::layer::har::spec::WebSocketMessageType;

fn collector_with(
    direction: WebSocketRelayDirection,
    msg: &WebSocketRelayMessage,
) -> WebSocketMessages {
    let collector = WebSocketMessages::new();
    record_message(Some(&collector), direction, msg);
    collector
}

/// Ingress carries what the client sent, so it maps to Chrome's `send`.
#[test]
fn ingress_is_recorded_as_send_and_egress_as_receive() {
    let sent = collector_with(
        WebSocketRelayDirection::Ingress,
        &WebSocketRelayMessage::Text("from client".into()),
    );
    let received = collector_with(
        WebSocketRelayDirection::Egress,
        &WebSocketRelayMessage::Text("from server".into()),
    );

    assert_eq!(
        sent.take().expect("messages")[0].r#type,
        WebSocketMessageType::Send
    );
    assert_eq!(
        received.take().expect("messages")[0].r#type,
        WebSocketMessageType::Receive
    );
}

#[test]
fn a_text_frame_keeps_its_payload_verbatim() {
    let payload = r#"{"type":"response.output_item.added","item":{"name":"shell"}}"#;
    let collector = collector_with(
        WebSocketRelayDirection::Ingress,
        &WebSocketRelayMessage::Text(payload.into()),
    );

    let messages = collector.take().expect("messages");
    assert_eq!(messages[0].opcode, 1);
    assert_eq!(messages[0].data.as_str(), payload);
}

#[test]
fn a_binary_frame_is_base64_encoded() {
    let collector = collector_with(
        WebSocketRelayDirection::Ingress,
        &WebSocketRelayMessage::Binary(vec![0x00, 0x01, 0x02, 0xaa].into()),
    );

    let messages = collector.take().expect("messages");
    assert_eq!(messages[0].opcode, 2);
    assert_eq!(messages[0].data.as_str(), "AAECqg==");
}

/// Order is what makes a stream readable; a request/response pair must not be reordered.
#[test]
fn messages_are_kept_in_relay_order() {
    let collector = WebSocketMessages::new();
    for (direction, text) in [
        (WebSocketRelayDirection::Ingress, "one"),
        (WebSocketRelayDirection::Egress, "two"),
        (WebSocketRelayDirection::Egress, "three"),
    ] {
        record_message(
            Some(&collector),
            direction,
            &WebSocketRelayMessage::Text(text.into()),
        );
    }

    let messages = collector.take().expect("messages");
    let texts: Vec<&str> = messages.iter().map(|m| m.data.as_str()).collect();
    assert_eq!(texts, vec!["one", "two", "three"]);
}

/// A connection that is not being recorded must cost nothing and produce nothing.
#[test]
fn no_collector_means_no_recording() {
    record_message(
        None,
        WebSocketRelayDirection::Egress,
        &WebSocketRelayMessage::Text("dropped".into()),
    );
    // Reaching here without panicking is the assertion: the None path is a no-op.
    let empty = WebSocketMessages::new();
    assert!(empty.take().is_none(), "an untouched collector yields None");
}

#[test]
fn the_collector_is_reachable_through_extensions() {
    let extensions = Extensions::default();
    extensions.insert(WebSocketMessages::new());

    let collector = extensions
        .get_ref::<WebSocketMessages>()
        .expect("collector in extensions");
    record_message(
        Some(collector),
        WebSocketRelayDirection::Egress,
        &WebSocketRelayMessage::Text("hello".into()),
    );

    assert_eq!(
        extensions
            .get_ref::<WebSocketMessages>()
            .and_then(|c| c.take())
            .map(|m| m.len()),
        Some(1),
        "the clone in extensions shares the same buffer",
    );
}
