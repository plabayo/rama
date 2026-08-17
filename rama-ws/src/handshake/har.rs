//! Record relayed WebSocket messages into the HAR entry of the upgraded connection.
//!
//! A WebSocket entry in a HAR is a `101` with no body, and every frame arrives after
//! that response has been returned. [`WebSocketHarRecorder`] sits in the relay, pushes
//! each message into the [`WebSocketMessages`] collector carried in the connection's
//! extensions, and passes the message on untouched. The HAR layer reads the same
//! collector when it writes the entry.
//!
//! The gap is not closed yet: `HARExportService` writes the entry the moment the inner
//! service returns the `101`, which is before the upgrade task — and therefore this
//! recorder — has seen anything. Deferring the entry for an upgraded connection until
//! the socket closes is what remains.
//!
//! Enable the `ws-har` feature to use it.

use rama_core::{Service, error::BoxError, extensions::ExtensionsRef, telemetry::tracing};

use rama_http::layer::har::extensions::WebSocketMessages;
use rama_http::layer::har::spec::WebSocketMessageType;
use std::time::{SystemTime, UNIX_EPOCH};

use super::mitm::{
    WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayMessage, WebSocketRelayOutput,
};

#[derive(Debug, Clone, Default)]
/// Relay middleware that copies every message into the connection's
/// [`WebSocketMessages`] collector, then forwards it unchanged.
///
/// Messages are only recorded when a collector is present in the extensions, so this is
/// a no-op on connections that are not being recorded.
pub struct WebSocketHarRecorder<S> {
    inner: S,
    /// Used when set; otherwise the collector is looked up in the message extensions.
    ///
    /// A caller that already holds the collector — because it also writes the entry —
    /// can hand it over directly, which avoids needing a mutable extensions store on
    /// the bridge IO.
    collector: Option<WebSocketMessages>,
}

impl<S> WebSocketHarRecorder<S> {
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            collector: None,
        }
    }

    #[must_use]
    pub fn with_collector(inner: S, collector: WebSocketMessages) -> Self {
        Self {
            inner,
            collector: Some(collector),
        }
    }
}

/// Seconds since the unix epoch, which is the form Chrome DevTools uses for
/// `_webSocketMessages[].time` (unlike the ISO-8601 strings elsewhere in HAR).
fn unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

/// Ingress is what arrives from the client, i.e. client to server, which Chrome labels
/// `send`; egress is what goes back out to the client, which it labels `receive`.
///
/// Measured against a real Codex session: the 52 KB `response.create` the client sends
/// arrives as `Ingress`, and the server's reply leaves as `Egress`. Getting this the
/// wrong way round silently mislabels every frame in the recording.
const fn message_type(direction: WebSocketRelayDirection) -> WebSocketMessageType {
    match direction {
        WebSocketRelayDirection::Ingress => WebSocketMessageType::Send,
        WebSocketRelayDirection::Egress => WebSocketMessageType::Receive,
    }
}

/// Records one relayed message, if this connection is being recorded.
pub fn record_message(
    collector: Option<&WebSocketMessages>,
    direction: WebSocketRelayDirection,
    message: &WebSocketRelayMessage,
) {
    let Some(collector) = collector else {
        return;
    };
    tracing::trace!("ws-har: recording relayed message");
    let kind = message_type(direction);
    let time = unix_seconds();
    match message {
        WebSocketRelayMessage::Text(text) => collector.push_text(kind, time, text.as_str()),
        WebSocketRelayMessage::Binary(bytes) => collector.push_binary(kind, time, bytes),
    }
}

impl<S> Service<WebSocketRelayInput> for WebSocketHarRecorder<S>
where
    S: Service<WebSocketRelayInput, Output: Into<WebSocketRelayOutput>, Error: Into<BoxError>>,
{
    type Output = WebSocketRelayOutput;
    type Error = BoxError;

    async fn serve(&self, input: WebSocketRelayInput) -> Result<Self::Output, Self::Error> {
        let collector = self
            .collector
            .as_ref()
            .or_else(|| input.extensions().get_ref::<WebSocketMessages>());
        record_message(collector, input.direction, &input.message);
        self.inner
            .serve(input)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}

#[cfg(test)]
#[path = "har_tests.rs"]
mod tests;
