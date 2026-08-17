use rama_core::extensions::Extension;
use rama_utils::str::arcstr::ArcStr;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(http))]
pub struct RequestComment(pub ArcStr);

#[cfg(feature = "ws-har")]
mod ws {
    use super::*;
    use crate::layer::har::spec::{WebSocketMessage, WebSocketMessageType};
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[must_use]
    #[derive(Debug, Clone, Default, Extension)]
    #[extension(tags(http))]
    /// Collects the WebSocket messages relayed over one upgraded connection, so the HAR
    /// entry for that connection can carry them.
    ///
    /// A WebSocket entry is a `101` with no body: by the time any frame exists the
    /// response is long since returned. Sharing one buffer between the relay and the
    /// HAR service is what lets the two meet — the relay pushes as frames pass, and the
    /// entry is written from the same buffer.
    ///
    /// Note that [`HARExportService`] reads this buffer as soon as the inner service
    /// yields a response, which for an upgrade is before a single frame has been
    /// relayed. Until the entry for a `101` is deferred to socket close, the field it
    /// produces is empty in that flow.
    ///
    /// [`HARExportService`]: crate::layer::har::service::HARExportService
    pub struct WebSocketMessages(Arc<Mutex<Vec<WebSocketMessage>>>);

    impl WebSocketMessages {
        pub fn new() -> Self {
            Self::default()
        }

        /// Records one relayed message.
        ///
        /// `data` is stored as-is for text and base64-encoded for binary, because HAR is
        /// JSON and a binary frame has no faithful UTF-8 form.
        pub fn push_text(&self, direction: WebSocketMessageType, time: f64, text: &str) {
            self.push(WebSocketMessage {
                r#type: direction,
                time,
                opcode: 1,
                data: text.into(),
            });
        }

        pub fn push_binary(&self, direction: WebSocketMessageType, time: f64, data: &[u8]) {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            self.push(WebSocketMessage {
                r#type: direction,
                time,
                opcode: 2,
                data: STANDARD.encode(data).into(),
            });
        }

        fn push(&self, message: WebSocketMessage) {
            self.0.lock().push(message);
        }

        /// Drains everything relayed so far. Returns `None` when nothing was seen, so a
        /// non-WebSocket entry omits the field entirely.
        ///
        /// Draining rather than copying keeps a collector that outlives one entry from
        /// re-emitting the same messages on the next one.
        #[must_use]
        pub fn take(&self) -> Option<Vec<WebSocketMessage>> {
            let mut guard = self.0.lock();
            (!guard.is_empty()).then(|| std::mem::take(&mut *guard))
        }
    }
}

#[cfg(feature = "ws-har")]
pub use ws::WebSocketMessages;
