use rama_core::bytes::{BufMut as _, Bytes, BytesMut};
use rama_error::OpaqueError;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::smol_str::SmolStr;
use std::{fmt, time::Duration};

use super::{EventDataWrite, JsonEventData};

/// Server-sent event
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event<T = String> {
    pub(super) event: Option<SmolStr>,
    pub(super) id: Option<SmolStr>,
    pub(super) data: Option<T>,
    pub(super) retry: Option<Duration>,
    pub(super) comments: Option<Vec<SmolStr>>,
}

impl<T> Default for Event<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct EventBuildError {
    kind: EventBuildErrorKind,
}

impl EventBuildError {
    pub(super) fn invalid_characters(chars: SmolStr) -> Self {
        Self {
            kind: EventBuildErrorKind::InvalidCharacter(chars),
        }
    }
}

#[derive(Debug)]
enum EventBuildErrorKind {
    InvalidCharacter(SmolStr),
}

impl fmt::Display for EventBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            EventBuildErrorKind::InvalidCharacter(s) => {
                write!(f, "event build error: invalid character(s): {s}")
            }
        }
    }
}

impl std::error::Error for EventBuildError {}

impl<T> Event<T> {
    /// Create a new [`Event`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            event: None,
            id: None,
            data: None,
            retry: None,
            comments: None,
        }
    }
}

impl<T: EventDataWrite> Event<T> {
    pub(super) fn serialize(&self) -> Result<Bytes, OpaqueError> {
        let mut buffer = BytesMut::new();

        let mut serialize = |name, value| {
            buffer.extend_from_slice(name);
            buffer.put_u8(b':');
            buffer.put_u8(b' ');
            buffer.extend_from_slice(value);
            buffer.put_u8(b'\n');
        };

        for comment in self.comments.iter().flatten() {
            serialize(b"", comment.as_bytes());
        }
        if let Some(ref id) = self.id {
            serialize(b"id", id.as_bytes());
        }

        if let Some(ref event) = self.event {
            serialize(b"event", event.as_bytes());
        }

        if let Some(retry) = self.retry {
            let mut buf = itoa::Buffer::new();
            serialize(b"retry", buf.format(retry.as_millis()).as_bytes());
        }

        let mut buffer = match &self.data {
            Some(data) => {
                buffer.extend_from_slice(b"data");
                buffer.put_u8(b':');
                buffer.put_u8(b' ');

                let mut buf_write = buffer.writer();
                data.write_data(&mut DataWriteSplitter(&mut buf_write))?;
                let mut buffer = buf_write.into_inner();
                buffer.put_u8(b'\n');
                buffer
            }
            None => buffer,
        };

        if !buffer.is_empty() {
            buffer.put_u8(b'\n');
        }

        Ok(buffer.freeze())
    }
}

impl<T> Event<T> {
    /// Return the event's identifier field (`id:<identifier>`).
    ///
    /// This corresponds to [`MessageEvent`'s `lastEventId` field]. If no ID is in the event itself,
    /// the browser will set that field to the last known message ID, starting with the empty
    /// string.
    ///
    /// [`MessageEvent`'s `lastEventId` field]: https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent/lastEventId
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    generate_set_and_with! {
        /// Set the event's identifier field (`id:<identifier>`).
        ///
        /// This corresponds to [`MessageEvent`'s `lastEventId` field]. If no ID is in the event itself,
        /// the browser will set that field to the last known message ID, starting with the empty
        /// string.
        ///
        /// Previously set value will be overwritten.
        ///
        /// [`MessageEvent`'s `lastEventId` field]: https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent/lastEventId
        pub fn id(mut self, id: impl Into<SmolStr>) -> Result<Self, EventBuildError> {
            let id = id.into();
            if id.contains(['\n', '\r', '\0']) {
                return Err(EventBuildError::invalid_characters(id));
            }
            self.id = Some(id);
            Ok(self)
        }
    }

    /// Return the event's data data field(s) (`data: <content>`)
    ///
    /// This corresponds to [`MessageEvent`'s data field].
    ///
    /// [`MessageEvent`'s data field]: https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent/data
    pub fn data(&self) -> Option<&T> {
        self.data.as_ref()
    }

    /// Consume `self` and return the event's data data field(s) (`data: <content>`)
    ///
    /// This corresponds to [`MessageEvent`'s data field].
    ///
    /// [`MessageEvent`'s data field]: https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent/data
    pub fn into_data(self) -> Option<T> {
        self.data
    }

    generate_set_and_with! {
        /// Set the event's data data field(s) (`data: <content>`)
        ///
        /// The serialized data will automatically break newlines across `data: ` fields.
        ///
        /// This corresponds to [`MessageEvent`'s data field].
        ///
        /// Note that events with an empty data field will be ignored by the browser.
        /// Previously set value will be overwritten.
        ///
        /// [`MessageEvent`'s data field]: https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent/data
        pub fn data(mut self, data: T) -> Self {
            self.data = Some(data);
            self
        }
    }

    /// Return the event's name field (`event:<event-name>`).
    ///
    /// This corresponds to the `type` parameter given when calling `addEventListener` on an
    /// [`EventSource`]. For example, `.event("update")` should correspond to
    /// `.addEventListener("update", ...)`. If no event type is given, browsers will fire a
    /// [`message` event] instead.
    ///
    /// [`EventSource`]: https://developer.mozilla.org/en-US/docs/Web/API/EventSource
    /// [`message` event]: https://developer.mozilla.org/en-US/docs/Web/API/EventSource/message_event
    pub fn event(&self) -> Option<&str> {
        self.event.as_deref()
    }

    generate_set_and_with! {
        /// Set the event's name field (`event:<event-name>`).
        ///
        /// Previously set event will be overwritten.
        ///
        /// This corresponds to the `type` parameter given when calling `addEventListener` on an
        /// [`EventSource`]. For example, `.event("update")` should correspond to
        /// `.addEventListener("update", ...)`. If no event type is given, browsers will fire a
        /// [`message` event] instead.
        ///
        /// [`EventSource`]: https://developer.mozilla.org/en-US/docs/Web/API/EventSource
        /// [`message` event]: https://developer.mozilla.org/en-US/docs/Web/API/EventSource/message_event
        pub fn event(mut self, event: impl Into<SmolStr>) -> Result<Self, EventBuildError> {
            let event = event.into();
            if event.contains(['\n', '\r']) {
                return Err(EventBuildError::invalid_characters(event));
            }
            self.event = Some(event);
            Ok(self)
        }
    }

    /// Return the event's retry timeout field (`retry:<timeout>`).
    ///
    /// This sets how long clients will wait before reconnecting if they are disconnected from the
    /// SSE endpoint. Note that this is just a hint: clients are free to wait for longer if they
    /// wish, such as if they implement exponential backoff.
    pub fn retry(&self) -> Option<Duration> {
        self.retry
    }

    generate_set_and_with! {
        /// Set the event's retry timeout field (`retry:<timeout>`).
        ///
        /// Previously set retry will be overwritten.
        ///
        /// This sets how long clients will wait before reconnecting if they are disconnected from the
        /// SSE endpoint. Note that this is just a hint: clients are free to wait for longer if they
        /// wish, such as if they implement exponential backoff.
        pub const fn static_retry(mut self, millis: u64) -> Self {
            self.retry = Some(Duration::from_millis(millis));
            self
        }
    }

    generate_set_and_with! {
        /// Set the event's retry timeout field (`retry:<timeout>`).
        ///
        /// Previously set retry will be overwritten.
        ///
        /// This sets how long clients will wait before reconnecting if they are disconnected from the
        /// SSE endpoint. Note that this is just a hint: clients are free to wait for longer if they
        /// wish, such as if they implement exponential backoff.
        pub fn retry(mut self, millis: u64) -> Self {
            self.retry = Some(Duration::from_millis(millis));
            self
        }
    }

    /// Return the event's comment fields (`:<comment-text>`).
    pub fn comment(&self) -> impl Iterator<Item = &str> {
        self.comments.iter().flatten().map(|s| s.as_str())
    }

    generate_set_and_with! {
        /// Set the event's comment field (`:<comment-text>`).
        ///
        /// This field will be ignored by most SSE clients.
        ///
        /// You can add as many comments as you want by calling this function as many as you wish,
        /// unlike other setters this one does not overwrite.
        pub fn comment(mut self, comment: impl Into<SmolStr>) -> Result<Self, EventBuildError> {
            let comment = comment.into();
            if comment.contains(['\n', '\r']) {
                return Err(EventBuildError::invalid_characters(comment));
            }
            self.comments.get_or_insert_default().push(comment);
            Ok(self)
        }
    }
}

impl Event {
    generate_set_and_with! {
        /// Use [`JsonEventData`] as a shortcut to serialize it directly
        /// into a [`String`] using [`Self::data`].
        pub fn json_data(mut self, data: impl serde::Serialize) -> Result<Self, OpaqueError> {
            let mut v = Vec::new();
            JsonEventData(data).write_data(&mut v)?;
            self.data = Some(String::from_utf8(v).map_err(|_| OpaqueError::from_display("utf8 error"))?);
            Ok(self)
        }
    }
}

struct DataWriteSplitter<'a, W: std::io::Write>(&'a mut W);

impl<W: std::io::Write> std::io::Write for DataWriteSplitter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut last_split = 0;
        for delimiter in memchr::memchr2_iter(b'\n', b'\r', buf) {
            self.0.write_all(&buf[last_split..=delimiter])?;
            self.0.write_all(b"data: ")?;
            last_split = delimiter + 1;
        }
        self.0.write_all(&buf[last_split..])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
