use crate::sse::event_data::EventDataLineReader;

use super::parser::{RawEventLine, is_bom, line};
use super::utf8_stream::Utf8Stream;
use super::{Event, EventBuildError, EventDataRead};

use pin_project_lite::pin_project;
use rama_core::futures::stream::Stream;
use rama_core::futures::task::{Context, Poll};
use rama_core::telemetry::tracing;
use rama_error::{BoxError, OpaqueError};
use smol_str::SmolStr;
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;

struct EventBuilder<T: EventDataRead> {
    reader: T::Reader,
    event: Event<T>,
    is_complete: bool,
}

impl<T> fmt::Debug for EventBuilder<T>
where
    T: EventDataRead + fmt::Debug,
    T::Reader: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBuilder")
            .field("reader", &self.reader)
            .field("event", &self.event)
            .field("is_complete", &self.is_complete)
            .finish()
    }
}

impl<T: EventDataRead> Default for EventBuilder<T> {
    fn default() -> Self {
        Self {
            reader: T::line_reader(),
            event: Default::default(),
            is_complete: false,
        }
    }
}

impl<T: EventDataRead> EventBuilder<T> {
    /// From the HTML spec
    ///
    /// -> If the field name is "event"
    ///    Set the event type buffer to field value.
    ///
    /// -> If the field name is "data"
    ///    Append the field value to the data buffer, then append a single U+000A LINE FEED (LF)
    ///    character to the data buffer.
    ///
    /// -> If the field name is "id"
    ///    If the field value does not contain U+0000 NULL, then set the last event ID buffer
    ///    to the field value. Otherwise, ignore the field.
    ///
    /// -> If the field name is "retry"
    ///    If the field value consists of only ASCII digits, then interpret the field value as
    ///    an integer in base ten, and set the event stream's reconnection time to that integer.
    ///    Otherwise, ignore the field.
    ///
    /// -> Otherwise
    ///    The field is ignored.
    fn add(&mut self, line: RawEventLine) -> Result<(), OpaqueError> {
        match line {
            RawEventLine::Field(field, val) => match field {
                "event" => {
                    if let Some(val) = val {
                        self.event.try_set_event(val).unwrap();
                    }
                }
                "data" => {
                    self.reader.read_line(val.unwrap_or(""))?;
                }
                "id" => {
                    if let Some(val) = val
                        && !val.contains('\u{0000}')
                    {
                        self.event.try_set_id(val).unwrap();
                    }
                }
                "retry" => {
                    if let Some(val) = val.and_then(|v| v.parse::<u64>().ok()) {
                        self.event.set_retry(val);
                    }
                }
                _ => {
                    tracing::debug!("ignore unknown SSE field {field}: value = {val:?}",)
                }
            },
            RawEventLine::Comment(comment) => {
                self.event.try_set_comment(comment).unwrap();
            }
            RawEventLine::Empty => self.is_complete = true,
        }
        Ok(())
    }

    /// From the HTML spec
    ///
    /// 1. Set the last event ID string of the event source to the value of the last event ID
    ///    buffer. The buffer does not get reset, so the last event ID string of the event source
    ///    remains set to this value until the next time it is set by the server.
    /// 2. If the data buffer is an empty string, set the data buffer and the event type buffer
    ///    to the empty string and return.
    /// 3. If the data buffer's last character is a U+000A LINE FEED (LF) character, then remove
    ///    the last character from the data buffer.
    /// 4. Let event be the result of creating an event using MessageEvent, in the relevant Realm
    ///    of the EventSource object.
    /// 5. Initialize event's type attribute to message, its data attribute to data, its origin
    ///    attribute to the serialization of the origin of the event stream's final URL (i.e., the
    ///    URL after redirects), and its lastEventId attribute to the last event ID string of the
    ///    event source.
    /// 6. If the event type buffer has a value other than the empty string, change the type of
    ///    the newly created event to equal the value of the event type buffer.
    /// 7. Set the data buffer and the event type buffer to the empty string.
    /// 8. Queue a task which, if the readyState attribute is set to a value other than CLOSED,
    ///    dispatches the newly created event at the EventSource object.
    fn try_dispatch(&mut self) -> Result<Event<T>, OpaqueError> {
        self.is_complete = false;
        let mut event = std::mem::take(&mut self.event);
        if let Some(data) = self.reader.data(event.event.as_deref())? {
            event.set_data(data);
        }
        Ok(event)
    }
}

#[derive(Debug, Clone, Copy)]
enum EventStreamState {
    NotStarted,
    Started,
    Terminated,
}

impl EventStreamState {
    fn is_terminated(self) -> bool {
        matches!(self, Self::Terminated)
    }
    fn is_started(self) -> bool {
        matches!(self, Self::Started)
    }
}

pin_project! {
    /// A Stream of SSE's used by the client.
    pub struct EventStream<S, T: EventDataRead = String> {
        #[pin]
        stream: Utf8Stream<S>,
        buffer: String,
        builder: EventBuilder<T>,
        state: EventStreamState,
        last_event_id: Option<SmolStr>,
        _event_data: PhantomData<fn() -> T>,
    }
}

impl<S, T: EventDataRead> EventStream<S, T> {
    /// Initialize the EventStream with a Stream
    pub fn new(stream: S) -> Self {
        Self {
            stream: Utf8Stream::new(stream),
            buffer: String::new(),
            builder: EventBuilder::default(),
            state: EventStreamState::NotStarted,
            last_event_id: None,
            _event_data: PhantomData,
        }
    }

    /// Set the last event ID of the stream. Useful for initializing the stream with a previous
    /// last event ID
    pub fn try_set_last_event_id(&mut self, id: impl Into<SmolStr>) -> Result<(), OpaqueError> {
        let id = id.into();
        if id.contains(['\n', '\r', '\0']) {
            return Err(OpaqueError::from_std(EventBuildError::invalid_characters(
                id,
            )));
        }
        self.last_event_id = Some(id);
        Ok(())
    }

    /// Get the last event ID of the stream
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }
}

fn parse_event<T: EventDataRead>(
    buffer: &mut String,
    builder: &mut EventBuilder<T>,
) -> Result<Option<Event<T>>, OpaqueError> {
    if buffer.is_empty() {
        return Ok(None);
    }
    loop {
        match line(buffer.as_ref()) {
            Ok((rem, next_line)) => {
                builder.add(next_line)?;
                let consumed = buffer.len() - rem.len();
                let rem = buffer.split_off(consumed);
                *buffer = rem;
                if builder.is_complete {
                    return builder.try_dispatch().map(Some);
                }
            }
            Err(nom::Err::Incomplete(_)) => {
                return Ok(None);
            }
            Err(nom::Err::Error(err) | nom::Err::Failure(err)) => {
                return Err(OpaqueError::from_display(format!("SSE parse error: {err}")));
            }
        }
    }
}

impl<S, B, E, T> Stream for EventStream<S, T>
where
    S: Stream<Item = Result<B, E>>,
    E: Into<BoxError>,
    B: AsRef<[u8]>,
    T: EventDataRead,
{
    type Item = Result<Event<T>, OpaqueError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        match parse_event(this.buffer, this.builder) {
            Ok(Some(event)) => {
                *this.last_event_id = event.id().map(SmolStr::new);
                return Poll::Ready(Some(Ok(event)));
            }
            Err(err) => return Poll::Ready(Some(Err(err))),
            _ => {}
        }

        if this.state.is_terminated() {
            return Poll::Ready(None);
        }

        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(string))) => {
                    if string.is_empty() {
                        continue;
                    }

                    let slice = if this.state.is_started() {
                        &string
                    } else {
                        *this.state = EventStreamState::Started;
                        if is_bom(string.chars().next().unwrap()) {
                            &string[1..]
                        } else {
                            &string
                        }
                    };
                    this.buffer.push_str(slice);

                    match parse_event(this.buffer, this.builder) {
                        Ok(Some(event)) => {
                            *this.last_event_id = event.id().map(SmolStr::new);
                            return Poll::Ready(Some(Ok(event)));
                        }
                        Err(err) => return Poll::Ready(Some(Err(err))),
                        _ => {}
                    }
                }
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Some(Err(OpaqueError::from_boxed(err.into()))));
                }
                Poll::Ready(None) => {
                    *this.state = EventStreamState::Terminated;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{BodyExtractExt, sse::JsonEventData};

    use super::*;
    use rama_core::futures::prelude::*;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::convert::Infallible;

    macro_rules! event {
        (
            $data:expr,
            $(event = $name:literal,)*
            $(id = $id:literal,)*
            $(comment = $comment:literal,)*
        ) => {
            {
                #[allow(unused_mut)]
                let mut event = Event {
                    data: Some($data),
                    ..Default::default()
                };
                $(
                    event.try_set_event($name).unwrap();
                )*
                $(
                    event.try_set_id($id).unwrap();
                )*
                $(
                    event.try_set_comment($comment).unwrap();
                )*
                event
            }
        };
        (
            @,
            $(event = $name:literal,)*
            $(id = $id:literal,)*
            $(comment = $comment:literal,)*
        ) => {
            {
                #[allow(unused_mut)]
                let mut event = Event::<String>::default();
                $(
                    event.try_set_event($name).unwrap();
                )*
                $(
                    event.try_set_id($id).unwrap();
                )*
                $(
                    event.try_set_comment($comment).unwrap();
                )*
                event
            }
        };
    }

    #[tokio::test]
    async fn test_string_event_serialize() {
        for (expected, event) in [
            ("", event!(@,)),
            (
                "event: ping\ndata: 42\n\n",
                event!("42".to_owned(), event = "ping",),
            ),
            (
                "data: example message\n\n",
                event!("example message".to_owned(),),
            ),
            (
                "data: a\ndata: b\ndata: c\ndata: d\ndata: e\ndata: f\n\n",
                event!("a\nb\nc\nd\ne\nf".to_owned(),),
            ),
            (
                ": this is a comment\n: another comment\nid: 42\nevent: some-event\ndata: and some data\n\n",
                event!(
                    "and some data".to_owned(),
                    event = "some-event",
                    id = "42",
                    comment = "this is a comment",
                    comment = "another comment",
                ),
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            assert_eq!(expected, buffer);
        }
    }

    #[tokio::test]
    async fn test_string_event_deserialize() {
        for (input, expected) in [
            ("", None),
            (
                "data: 42\nevent: ping\n\n",
                Some(event!("42".to_owned(), event = "ping",)),
            ),
            (
                "event: ping\ndata: 42\n\n",
                Some(event!("42".to_owned(), event = "ping",)),
            ),
            (
                "data: example message\n\n",
                Some(event!("example message".to_owned(),)),
            ),
            (
                "data: a\ndata: b\ndata: c\ndata: d\ndata: e\ndata: f\n\n",
                Some(event!("a\nb\nc\nd\ne\nf".to_owned(),)),
            ),
            (
                ": this is a comment\n: another comment\nid: 42\nevent: some-event\ndata: and some data\n\n",
                Some(event!(
                    "and some data".to_owned(),
                    event = "some-event",
                    id = "42",
                    comment = "this is a comment",
                    comment = "another comment",
                )),
            ),
        ] {
            let mut buffer = input.to_owned();
            let mut builder = EventBuilder::default();
            let event_out: Option<Event> = parse_event(&mut buffer, &mut builder).unwrap();
            assert!(
                buffer.is_empty(),
                "input: '{input}'; buffer: '{buffer}'; builder: '{builder:?}'"
            );
            assert!(
                !builder.is_complete,
                "input: '{input}'; builder: '{builder:?}'"
            );
            assert_eq!(Event::default(), builder.event, "input: '{input}'");
            assert_eq!(expected, event_out, "input: '{input}'");
        }
    }

    #[tokio::test]
    async fn test_string_event_serialize_deserialize() {
        for event in [
            event!("foo".to_owned(), event = "ping",),
            event!(
                "and some data".to_owned(),
                event = "some-event",
                id = "42",
                comment = "this is a comment",
                comment = "another comment",
            ),
        ] {
            let mut buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            let mut builder = EventBuilder::default();
            let event_out: Event = parse_event(&mut buffer, &mut builder).unwrap().unwrap();
            assert!(buffer.is_empty());
            assert!(!builder.is_complete);
            assert_eq!(Event::default(), builder.event);
            assert_eq!(event, event_out);
        }
    }

    #[tokio::test]
    async fn test_json_event_serialize() {
        for (expected, event) in [
            ("data: {}\n\n", event!(JsonEventData(json!({})),)),
            (
                "data: {\"name\":\"john\"}\n\n",
                event!(JsonEventData(json!({"name": "john"})),),
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            assert_eq!(expected, buffer);
        }
    }

    #[tokio::test]
    async fn test_json_event_deserialize() {
        #[derive(Debug, Deserialize, Default, PartialEq, Eq)]
        struct Data {
            points: Option<Vec<u32>>,
        }
        type PointsEvent = Event<JsonEventData<Data>>;

        for (input, expected) in [
            (
                "data: {}\n\n",
                Some(event!(JsonEventData(Data::default()),)),
            ),
            (
                "data: {\"points\":[]}\nevent: message\n\n",
                Some(event!(
                    JsonEventData(Data {
                        points: Some(vec![])
                    }),
                    event = "message",
                )),
            ),
            (
                "data: {\"points\":[4,2]}\nevent: ping\n\n",
                Some(event!(
                    JsonEventData(Data {
                        points: Some(vec![4, 2])
                    }),
                    event = "ping",
                )),
            ),
        ] {
            let mut buffer = input.to_owned();
            let mut builder = EventBuilder::default();
            let event_out: Option<PointsEvent> = parse_event(&mut buffer, &mut builder).unwrap();
            assert!(
                buffer.is_empty(),
                "input: '{input}'; buffer: '{buffer}'; builder: '{builder:?}'"
            );
            assert!(
                !builder.is_complete,
                "input: '{input}'; builder: '{builder:?}'"
            );
            assert_eq!(PointsEvent::default(), builder.event, "input: '{input}'");
            assert_eq!(expected, event_out, "input: '{input}'");
        }
    }

    #[tokio::test]
    async fn test_json_event_serialize_deserialize() {
        #[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
        struct Log {
            text: String,
        }
        type LogEvent = Event<JsonEventData<Log>>;

        for event in [
            event!(
                JsonEventData(Log {
                    text: "a log line".to_owned()
                }),
                event = "message",
            ),
            event!(
                JsonEventData(Log {
                    text: "another log line".to_owned()
                }),
                event = "final",
                id = "L3",
                comment = "this is",
                comment = " a log",
            ),
        ] {
            let mut buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            let mut builder = EventBuilder::default();
            let event_out: LogEvent = parse_event(&mut buffer, &mut builder).unwrap().unwrap();
            assert!(buffer.is_empty());
            assert!(!builder.is_complete);
            assert_eq!(LogEvent::default(), builder.event);
            assert_eq!(event, event_out);
        }
    }

    #[tokio::test]
    async fn test_multiline_event_serialize() {
        for (expected, event) in [
            ("data: \n\n", event!(Vec::<String>::default(),)),
            ("data: a\n\n", event!(vec!["a".to_owned()],)),
            (
                "data: a\ndata: b\n\n",
                event!(vec!["a".to_owned(), "b".to_owned()],),
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            assert_eq!(expected, buffer);
        }
    }

    #[tokio::test]
    async fn test_multiline_event_deserialize() {
        for (input, expected) in [
            ("", None),
            ("data: \n\n", Some(event!(vec![String::default()],))),
            ("data: a\n\n", Some(event!(vec!["a".to_owned()],))),
            (
                "data: a\ndata: b\n\n",
                Some(event!(vec!["a".to_owned(), "b".to_owned()],)),
            ),
        ] {
            let mut buffer = input.to_owned();
            let mut builder = EventBuilder::default();
            let event_out: Option<Event<Vec<String>>> =
                parse_event(&mut buffer, &mut builder).unwrap();
            assert!(
                buffer.is_empty(),
                "input: '{input}'; buffer: '{buffer}'; builder: '{builder:?}'"
            );
            assert!(
                !builder.is_complete,
                "input: '{input}'; builder: '{builder:?}'"
            );
            assert_eq!(
                Event::<Vec<String>>::default(),
                builder.event,
                "input: '{input}'"
            );
            assert_eq!(expected, event_out, "input: '{input}'");
        }
    }

    #[tokio::test]
    async fn test_multiline_event_serialize_deserialize() {
        type MultilineEvent = Event<Vec<String>>;

        for event in [
            event!(vec!["foo".to_owned(), "bar".to_owned()], event = "message",),
            event!(
                vec!["foo".to_owned()],
                event = "final",
                id = "L3",
                comment = "this is",
                comment = " a log",
            ),
        ] {
            let mut buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            let mut builder = EventBuilder::default();
            let event_out: MultilineEvent =
                parse_event(&mut buffer, &mut builder).unwrap().unwrap();
            assert!(buffer.is_empty());
            assert!(!builder.is_complete);
            assert_eq!(MultilineEvent::default(), builder.event);
            assert_eq!(event, event_out);
        }
    }

    #[tokio::test]
    async fn valid_data_fields() {
        for (input, expected) in [
            (
                vec!["data: Hello, world!\n\n"],
                vec![event!("Hello, world!".to_owned(),)],
            ),
            (
                vec!["data: Hello,", " world!\n\n"],
                vec![event!("Hello, world!".to_owned(),)],
            ),
            (
                vec!["data: Hello,", "", " world!\n\n"],
                vec![event!("Hello, world!".to_owned(),)],
            ),
            (
                vec!["data: Hello,\ndata: world!\n\n"],
                vec![event!("Hello,\nworld!".to_owned(),)],
            ),
            (
                vec!["data: Hello,\n\ndata: world!\n\n"],
                vec![event!("Hello,".to_owned(),), event!("world!".to_owned(),)],
            ),
        ] {
            let stream = EventStream::new(stream::iter(input.iter().map(Ok::<_, Infallible>)));
            let output = stream.try_collect::<Vec<_>>().await.unwrap();
            assert_eq!(expected, output, "input: '{input:?}'; output: '{output:?}'");
        }
    }

    #[tokio::test]
    async fn spec_examples() {
        for (input, expected) in [
            (
                vec![
                    "data: This is the first message.

data: This is the second message, it
data: has two lines.

data: This is the third message.

",
                ],
                vec![
                    event!("This is the first message.".to_owned(),),
                    event!("This is the second message, it\nhas two lines.".to_owned(),),
                    event!("This is the third message.".to_owned(),),
                ],
            ),
            (
                vec![
                    "event: add
data: 73857293

event: remove
data: 2153

event: add
data: 113411

    ",
                ],
                vec![
                    event!("73857293".to_owned(), event = "add",),
                    event!("2153".to_owned(), event = "remove",),
                    event!("113411".to_owned(), event = "add",),
                ],
            ),
            (
                vec![
                    "data: YHOO
data: +2
data: 10

    ",
                ],
                vec![event!("YHOO\n+2\n10".to_owned(),)],
            ),
            (
                vec![
                    ": test stream

data: first event
id: 1

data:second event
id

data:  third event

    ",
                ],
                vec![
                    event!(@, comment = "test stream",),
                    event!("first event".to_owned(), id = "1",),
                    event!("second event".to_owned(),),
                    event!(" third event".to_owned(),),
                ],
            ),
            (
                vec![
                    "data

data
data

data:
",
                ],
                vec![event!("".to_owned(),), event!("\n".to_owned(),)],
            ),
            (
                vec![
                    "data:test

data: test

",
                ],
                vec![event!("test".to_owned(),), event!("test".to_owned(),)],
            ),
        ] {
            let stream = EventStream::new(stream::iter(input.iter().map(Ok::<_, Infallible>)));
            let expect = format!("input: '{input:?}'");
            let output = stream.try_collect::<Vec<_>>().await.expect(&expect);
            assert_eq!(expected, output, "input: '{input:?}'; output: '{output:?}'");
        }
    }
}
