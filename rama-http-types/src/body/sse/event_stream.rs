use super::parser::{RawEventLine, is_bom, is_lf, line};
use super::utf8_stream::Utf8Stream;
use super::{Event, EventBuildError, EventDataRead};
use futures_core::stream::Stream;
use futures_core::task::{Context, Poll};
use pin_project_lite::pin_project;
use rama_error::{BoxError, OpaqueError};
use smol_str::SmolStr;
use std::marker::PhantomData;
use std::pin::Pin;

#[derive(Debug)]
struct EventBuilder<T> {
    raw_data: String,
    event: Event<T>,
    is_complete: bool,
}

impl<T> Default for EventBuilder<T> {
    fn default() -> Self {
        Self {
            raw_data: Default::default(),
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
    fn add(&mut self, line: RawEventLine) {
        match line {
            RawEventLine::Field(field, val) => match field {
                "event" => {
                    if let Some(val) = val {
                        self.event.try_set_event(val).unwrap();
                    }
                }
                "data" => {
                    self.raw_data.push_str(val.unwrap_or("")); // TODO: verify if this is desired
                    self.raw_data.push('\u{000A}');
                }
                "id" => {
                    if let Some(val) = val {
                        if !val.contains('\u{0000}') {
                            // TODO: verify if this is desired
                            self.event.try_set_id(val).unwrap();
                        }
                    }
                }
                "retry" => {
                    if let Some(val) = val.and_then(|v| v.parse::<u64>().ok()) {
                        self.event.set_retry(val);
                    }
                }
                _ => {}
            },
            RawEventLine::Comment(comment) => {
                self.event.try_set_comment(comment).unwrap();
            }
            RawEventLine::Empty => self.is_complete = true,
        }
    }

    /// From the HTML spec
    ///
    /// 1. Set the last event ID string of the event source to the value of the last event ID
    /// buffer. The buffer does not get reset, so the last event ID string of the event source
    /// remains set to this value until the next time it is set by the server.
    /// 2. If the data buffer is an empty string, set the data buffer and the event type buffer
    /// to the empty string and return.
    /// 3. If the data buffer's last character is a U+000A LINE FEED (LF) character, then remove
    /// the last character from the data buffer.
    /// 4. Let event be the result of creating an event using MessageEvent, in the relevant Realm
    /// of the EventSource object.
    /// 5. Initialize event's type attribute to message, its data attribute to data, its origin
    /// attribute to the serialization of the origin of the event stream's final URL (i.e., the
    /// URL after redirects), and its lastEventId attribute to the last event ID string of the
    /// event source.
    /// 6. If the event type buffer has a value other than the empty string, change the type of
    /// the newly created event to equal the value of the event type buffer.
    /// 7. Set the data buffer and the event type buffer to the empty string.
    /// 8. Queue a task which, if the readyState attribute is set to a value other than CLOSED,
    /// dispatches the newly created event at the EventSource object.
    fn try_dispatch(&mut self) -> Result<Event<T>, OpaqueError> {
        self.is_complete = false;
        let mut event = std::mem::take(&mut self.event);

        // TODO: verify if this required
        if is_lf(self.raw_data.chars().next_back().unwrap()) {
            self.raw_data.pop();
        }
        event.set_data(T::read_data(std::mem::take(&mut self.raw_data))?);

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
    pub struct EventStream<S, T = String> {
        #[pin]
        stream: Utf8Stream<S>,
        buffer: String,
        builder: EventBuilder<T>,
        state: EventStreamState,
        last_event_id: Option<SmolStr>,
        _event_data: PhantomData<fn() -> T>,
    }
}

impl<S, T> EventStream<S, T> {
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
    pub fn try_set_last_event_id(&mut self, id: impl AsRef<str>) -> Result<(), OpaqueError> {
        let id = id.as_ref();
        if id.contains(['\n', '\r', '\0']) {
            return Err(OpaqueError::from_std(EventBuildError::invalid_characters(
                id,
            )));
        }
        self.last_event_id = Some(SmolStr::new(id));
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
                builder.add(next_line);
                let consumed = buffer.len() - rem.len();
                let rem = buffer.split_off(consumed);
                *buffer = rem;
                if builder.is_complete {
                    return builder.try_dispatch().map(Some);
                }
            }
            Err(nom::Err::Incomplete(_)) => return Ok(None),
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
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
    use std::convert::Infallible;

    use super::*;
    use futures::prelude::*;

    #[tokio::test]
    async fn valid_data_fields() {
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "data: Hello, world!\n\n"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![Event::new().with_data("Hello, world!".to_owned())]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![
                Ok::<_, Infallible>("data: Hello,"),
                Ok::<_, Infallible>(" world!\n\n")
            ]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![Event::new().with_data("Hello, world!".to_owned())]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![
                Ok::<_, Infallible>("data: Hello,"),
                Ok::<_, Infallible>(""),
                Ok::<_, Infallible>(" world!\n\n")
            ]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![Event::new().with_data("Hello, world!".to_owned())]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "data: Hello, world!\n"
            )]))
            .try_collect::<Vec<Event>>()
            .await
            .unwrap(),
            vec![]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "data: Hello,\ndata: world!\n\n"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![Event::new().with_data("Hello,\nworld!".to_owned())]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "data: Hello,\n\ndata: world!\n\n"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![
                Event::new().with_data("Hello,".to_owned()),
                Event::new().with_data("world!".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn spec_examples() {
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "data: This is the first message.

data: This is the second message, it
data: has two lines.

data: This is the third message.

"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![
                Event::new().with_data("This is the first message.".to_owned()),
                Event::new().with_data("This is the second message, it\nhas two lines.".to_owned()),
                Event::new().with_data("This is the third message.".to_owned())
            ]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "event: add
data: 73857293

event: remove
data: 2153

event: add
data: 113411

"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![
                Event::new()
                    .try_with_event("add")
                    .unwrap()
                    .with_data("73857293".to_owned()),
                Event::new()
                    .try_with_event("remove")
                    .unwrap()
                    .with_data("2153".to_owned()),
                Event::new()
                    .try_with_event("add")
                    .unwrap()
                    .with_data("113411".to_owned()),
            ]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "data: YHOO
data: +2
data: 10

"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![Event::new().with_data("YHOO\n+2\n10".to_owned())]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                ": test stream

data: first event
id: 1

data:second event
id

data:  third event

"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![
                Event::new()
                    .try_with_id("1")
                    .unwrap()
                    .with_data("first event".to_owned()),
                Event::new().with_data("second event".to_owned()),
                Event::new().with_data("third event".to_owned()),
            ]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "data

data
data

data:
"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![
                Event::new().with_data("".to_owned()),
                Event::new().with_data("\n".to_owned()),
            ]
        );
        assert_eq!(
            EventStream::new(stream::iter(vec![Ok::<_, Infallible>(
                "data:test

data: test

"
            )]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec![
                Event::new().with_data("test".to_owned()),
                Event::new().with_data("test".to_owned()),
            ]
        );
    }
}
