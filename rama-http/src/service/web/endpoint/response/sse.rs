//! Server-Sent Events (SSE) response.

use futures_lite::Stream;
use futures_util::TryStream;
use rama_core::error::BoxError;
use rama_http_headers::{CacheControl, Connection, ContentType};
use rama_http_types::{
    Body, Response,
    sse::{
        Event, EventDataWrite,
        server::{KeepAlive, KeepAliveStream, SseResponseBody},
    },
};
use std::fmt;

use super::{Headers, IntoResponse};

/// An SSE response
#[must_use]
pub struct Sse<S> {
    stream: S,
}

impl<S> Sse<S> {
    /// Create a new [`Sse`] response that will respond with the given stream of
    /// [`Event`]s.
    pub fn new<T>(stream: S) -> Self
    where
        S: TryStream<Ok = Event<T>> + Send + 'static,
        S::Error: Into<BoxError>,
        T: EventDataWrite,
    {
        Sse { stream }
    }

    /// Configure the interval between keep-alive messages.
    ///
    /// Defaults to no keep-alive messages.
    pub fn with_keep_alive<T, E>(self, keep_alive: KeepAlive<T>) -> Sse<KeepAliveStream<S, T>>
    where
        S: Stream<Item = Result<Event<T>, E>>,
        E: Into<BoxError>,
        T: EventDataWrite,
    {
        Sse {
            stream: KeepAliveStream::new(keep_alive, self.stream),
        }
    }
}

impl<S: Clone> Clone for Sse<S> {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.clone(),
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for Sse<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sse").field("stream", &self.stream).finish()
    }
}

impl<S, E, T> IntoResponse for Sse<S>
where
    S: Stream<Item = Result<Event<T>, E>> + Send + 'static,
    E: Into<BoxError>,
    T: EventDataWrite,
{
    fn into_response(self) -> Response {
        (
            Headers((
                CacheControl::default().with_no_cache(),
                ContentType::text_event_stream(),
                // will be automatically filtered out for h2+
                Connection::keep_alive(),
            )),
            Body::new(SseResponseBody::new(self.stream)),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{client::HttpClientExt as _, web::Router};
    use futures_util::stream;
    use rama_core::{Service as _, combinators::Either};
    use rama_http_types::sse::JsonEventData;
    use std::{collections::HashMap, convert::Infallible, time::Duration};
    use tokio_stream::StreamExt as _;

    #[tokio::test]
    async fn basic() {
        let client = Router::new()
            .get("/", async || {
                let stream = stream::iter(vec![
                    Event::default()
                        .with_data(Either::A("one"))
                        .try_with_static_comment("this is a comment")
                        .unwrap(),
                    Event::default().with_data(Either::B(JsonEventData(
                        serde_json::json!({ "foo": "bar" }),
                    ))),
                    Event::default()
                        .try_with_static_event("three")
                        .unwrap()
                        .with_retry(30_000)
                        .try_with_static_id("unique-id")
                        .unwrap(),
                ])
                .map(Ok::<_, Infallible>);
                Sse::new(stream)
            })
            .boxed();

        let response = client
            .get("http://example.com")
            .send(rama_core::Context::default())
            .await
            .unwrap();

        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(response.headers()["cache-control"], "no-cache");

        let mut stream = response.into_body();

        let event_fields =
            parse_event(std::str::from_utf8(&stream.chunk().await.unwrap().unwrap()).unwrap());
        assert_eq!(event_fields.get("data").unwrap(), "one");
        assert_eq!(event_fields.get("comment").unwrap(), "this is a comment");

        let event_fields =
            parse_event(std::str::from_utf8(&stream.chunk().await.unwrap().unwrap()).unwrap());
        assert_eq!(event_fields.get("data").unwrap(), "{\"foo\":\"bar\"}");
        assert!(!event_fields.contains_key("comment"));

        let event_fields =
            parse_event(std::str::from_utf8(&stream.chunk().await.unwrap().unwrap()).unwrap());
        assert_eq!(event_fields.get("event").unwrap(), "three");
        assert_eq!(event_fields.get("retry").unwrap(), "30000");
        assert_eq!(event_fields.get("id").unwrap(), "unique-id");
        assert!(!event_fields.contains_key("comment"));

        assert!(stream.chunk().await.unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn keep_alive() {
        const DELAY: Duration = Duration::from_secs(5);

        let client = Router::new()
            .get("/", async || {
                let stream = stream::repeat_with(|| Event::default().with_data("msg"))
                    .map(Ok::<_, Infallible>)
                    .throttle(DELAY);

                Sse::new(stream).with_keep_alive(
                    KeepAlive::<&'static str>::new()
                        .with_interval(Duration::from_secs(1))
                        .try_with_text("keep-alive-text")
                        .unwrap(),
                )
            })
            .boxed();

        let mut stream = client
            .get("http://example.com")
            .send(rama_core::Context::default())
            .await
            .unwrap()
            .into_body();

        for _ in 0..5 {
            // first message should be an event
            let event_fields =
                parse_event(std::str::from_utf8(&stream.chunk().await.unwrap().unwrap()).unwrap());
            assert_eq!(event_fields.get("data").unwrap(), "msg");

            // then 4 seconds of keep-alive messages
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let event_fields = parse_event(
                    std::str::from_utf8(&stream.chunk().await.unwrap().unwrap()).unwrap(),
                );
                assert_eq!(event_fields.get("comment").unwrap(), "keep-alive-text");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn keep_alive_ends_when_the_stream_ends() {
        const DELAY: Duration = Duration::from_secs(5);

        let client = Router::new()
            .get("/", async || {
                let stream = stream::repeat_with(|| Event::default().with_data("msg"))
                    .map(Ok::<_, Infallible>)
                    .throttle(DELAY)
                    .take(2);

                Sse::new(stream).with_keep_alive(
                    KeepAlive::<&'static str>::new()
                        .with_interval(Duration::from_secs(1))
                        .try_with_text("keep-alive-text")
                        .unwrap(),
                )
            })
            .boxed();

        let mut stream = client
            .get("http://example.com")
            .send(rama_core::Context::default())
            .await
            .unwrap()
            .into_body();

        // first message should be an event
        let event_fields =
            parse_event(std::str::from_utf8(&stream.chunk().await.unwrap().unwrap()).unwrap());
        assert_eq!(event_fields.get("data").unwrap(), "msg");

        // then 4 seconds of keep-alive messages
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let event_fields =
                parse_event(std::str::from_utf8(&stream.chunk().await.unwrap().unwrap()).unwrap());
            assert_eq!(event_fields.get("comment").unwrap(), "keep-alive-text");
        }

        // then the last event
        let event_fields =
            parse_event(std::str::from_utf8(&stream.chunk().await.unwrap().unwrap()).unwrap());
        assert_eq!(event_fields.get("data").unwrap(), "msg");

        // then no more events or keep-alive messages
        assert!(stream.chunk().await.unwrap().is_none());
    }

    fn parse_event(payload: &str) -> HashMap<String, String> {
        let mut fields = HashMap::new();

        let mut lines = payload.lines().peekable();
        while let Some(line) = lines.next() {
            if line.is_empty() {
                assert_eq!(None, lines.next());
                break;
            }

            let (mut key, value) = line.split_once(':').unwrap();
            let value = value.trim();
            if key.is_empty() {
                key = "comment";
            }
            fields.insert(key.to_owned(), value.to_owned());
        }

        fields
    }
}
