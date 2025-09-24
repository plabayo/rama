use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use pin_project_lite::pin_project;
use rama_error::{BoxError, OpaqueError};
use serde::Serialize;

use crate::futures::{Stream, ready};

pin_project! {
    /// Wraps a [Stream] of [Result]s of items that can be json-serialized and offers
    /// a [Stream] implementation of Bytes (json-encoded)-records according to [Serialize], forwarding
    /// potential errors returned by the wrapped iterator.
    pub struct JsonWriteStream<S> {
        written: bool,
        #[pin]
        item_stream: S,
    }
}

impl<S> JsonWriteStream<S> {
    /// Creates a new fallible NDJSON-stream wrapping the given item stream,
    /// to produce a fresh ndjson writer stream.
    pub fn new(item_stream: S) -> Self {
        Self {
            written: false,
            item_stream,
        }
    }

    /// Creates a new fallible NDJSON-stream wrapping the given item stream,
    /// to produce a continued ndjson writer stream.
    ///
    /// Only use this in case you continue from an existing stream,
    /// previously already written ndjson items to, without other data in between.
    pub fn new_continued(item_stream: S) -> Self {
        Self {
            written: true,
            item_stream,
        }
    }

    pub fn into_inner(self) -> S {
        self.item_stream
    }
}

impl<S, T, E> Stream for JsonWriteStream<S>
where
    S: Stream<Item = Result<T, E>>,
    T: Serialize,
    E: Into<BoxError>,
{
    type Item = Result<Bytes, OpaqueError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        match ready!(this.item_stream.as_mut().poll_next(cx)) {
            Some(Ok(item)) => {
                let mut v = Vec::new();
                if *this.written {
                    v.push(b'\n');
                }

                // TODO: in future we probably want to be smarter in this body
                // regarding allocations... for now this is good enough however

                Poll::Ready(Some(
                    if let Err(err) = serde_json::to_writer(&mut v, &item) {
                        Err(OpaqueError::from_boxed(err.into()))
                    } else {
                        *this.written = true;
                        Ok(Bytes::from(v))
                    },
                ))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(OpaqueError::from_boxed(err.into())))),
            None => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;

    use crate::futures::StreamExt;
    use crate::futures::stream;
    use tokio_test::assert_pending;
    use tokio_test::task;

    #[derive(Debug, Serialize, Eq, PartialEq)]
    struct TestStruct {
        key: u64,
        value: u64,
    }

    #[test]
    fn pending_stream_results_in_pending_item() {
        let mut ndjson_stream =
            JsonWriteStream::new(stream::pending::<Result<TestStruct, OpaqueError>>());

        let mut next = task::spawn(ndjson_stream.next());

        assert_pending!(next.poll());
    }

    #[test]
    fn empty_stream_results_in_empty_results() {
        let collected = tokio_test::block_on(
            JsonWriteStream::new(stream::empty::<Result<TestStruct, OpaqueError>>())
                .collect::<Vec<Result<Bytes, OpaqueError>>>(),
        );
        assert!(collected.is_empty());
    }

    #[test]
    fn iter_with_single_json_line() {
        let stream = stream::once(async { Ok::<_, Infallible>(TestStruct { key: 1, value: 2 }) });

        let collected = tokio_test::block_on(
            JsonWriteStream::new(stream).collect::<Vec<Result<Bytes, OpaqueError>>>(),
        );

        let mut result = collected.into_iter();
        assert_eq!(result.next().unwrap().unwrap(), r##"{"key":1,"value":2}"##);
        assert!(result.next().is_none());
    }

    #[test]
    fn iter_with_two_json_lines() {
        let stream = stream::iter([
            Ok::<_, Infallible>(TestStruct { key: 1, value: 2 }),
            Ok::<_, Infallible>(TestStruct { key: 3, value: 4 }),
        ]);

        let collected = tokio_test::block_on(
            JsonWriteStream::new(stream).collect::<Vec<Result<Bytes, OpaqueError>>>(),
        );

        let mut result = collected.into_iter();
        assert_eq!(result.next().unwrap().unwrap(), r##"{"key":1,"value":2}"##);
        assert_eq!(result.next().unwrap().unwrap(), "\n{\"key\":3,\"value\":4}");
        assert!(result.next().is_none());
    }
}
