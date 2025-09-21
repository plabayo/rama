use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use rama_core::futures::{Stream, ready};
use rama_error::{BoxError, ErrorContext as _, OpaqueError};
use serde::Deserialize;

use super::config::ParseConfig;
use super::engine::NdjsonEngine;

pin_project! {
    /// Wraps a [Stream] of [Result]s of data blocks, i.e. types that reference as byte array, and offers
    /// a [Stream] mplementation over parsed NDJSON-records according to [Deserialize], forwarding
    /// potential errors returned by the wrapped iterator.
    pub struct JsonStream<T, S> {
        engine: NdjsonEngine<T>,
        #[pin]
        bytes_stream: S
    }
}

impl<T, S> JsonStream<T, S> {
    /// Creates a new fallible NDJSON-stream wrapping the given `bytes_stream` with default
    /// [ParseConfig].
    pub fn new(bytes_stream: S) -> Self {
        Self {
            engine: NdjsonEngine::new(),
            bytes_stream,
        }
    }

    /// Creates a new fallible NDJSON-stream wrapping the given `bytes_stream` with the given
    /// [ParseConfig] to control its behavior. See [ParseConfig] for more details.
    pub fn new_with_config(bytes_stream: S, config: ParseConfig) -> Self {
        Self {
            engine: NdjsonEngine::with_config(config),
            bytes_stream,
        }
    }
}

impl<T, S, B, E> Stream for JsonStream<T, S>
where
    for<'deserialize> T: Deserialize<'deserialize>,
    E: Into<BoxError>,
    S: Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
{
    type Item = Result<T, OpaqueError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            if let Some(result) = this.engine.pop() {
                return Poll::Ready(Some(result.context("json-deserialize next value")));
            }

            let bytes = ready!(this.bytes_stream.as_mut().poll_next(cx));

            match bytes {
                Some(Ok(bytes)) => this.engine.input(bytes),
                Some(Err(err)) => {
                    let err = OpaqueError::from_boxed(err.into());
                    return Poll::Ready(Some(Err(err)));
                }
                None => {
                    this.engine.finalize();
                    return Poll::Ready(
                        this.engine
                            .pop()
                            .map(|res| res.context("json-deserialize last value")),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::pin::pin;

    use rama_core::futures::StreamExt;
    use rama_core::futures::stream;
    use tokio_test::assert_pending;
    use tokio_test::task;

    use crate::body::json::EmptyLineHandling;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct TestStruct {
        key: u64,
        value: u64,
    }

    struct SingleThenPanicIter {
        data: Option<String>,
    }

    impl Iterator for SingleThenPanicIter {
        type Item = Result<String, OpaqueError>;

        fn next(&mut self) -> Option<Self::Item> {
            Some(Ok(self.data.take().expect("iterator queried twice")))
        }
    }

    #[test]
    fn pending_stream_results_in_pending_item() {
        let mut ndjson_stream: JsonStream<(), _> =
            JsonStream::new(stream::pending::<Result<&str, OpaqueError>>());

        let mut next = task::spawn(ndjson_stream.next());

        assert_pending!(next.poll());
    }

    #[test]
    fn empty_stream_results_in_empty_results() {
        let collected = tokio_test::block_on(
            JsonStream::<_, _>::new(stream::empty::<Result<&[u8], OpaqueError>>())
                .collect::<Vec<Result<(), OpaqueError>>>(),
        );
        assert!(collected.is_empty());
    }

    #[test]
    fn singleton_iter_with_single_json_line() {
        let stream = stream::once(async { Ok::<_, Infallible>("{\"key\":1,\"value\":2}\n") });

        let collected = tokio_test::block_on(
            JsonStream::<_, _>::new(stream).collect::<Vec<Result<TestStruct, OpaqueError>>>(),
        );

        let mut result = collected.into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 1, value: 2 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn multiple_iter_items_compose_single_json_line() {
        let stream = stream::iter(vec![
            Ok::<_, Infallible>("{\"key\""),
            Ok::<_, Infallible>(":12,"),
            Ok::<_, Infallible>("\"value\""),
            Ok::<_, Infallible>(":34}\n"),
        ]);

        let collected = tokio_test::block_on(
            JsonStream::<_, _>::new(stream).collect::<Vec<Result<TestStruct, OpaqueError>>>(),
        );

        let mut result = collected.into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 12, value: 34 }
        );
        assert!(result.next().is_none());
    }

    #[tokio::test]
    async fn wrapped_stream_not_queried_while_sufficient_data_remains() {
        let iter = SingleThenPanicIter {
            data: Some("{\"key\":0,\"value\":0}\n{\"key\":0,\"value\":0}\n".to_owned()),
        };
        let mut ndjson_stream = JsonStream::<TestStruct, _>::new(stream::iter(iter));

        assert!(ndjson_stream.next().await.is_some());
        assert!(ndjson_stream.next().await.is_some());
    }

    #[tokio::test]
    async fn stream_with_parse_always_config_respects_config() {
        let stream = stream::once(async { Ok::<_, Infallible>("{\"key\":1,\"value\":2}\n\n") });
        let config =
            ParseConfig::default().with_empty_line_handling(EmptyLineHandling::ParseAlways);
        let mut ndjson_stream = pin!(JsonStream::<TestStruct, _>::new_with_config(stream, config));

        assert!(ndjson_stream.next().await.unwrap().is_ok());
        assert!(ndjson_stream.next().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn stream_with_ignore_empty_config_respects_config() {
        let stream = stream::once(async { Ok::<_, Infallible>("{\"key\":1,\"value\":2}\n\n") });
        let config =
            ParseConfig::default().with_empty_line_handling(EmptyLineHandling::IgnoreEmpty);
        let mut ndjson_stream = pin!(JsonStream::<TestStruct, _>::new_with_config(stream, config));

        assert!(ndjson_stream.next().await.unwrap().is_ok());
        assert!(ndjson_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn stream_with_parse_rest_handles_valid_finalization() {
        let stream = stream::once(async { Ok::<_, Infallible>("{\"key\":1,\"value\":2}") });
        let config = ParseConfig::default().with_parse_rest(true);
        let mut ndjson_stream = pin!(JsonStream::<TestStruct, _>::new_with_config(stream, config));

        assert_eq!(
            ndjson_stream.next().await.unwrap().unwrap(),
            TestStruct { key: 1, value: 2 }
        );
        assert!(ndjson_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn stream_with_parse_rest_handles_invalid_finalization() {
        let stream = stream::once(async { Ok::<_, Infallible>("{\"key\":1,") });
        let config = ParseConfig::default().with_parse_rest(true);
        let mut ndjson_stream = pin!(JsonStream::<TestStruct, _>::new_with_config(stream, config));

        assert!(ndjson_stream.next().await.unwrap().is_err());
        assert!(ndjson_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn stream_without_parse_rest_does_not_handle_finalization() {
        let stream = stream::once(async { Ok::<_, Infallible>("some text") });
        let config = ParseConfig::default().with_parse_rest(false);
        let mut ndjson_stream = pin!(JsonStream::<TestStruct, _>::new_with_config(stream, config));

        assert!(ndjson_stream.next().await.is_none());
    }

    #[test]
    fn fallible_stream_operates_correctly_with_interspersed_errors() {
        let data_vec = vec![
            Err(OpaqueError::from_display("test message 1")),
            Ok("invalid json\n{\"key\":11,\"val"),
            Ok("ue\":22}\n{\"key\":33,\"value\":44}\ninvalid json\n"),
            Err(OpaqueError::from_display("test message 2")),
            Ok("{\"key\":55,\"value\":66}\n"),
        ];
        let data_stream = stream::iter(data_vec);
        let fallible_ndjson_stream = JsonStream::<TestStruct, _>::new(data_stream);

        let mut iter = tokio_test::block_on(fallible_ndjson_stream.collect::<Vec<_>>()).into_iter();

        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().unwrap().is_err());
        assert_eq!(
            TestStruct { key: 11, value: 22 },
            iter.next().unwrap().unwrap()
        );
        assert_eq!(
            TestStruct { key: 33, value: 44 },
            iter.next().unwrap().unwrap()
        );
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().unwrap().is_err());
        assert_eq!(
            TestStruct { key: 55, value: 66 },
            iter.next().unwrap().unwrap()
        );
        assert!(iter.next().is_none());
    }
}
