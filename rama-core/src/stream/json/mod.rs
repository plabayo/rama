//! ndjson support in rama
//!
//! Newline Delimited Json streams.
//!
//! Use SSE If you can, ndjson if you must.

mod config;
pub use config::{EmptyLineHandling, ParseConfig};

mod engine;
mod stream;

pub use stream::read::JsonReadStream;
pub use stream::write::JsonWriteStream;

mod codec;
pub use codec::{JsonDecoder, JsonEncoder};

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;

    use crate::futures::{StreamExt, stream::once};
    use serde::Deserialize;

    #[tokio::test]
    async fn test_json_stream_simple() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Data {
            bar: String,
        }

        for (index, input) in [
            "{\"bar\":\"foo\"}\n{\"bar\":\"qux\"}\n{\"bar\":\"baz\"}",
            "{\"bar\": \"foo\"}\n{\"bar\": \"qux\"}\n{\"bar\": \"baz\"}",
            "{\"bar\":\"foo\"}\n{\"bar\":\"qux\"}\n{\"bar\":\"baz\"}\n",
            "{\"bar\": \"foo\"}\n{\"bar\": \"qux\"}\n{\"bar\": \"baz\"}\n",
        ]
        .into_iter()
        .enumerate()
        {
            let mut stream =
                JsonReadStream::new(Box::pin(once(async { Ok::<_, Infallible>(input) })));

            for expected in ["foo", "qux", "baz"] {
                assert_eq!(
                    Some(Some(Data {
                        bar: expected.to_owned()
                    })),
                    stream.next().await.map(|e| e.ok()),
                    "#{}, input: {input}",
                    index + 1,
                );
            }

            assert!(stream.next().await.is_none());
        }
    }
}
