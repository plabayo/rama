//! Streaming readers for JSON arrays and newline-delimited JSON.

mod array;
mod config;
pub use config::{
    ArrayParseConfig, DEFAULT_MAX_ELEMENT_BYTES, DEFAULT_MAX_LINE_BYTES, EmptyLineHandling,
    ParseConfig,
};

mod engine;

mod io;
pub use io::array::JsonArrayReadStream;
pub use io::read::JsonReadStream;
pub use io::write::JsonWriteStream;

mod codec;
pub use codec::{JsonDecoder, JsonEncoder};

#[cfg(test)]
mod tests {
    use super::*;

    use core::convert::Infallible;

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
