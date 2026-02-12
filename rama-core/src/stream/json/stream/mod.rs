pub(super) mod read;
pub(super) mod write;

#[cfg(test)]
mod tests {
    use crate::futures::StreamExt as _;
    use crate::futures::stream;
    use rama_error::BoxError;
    use std::convert::Infallible;
    use tokio_test::{assert_pending, block_on, task};

    use super::read::*;
    use super::write::*;

    #[test]
    fn write_read_pending() {
        let mut ndjson_stream: JsonReadStream<u32, _> = JsonReadStream::new(JsonWriteStream::new(
            stream::pending::<Result<u32, BoxError>>(),
        ));

        let mut next = task::spawn(ndjson_stream.next());

        assert_pending!(next.poll());
    }

    #[test]
    fn write_read_pending_empty() {
        let collected: Vec<Result<u32, BoxError>> = block_on(
            JsonReadStream::new(JsonWriteStream::new(
                stream::empty::<Result<u32, BoxError>>(),
            ))
            .collect::<Vec<Result<u32, BoxError>>>(),
        );
        assert!(collected.is_empty());
    }

    #[test]
    fn write_read_once() {
        let stream = stream::once(std::future::ready(1u32)).map(Ok::<_, Infallible>);

        let collected = tokio_test::block_on(
            JsonReadStream::new(JsonWriteStream::new(stream))
                .collect::<Vec<Result<u32, BoxError>>>(),
        );

        let mut result = collected.into_iter();
        assert_eq!(result.next().unwrap().unwrap(), 1);
        assert!(result.next().is_none());
    }

    #[test]
    fn write_read_twice() {
        let stream = stream::iter([4u32, 2u32]).map(Ok::<_, Infallible>);

        let collected = tokio_test::block_on(
            JsonReadStream::new(JsonWriteStream::new(stream))
                .collect::<Vec<Result<u32, BoxError>>>(),
        );

        let mut result = collected.into_iter();
        assert_eq!(result.next().unwrap().unwrap(), 4);
        assert_eq!(result.next().unwrap().unwrap(), 2);
        assert!(result.next().is_none());
    }
}
