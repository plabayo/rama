use pin_project_lite::pin_project;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_core::futures::stream::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
pub(super) struct Utf8Stream<S> {
    #[pin]
    stream: S,
    buffer: Vec<u8>,
    terminated: bool,
}
}

impl<S> Utf8Stream<S> {
    pub(super) fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
            terminated: false,
        }
    }
}

impl<S, B, E> Stream for Utf8Stream<S>
where
    S: Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
    E: Into<BoxError>,
{
    type Item = Result<String, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if *this.terminated {
            return Poll::Ready(None);
        }
        match this.stream.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                this.buffer.extend_from_slice(bytes.as_ref());
                let bytes = core::mem::take(this.buffer);
                match String::from_utf8(bytes) {
                    Ok(string) => Poll::Ready(Some(Ok(string))),
                    Err(err) => {
                        let valid_size = err.utf8_error().valid_up_to();
                        let mut bytes = err.into_bytes();
                        let rem = bytes.split_off(valid_size);
                        *this.buffer = rem;
                        Poll::Ready(Some(Ok(unsafe { String::from_utf8_unchecked(bytes) })))
                    }
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.context("utf8 error")))),
            Poll::Ready(None) => {
                *this.terminated = true;
                if this.buffer.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(
                        String::from_utf8(core::mem::take(this.buffer)).context("utf8 eror"),
                    ))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use rama_core::futures::prelude::*;

    #[tokio::test]
    async fn valid_streams() {
        assert_eq!(
            Utf8Stream::new(stream::iter(vec![Ok::<_, Infallible>(b"Hello, world!")]))
                .try_collect::<Vec<_>>()
                .await
                .unwrap(),
            vec!["Hello, world!"]
        );
        assert_eq!(
            Utf8Stream::new(stream::iter(vec![Ok::<_, Infallible>("Hello, world!")]))
                .try_collect::<Vec<_>>()
                .await
                .unwrap(),
            vec!["Hello, world!"]
        );
        assert_eq!(
            Utf8Stream::new(stream::iter(vec![Ok::<_, Infallible>("")]))
                .try_collect::<Vec<_>>()
                .await
                .unwrap(),
            vec![""]
        );
        assert_eq!(
            Utf8Stream::new(stream::iter(vec![
                Ok::<_, Infallible>("Hello"),
                Ok::<_, Infallible>(", world!")
            ]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec!["Hello", ", world!"]
        );
        assert_eq!(
            Utf8Stream::new(stream::iter(vec![Ok::<_, Infallible>(vec![
                240, 159, 145, 141
            ]),]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec!["👍"]
        );
        assert_eq!(
            Utf8Stream::new(stream::iter(vec![
                Ok::<_, Infallible>(vec![240, 159]),
                Ok::<_, Infallible>(vec![145, 141])
            ]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec!["", "👍"]
        );
        assert_eq!(
            Utf8Stream::new(stream::iter(vec![
                Ok::<_, Infallible>(vec![240, 159]),
                Ok::<_, Infallible>(vec![145, 141, 240, 159, 145, 141])
            ]))
            .try_collect::<Vec<_>>()
            .await
            .unwrap(),
            vec!["", "👍👍"]
        );
    }

    #[tokio::test]
    async fn invalid_streams() {
        let results = Utf8Stream::new(stream::iter(vec![Ok::<_, Infallible>(vec![240, 159])]))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_deref().unwrap(), "");
        assert!(results[1].is_err());
        let results = Utf8Stream::new(stream::iter(vec![
            Ok::<_, Infallible>(vec![240, 159]),
            Ok::<_, Infallible>(vec![145, 141, 240, 159, 145]),
        ]))
        .collect::<Vec<_>>()
        .await;
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].as_deref().unwrap(), "".to_owned());
        assert_eq!(results[1].as_deref().unwrap(), "👍".to_owned());
        assert!(results[2].is_err());
    }
}
