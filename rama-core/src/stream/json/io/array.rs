use core::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use pin_project_lite::pin_project;
use rama_error::BoxError;
use serde::de::DeserializeOwned;

use crate::{
    futures::{Stream, TryStream, ready},
    stream::json::{ArrayParseConfig, array::JsonArrayEngine},
};

pin_project! {
    /// Decodes one element at a time from a top-level JSON array.
    pub struct JsonArrayReadStream<T, S: TryStream> {
        #[pin]
        source: Option<S>,
        frame: Option<S::Ok>,
        offset: usize,
        engine: JsonArrayEngine,
        config: ArrayParseConfig,
        item: PhantomData<fn() -> T>,
    }
}

impl<T, S: TryStream> JsonArrayReadStream<T, S> {
    /// Reads an array using the default per-element byte limit.
    pub fn new(source: S) -> Self {
        Self::new_with_config(source, ArrayParseConfig::default())
    }

    /// Reads an array using the supplied per-element byte limit.
    pub fn new_with_config(source: S, config: ArrayParseConfig) -> Self {
        Self {
            source: Some(source),
            frame: None,
            offset: 0,
            engine: JsonArrayEngine::default(),
            config,
            item: PhantomData,
        }
    }
}

impl<T, S> Stream for JsonArrayReadStream<T, S>
where
    T: DeserializeOwned,
    S: TryStream<Ok: AsRef<[u8]>, Error: Into<BoxError>>,
{
    type Item = Result<T, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let result = loop {
            if let Some(frame) = this.frame.as_ref() {
                let bytes = frame.as_ref();
                let mut input = &bytes[*this.offset..];
                match this
                    .engine
                    .next(&mut input, this.config.max_element_bytes.get())
                {
                    Ok(Some(value)) => {
                        *this.offset = bytes.len() - input.len();
                        return Poll::Ready(Some(Ok(value)));
                    }
                    Err(err) => break Some(Err(err)),
                    Ok(None) => *this.frame = None,
                }
            }
            let Some(source) = this.source.as_mut().as_pin_mut() else {
                return Poll::Ready(None);
            };
            match ready!(source.try_poll_next(cx)) {
                Some(Ok(frame)) => {
                    *this.frame = Some(frame);
                    *this.offset = 0;
                }
                Some(Err(err)) => break Some(Err(err.into())),
                None => break this.engine.finish().err().map(Err),
            }
        };
        this.source.set(None);
        *this.frame = None;
        *this.engine = JsonArrayEngine::default();
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::futures::{StreamExt, stream};
    use std::{io, num::NonZeroUsize, sync::Arc};

    #[tokio::test]
    async fn limit_error_releases_source_and_ends_stream() {
        let oversized: Arc<[u8]> = Arc::from(b"[1234]".as_slice());
        let reference = Arc::downgrade(&oversized);
        let frames = stream::iter([Ok::<_, io::Error>(oversized)]);
        let config =
            ArrayParseConfig::default().with_max_element_bytes(NonZeroUsize::new(3).unwrap());
        let mut reader = JsonArrayReadStream::<u32, _>::new_with_config(frames, config);
        reader.next().await.unwrap().unwrap_err();
        assert!(reference.upgrade().is_none());
        assert!(reader.next().await.is_none());
    }

    #[tokio::test]
    async fn frames_with_several_elements_match_serde() {
        let doc = br#" [1,"two",{"three":[3]},[],null, -6e1 ] "#;
        let expected = serde_json::from_slice::<Vec<serde_json::Value>>(doc).unwrap();
        for size in 1..=doc.len() {
            let frames = stream::iter(doc.chunks(size).map(Ok::<_, io::Error>));
            let values = JsonArrayReadStream::<serde_json::Value, _>::new(frames)
                .map(Result::unwrap)
                .collect::<Vec<_>>()
                .await;
            assert_eq!(values, expected, "frame size {size}");
        }
    }

    #[tokio::test]
    async fn body_error_after_array_is_terminal() {
        let frames = stream::iter([
            Ok(b"[1]".as_slice()),
            Err(io::Error::other("upstream")),
            Ok(b"[2]"),
        ]);
        let mut reader = JsonArrayReadStream::<u32, _>::new(frames);
        assert_eq!(reader.next().await.unwrap().unwrap(), 1);
        assert_eq!(
            reader.next().await.unwrap().unwrap_err().to_string(),
            "upstream"
        );
        assert!(reader.next().await.is_none());
    }
}
