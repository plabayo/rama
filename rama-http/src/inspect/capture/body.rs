use std::sync::Arc;

use rama_core::{
    Service,
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, StreamExt, async_stream::stream_fn},
    stream::io::{ReaderStream, StreamReader},
};
use rama_inspect::storage::{ReadRecord, Reader};

use super::{CapturedBody, CapturedExchange, ExchangeCapture};

/// Pins the currently committed HTTP body records. Reopening this view always
/// yields the same prefix, even during capture, eviction or clearing the inspector.
#[derive(Clone)]
pub struct CapturedBodySource {
    entry: Arc<CapturedExchange>,
    body: CapturedBody,
    count: usize,
}

impl std::fmt::Debug for CapturedBodySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedBodySource")
            .field("body", &self.body)
            .field("records", &self.count)
            .finish_non_exhaustive()
    }
}

impl ExchangeCapture {
    pub fn body_source(&self, body: CapturedBody) -> CapturedBodySource {
        let count = match body {
            CapturedBody::Request => self.entry.request_body_records.read().len(),
            CapturedBody::Response => self.entry.response_body_records.read().len(),
        };
        CapturedBodySource {
            entry: self.entry.clone(),
            body,
            count,
        }
    }
}

impl CapturedBodySource {
    pub fn reader(&self) -> Reader {
        Box::pin(StreamReader::new(Box::pin(
            self.stream(None)
                .map(|chunk| chunk.map_err(std::io::Error::other)),
        )))
    }

    pub fn stream(
        &self,
        limit: Option<u64>,
    ) -> impl Stream<Item = Result<Bytes, BoxError>> + Send + 'static + use<> {
        let source = self.clone();
        stream_fn(move |mut output| async move {
            let result = async {
                let mut remaining = limit.unwrap_or(u64::MAX);
                for index in 0..source.count {
                    if remaining == 0 {
                        break;
                    }
                    let id = match source.body {
                        CapturedBody::Request => source.entry.request_body_records.read()[index],
                        CapturedBody::Response => source.entry.response_body_records.read()[index],
                    };
                    let reader = source
                        .entry
                        .collection
                        .serve(ReadRecord {
                            id,
                            range: limit.map(|_| 0..remaining),
                        })
                        .await?;
                    let mut stream = ReaderStream::new(reader);
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        remaining = remaining.saturating_sub(chunk.len() as u64);
                        output.yield_item(Ok(chunk)).await;
                    }
                }
                Ok::<(), BoxError>(())
            }
            .await;
            if let Err(error) = result {
                output.yield_item(Err(error)).await;
            }
        })
    }
}
