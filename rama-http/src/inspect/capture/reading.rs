use rama_core::{
    error::{BoxErrorExt as _, ErrorExt as _},
    futures::{StreamExt, async_stream::stream_fn},
    stream::io::ReaderStream,
};

use rama_inspect::Direction;

use super::*;

impl CaptureStore {
    pub async fn details(&self, id: u64) -> Result<CaptureDetails, BoxError> {
        let entry = self.exchange(id)?;
        self.details_for_entry(entry).await
    }

    pub(super) async fn details_for_entry(
        &self,
        entry: Arc<CapturedExchange>,
    ) -> Result<CaptureDetails, BoxError> {
        let summary = entry.snapshot();
        let records = self.read_records(&entry).await?;
        Ok(CaptureDetails {
            summary,
            records,
            metadata: entry.metadata.clone(),
            connection: entry.connection.as_ref().map(|c| c.snapshot()),
        })
    }

    pub async fn inspector_details(&self, id: u64) -> Result<CaptureDetails, BoxError> {
        self.exchange_capture(id)?.inspector_details().await
    }

    pub(super) async fn inspector_details_for_entry(
        &self,
        entry: &CapturedExchange,
    ) -> Result<CaptureDetails, BoxError> {
        let mut locations = entry.metadata_records.read().clone();
        locations.extend(*entry.replay_record.read());
        let mut records = Vec::with_capacity(locations.len());
        for location in locations {
            records.push(metadata::read(&entry.collection, location, Some(0)).await?);
        }
        Ok(CaptureDetails {
            summary: entry.snapshot(),
            records,
            metadata: entry.metadata.clone(),
            connection: entry.connection.as_ref().map(|c| c.snapshot()),
        })
    }

    /// Stream logical body bytes directly from storage. A range-limited backend
    /// can avoid reading bytes beyond a preview; no JSON or base64 decoding occurs.
    pub async fn body_stream(
        &self,
        id: u64,
        body: CapturedBody,
        limit: Option<u64>,
    ) -> Result<impl Stream<Item = Result<Bytes, BoxError>> + Send + 'static, BoxError> {
        Ok(self.exchange_capture(id)?.body_source(body).stream(limit))
    }

    pub(super) fn exchange(&self, id: u64) -> Result<Arc<CapturedExchange>, BoxError> {
        self.0
            .exchanges
            .read()
            .entries
            .get(&id)
            .cloned()
            .context("capture not found")
    }

    pub(super) async fn read_records(
        &self,
        entry: &CapturedExchange,
    ) -> Result<Vec<StoredRecord>, BoxError> {
        #[cfg(test)]
        self.0.record_reads.fetch_add(1, Ordering::Relaxed);
        let locations = entry.records.read().clone();
        let mut records = Vec::with_capacity(locations.len());
        for location in locations {
            records.push(read_record_at(&entry.collection, location).await?);
        }
        Ok(records)
    }

    pub async fn replay_request(&self, id: u64) -> Result<ReplayRequest, BoxError> {
        let capture = self.exchange_capture(id)?;
        let details = capture.inspector_details().await?;
        if details.summary.active {
            return Err(std::io::Error::other(
                "active captures cannot be replayed before the exchange completes",
            )
            .into());
        }
        if details.summary.request_truncated {
            return Err(std::io::Error::other(
                "captured request body was truncated and cannot be replayed safely",
            )
            .into());
        }
        let mut head = None;
        let mut request_end = None;
        let mut request_trailers = false;
        for record in details.records {
            match record {
                StoredRecord::RequestHead {
                    method,
                    url,
                    version,
                    headers,
                    ..
                } => head = Some((method, url, version, headers)),
                StoredRecord::Interception {
                    kind: None,
                    direction: Direction::Ingress,
                    forwarded_headers: Some(headers),
                    ..
                } => {
                    if let Some((_, _, _, current)) = &mut head {
                        *current = headers;
                    }
                }
                StoredRecord::RequestTrailers { .. } => request_trailers = true,
                StoredRecord::RequestEnd { outcome } if request_end.replace(outcome).is_some() => {
                    return Err(std::io::Error::other(
                        "captured request has multiple completion records",
                    )
                    .into());
                }
                _ => {}
            }
        }
        match request_end {
            Some(CaptureOutcome::Complete) => {}
            Some(outcome) => {
                return Err(BoxError::from_static_str(
                    "captured request cannot be replayed safely",
                )
                .context_field("outcome", outcome));
            }
            None => {
                return Err(
                    std::io::Error::other("captured request completion record missing").into(),
                );
            }
        }
        if request_trailers {
            return Err(std::io::Error::other(
                "captured request trailers cannot be replayed safely",
            )
            .into());
        }
        let (method, mut url, version, headers) = head.context("captured request head missing")?;
        if url.scheme().is_none() && url.authority().is_none() {
            let endpoint = details
                .summary
                .endpoint
                .clone()
                .context("captured request authority missing")?;
            url = url
                .with_scheme(details.summary.protocol.clone())
                .with_authority(endpoint);
        }
        Ok(ReplayRequest {
            method,
            url,
            version,
            protocol: details.summary.protocol,
            headers,
            body: capture.body_source(CapturedBody::Request),
            metadata: details.metadata,
        })
    }
}

impl ExchangeCapture {
    /// Read only the original request head; body and subsequent decision records are untouched.
    pub async fn request_head(&self) -> Result<Option<StoredRecord>, BoxError> {
        let first = self.entry.metadata_records.read().first().copied();
        match first {
            Some(location) => Ok(Some(
                read_record_at(&self.entry.collection, location).await?,
            )),
            None => Ok(None),
        }
    }

    /// Stream a pinned record prefix. Body records may be split into smaller
    /// chunks; metadata ordering and the concatenated body bytes are preserved.
    pub fn records_stream(
        &self,
    ) -> impl Stream<Item = Result<StoredRecord, BoxError>> + Send + 'static + use<> {
        let capture = self.clone();
        let count = capture.entry.records.read().len();
        stream_fn(move |mut output| async move {
            let result = async {
                for index in 0..count {
                    let location = capture.entry.records.read()[index];
                    match location.body {
                        Some(body) => {
                            let mut stream = ReaderStream::new(
                                capture.entry.collection.read(location.id).await?,
                            );
                            while let Some(data) = stream.next().await {
                                let data = data?;
                                output
                                    .yield_item(Ok(match body {
                                        CapturedBody::Request => StoredRecord::RequestBody { data },
                                        CapturedBody::Response => {
                                            StoredRecord::ResponseBody { data }
                                        }
                                    }))
                                    .await;
                            }
                        }
                        None => {
                            output
                                .yield_item(Ok(
                                    read_record_at(&capture.entry.collection, location).await?
                                ))
                                .await
                        }
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
