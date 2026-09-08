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
        let locations = entry.metadata_records.read().clone();
        let mut records = Vec::with_capacity(locations.len());
        for location in locations {
            records.push(read_record_at(&entry.collection, location).await?);
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
        use rama_core::futures::StreamExt as _;
        let entry = self.exchange(id)?;
        let locations = match body {
            CapturedBody::Request => entry.request_body_records.read().clone(),
            CapturedBody::Response => entry.response_body_records.read().clone(),
        };
        Ok(stream_fn(move |mut yielder| async move {
            let mut remaining = limit.unwrap_or(u64::MAX);
            for id in locations {
                if remaining == 0 {
                    break;
                }
                let reader = match entry
                    .collection
                    .serve(rama_inspect::storage::ReadRecord {
                        id,
                        range: limit.map(|_| 0..remaining),
                    })
                    .await
                {
                    Ok(reader) => reader,
                    Err(error) => {
                        yielder.yield_item(Err(error)).await;
                        break;
                    }
                };
                let mut stream = rama_core::stream::io::ReaderStream::new(reader);
                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(chunk) => {
                            remaining = remaining.saturating_sub(chunk.len() as u64);
                            yielder.yield_item(Ok(chunk)).await;
                        }
                        Err(error) => {
                            yielder.yield_item(Err(error.into())).await;
                            return;
                        }
                    }
                }
            }
        }))
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
        let details = self.details(id).await?;
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
        let mut body = Vec::new();
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
                    direction,
                    forwarded_headers: Some(headers),
                    ..
                } if direction == "request" => {
                    if let Some((_, _, _, current)) = &mut head {
                        *current = headers;
                    }
                }
                StoredRecord::RequestBody { data } => body.extend_from_slice(&data),
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
                return Err(std::io::Error::other(format!(
                    "captured request ended with {outcome} and cannot be replayed safely"
                ))
                .into());
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
            body: Bytes::from(body),
            metadata: details.metadata,
        })
    }
}
