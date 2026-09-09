use rama_net::ProtocolInputExt as _;

use super::*;
use crate::headers::{HeaderMapExt as _, Host as HostHeader};

impl CaptureStore {
    pub(super) fn try_reserve_exchange(&self) -> Option<CaptureExchangeAdmission<'_>> {
        loop {
            let pending = self.0.pending_exchanges.load(Ordering::Acquire);
            let retained = {
                let mut exchanges = self.0.exchanges.write();
                while exchanges.order.len().saturating_add(pending) >= self.0.max_exchanges {
                    let remove =
                        exchanges
                            .order
                            .iter()
                            .copied()
                            .enumerate()
                            .find_map(|(index, id)| {
                                let active = exchanges
                                    .entries
                                    .get(&id)
                                    .is_some_and(|entry| entry.active.load(Ordering::Relaxed));
                                (!active).then_some((index, id))
                            });
                    let Some((index, id)) = remove else { break };
                    exchanges.order.remove(index);
                    drop(exchanges.entries.remove(&id));
                }
                exchanges.entries.len()
            };
            if retained.saturating_add(pending) >= self.0.max_exchanges {
                return None;
            }
            if self
                .0
                .pending_exchanges
                .compare_exchange_weak(
                    pending,
                    pending.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(CaptureExchangeAdmission {
                    pending: &self.0.pending_exchanges,
                });
            }
        }
    }

    pub(super) async fn begin_exchange(
        &self,
        parts: &crate::request::Parts,
    ) -> Result<Option<u64>, BoxError> {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return Ok(None);
        };
        let Some(_admission) = self.try_reserve_exchange() else {
            return Ok(None);
        };
        let generation = self.0.generation.load(Ordering::Acquire);
        let id = self.0.next_exchange_id.fetch_add(1, Ordering::Relaxed);
        let connection_id = parts
            .extensions
            .get_ref::<ConnectionId>()
            .map(|id| id.0)
            .unwrap_or_default();
        let connection = (connection_id != 0)
            .then(|| {
                self.0
                    .connections
                    .read()
                    .entries
                    .get(&connection_id)
                    .cloned()
            })
            .flatten();
        let protocol = parts.protocol().unwrap_or(&Protocol::HTTP);
        let mut metadata = CaptureMetadata::default();
        if let Some(connection) = &connection {
            metadata.connection.clone_from(&connection.metadata);
        }
        self.0.observer.request(parts, &metadata);
        // Protocol owners may label an application carried by an HTTP handshake
        // (e.g. WebSocket). Transport resolution above uses the usual InputExt.
        let protocol = metadata
            .exchange
            .get_ref::<Protocol>()
            .unwrap_or(protocol)
            .clone();
        let user_agent = parts.headers.get(crate::header::USER_AGENT).cloned();
        let ja4h = metadata.request_fingerprint(parts);
        if let Some(connection) = &connection
            && let Ok(fingerprint) = AkamaiH2::compute(&parts.extensions)
        {
            _ = connection.akamai_h2.set(fingerprint);
        }
        let endpoint = parts
            .uri
            .authority()
            .map(|authority| authority.into_owned())
            .or_else(|| {
                parts
                    .headers
                    .typed_get::<HostHeader>()
                    .map(|host| host.0.into())
            });
        let (collection, writer) = self
            .0
            .storage
            .serve(CreateCollection { id })
            .await
            .context("create capture collection")?
            .split();
        let entry = Arc::new(CapturedExchange {
            decision: RwLock::new(None),
            decision_count: AtomicUsize::new(0),
            summary_template: HttpExchangeSummary {
                decision: None,
                id,
                connection_id,
                connection_display_id: connection
                    .as_ref()
                    .and_then(|connection| connection.display_id.get().copied())
                    .unwrap_or_default(),
                started_at: jiff::Timestamp::now(),
                method: parts.method.clone(),
                http_version: parts.version,
                url: parts.uri.clone(),
                endpoint,
                protocol,
                user_agent,
                status: None,
                active: true,
                response_started_at: None,
                completed_at: None,
                request_bytes: 0,
                response_bytes: 0,
                request_truncated: false,
                response_truncated: false,
                ja4h,
                metadata: metadata.clone(),
            },
            metadata,
            connection,
            status: AtomicU16::new(0),
            active: AtomicBool::new(true),
            upgraded: is_upgrade_request(parts),
            upgrade_lifecycle_started: AtomicBool::new(false),
            response_started_at: OnceLock::new(),
            completed_at: OnceLock::new(),
            request_bytes: AtomicU64::new(0),
            response_bytes: AtomicU64::new(0),
            request_truncated: AtomicBool::new(false),
            response_truncated: AtomicBool::new(false),
            extensions: Extensions::default(),
            extension_records: RwLock::new(BTreeMap::new()),
            collection,
            writer: Mutex::new(writer),
            searches: SyncMutex::default(),
            records: RwLock::new(Vec::new()),
            metadata_records: RwLock::new(Vec::new()),
            message_decisions: RwLock::new(Vec::new()),
            replay_record: RwLock::new(None),
            request_body_records: RwLock::new(Vec::new()),
            response_body_records: RwLock::new(Vec::new()),
            request_stored: AtomicU64::new(0),
            response_stored: AtomicU64::new(0),
            budget: self.0.budget.clone(),
            stored_bytes: AtomicU64::new(0),
            stored_records: AtomicU64::new(0),
        });
        let request_head = self
            .append(
                id,
                &entry,
                StoredRecord::RequestHead {
                    method: parts.method.clone(),
                    url: parts.uri.clone(),
                    version: parts.version,
                    headers: parts.headers.clone(),
                },
            )
            .await;
        if !matches!(&request_head, Ok(true)) {
            drop(entry);
            if let Err(error) = request_head {
                rama_core::telemetry::tracing::debug!("failed to start request capture: {error}");
            }
            return Ok(None);
        }
        {
            let mut exchanges = self.0.exchanges.write();
            if self.0.generation.load(Ordering::Acquire) != generation {
                drop(exchanges);
                drop(entry);
                return Ok(None);
            }
            exchanges.entries.insert(id, entry.clone());
            exchanges.order.push_back(id);
        }
        if let Some(connection) = &entry.connection {
            self.confirm_connection_entry(connection);
            _ = connection.request_count.try_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_add(1)),
            );
            self.trim_connections();
        }
        self.trim_exchanges();
        self.changed();
        Ok(Some(id))
    }

    pub(super) fn trim_exchanges(&self) {
        let mut exchanges = self.0.exchanges.write();
        loop {
            if exchanges.order.len() <= self.0.max_exchanges {
                break;
            }
            let remove = exchanges
                .order
                .iter()
                .copied()
                .enumerate()
                .find_map(|(index, id)| {
                    let active = match exchanges.entries.get(&id) {
                        Some(entry) => entry.active.load(Ordering::Relaxed),
                        None => false,
                    };
                    (!active).then_some((index, id))
                });
            let Some((index, id)) = remove else { break };
            exchanges.order.remove(index);
            // Release the registry reference. Storage remains alive while an
            // active reader or export still owns this exchange.
            drop(exchanges.entries.remove(&id));
        }
    }

    pub(super) async fn response_head(
        &self,
        id: u64,
        parts: &crate::response::Parts,
    ) -> Result<(), BoxError> {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return Ok(());
        };
        let entry = self.0.exchanges.read().entries.get(&id).cloned();
        if let Some(entry) = entry {
            self.0.observer.response(parts, &entry.metadata);
            entry.status.store(parts.status.as_u16(), Ordering::Relaxed);
            _ = entry.response_started_at.set(jiff::Timestamp::now());
            if let Some(socket) = parts.extensions.get_ref::<SocketInfo>()
                && !entry.metadata.upstream.contains::<SocketInfo>()
            {
                entry.metadata.upstream.insert(socket.clone());
            }
            if !self
                .append(
                    id,
                    &entry,
                    StoredRecord::ResponseHead {
                        status: parts.status,
                        version: parts.version,
                        headers: parts.headers.clone(),
                    },
                )
                .await?
            {
                mark_capture_gap_entry(&entry, BodyDirection::Response);
            }
            self.changed();
        }
        Ok(())
    }

    pub async fn record_decision(
        &self,
        id: u64,
        original: &crate::inspect::control::Message,
        outcome: &str,
        headers: Option<&HeaderMap>,
    ) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return;
        };
        let entry = self.0.exchanges.read().entries.get(&id).cloned();
        if let Some(entry) = entry {
            if entry
                .decision_count
                .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < self.0.max_decisions).then(|| count + 1)
                })
                .is_err()
            {
                return;
            }
            *entry.decision.write() = Some(outcome.into());
            let record = StoredRecord::Interception {
                kind: original.kind.clone(),
                direction: original.direction,
                outcome: outcome.into(),
                original_headers: original.headers.clone(),
                original_status: original.status,
                original_payload: original.payload.clone(),
                original_payload_length: original
                    .payload
                    .as_ref()
                    .map(|payload| payload.len() as u64),
                forwarded_headers: headers.cloned(),
            };
            if !matches!(self.append(id, &entry, record).await, Ok(true)) {
                // Forwarding may have used edited data. Do not present an older
                // stored head/body as a complete replayable capture.
                entry.request_truncated.store(true, Ordering::Release);
                entry.response_truncated.store(true, Ordering::Release);
            }
            self.changed();
        }
    }

    pub(super) async fn append(
        &self,
        _id: u64,
        entry: &CapturedExchange,
        mut record: StoredRecord,
    ) -> Result<bool, BoxError> {
        let (source, length, body) = match &mut record {
            StoredRecord::RequestBody { data } => (
                AppendRecord::bytes(data.clone()),
                data.len() as u64,
                Some(CapturedBody::Request),
            ),
            StoredRecord::ResponseBody { data } => (
                AppendRecord::bytes(data.clone()),
                data.len() as u64,
                Some(CapturedBody::Response),
            ),
            _ => {
                let payload = match &mut record {
                    StoredRecord::Interception {
                        original_payload: Some(payload),
                        ..
                    } => payload.replace_bytes(Bytes::new()),
                    _ => Bytes::new(),
                };
                let (source, length) = attachment::encode_parts(&record, payload)?;
                (source, length, None)
            }
        };
        let Some(mut budget) = self.0.budget.try_reserve(length) else {
            return Ok(false);
        };
        let writer = entry.writer.lock().await;
        // HTTP has a small fixed set of heads/trailers/end records. Upgraded
        // message decisions and replay history use separate indexes.
        if metadata::is_http_metadata(&record)
            && entry.metadata_records.read().len() >= metadata::MAX_HTTP_RECORDS
        {
            return Ok(false);
        }

        #[cfg(test)]
        if let Some(hook) = self.0.append_test_hook.lock().await.take() {
            hook.reached.notify_one();
            hook.resume.notified().await;
        }
        let location = writer.serve(source).await?;
        // Publish all indexes together, without an await after storage commits.
        let record_location = RecordLocation { id: location, body };
        entry.records.write().push(record_location);
        match &record {
            StoredRecord::RequestBody { .. } => entry.request_body_records.write().push(location),
            StoredRecord::ResponseBody { .. } => {
                entry.response_body_records.write().push(location);
            }
            StoredRecord::Interception { kind, .. } => {
                if kind.is_some() {
                    entry.message_decisions.write().push(record_location);
                } else {
                    entry.metadata_records.write().push(record_location);
                }
            }
            StoredRecord::ReplayResult { .. } => {
                *entry.replay_record.write() = Some(record_location)
            }
            StoredRecord::RequestHead { .. }
            | StoredRecord::RequestTrailers { .. }
            | StoredRecord::RequestEnd { .. }
            | StoredRecord::ResponseHead { .. }
            | StoredRecord::ResponseTrailers { .. }
            | StoredRecord::ResponseEnd { .. } => {
                entry.metadata_records.write().push(record_location)
            }
        }
        budget.commit(entry);
        Ok(true)
    }

    pub(super) async fn body_event(
        &self,
        id: u64,
        direction: BodyDirection,
        event: BodyCaptureEvent,
    ) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            if matches!(event, BodyCaptureEvent::Frame(_)) {
                self.mark_capture_gap(id, direction);
            }
            if direction == BodyDirection::Response && matches!(event, BodyCaptureEvent::End(_)) {
                let upgrade_lifecycle_started = self
                    .0
                    .exchanges
                    .read()
                    .entries
                    .get(&id)
                    .is_some_and(|entry| entry.upgrade_lifecycle_started.load(Ordering::Acquire));
                if !upgrade_lifecycle_started {
                    self.finish_http_exchange(id);
                }
            }
            return;
        };
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        match event {
            BodyCaptureEvent::Frame(frame) => match frame.into_data() {
                Ok(data) => {
                    let len = data.len() as u64;
                    let stored = match direction {
                        BodyDirection::Request => entry
                            .request_stored
                            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                                Some(current.saturating_add(len).min(self.0.body_limit))
                            })
                            .unwrap_or_default(),
                        BodyDirection::Response => entry
                            .response_stored
                            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                                Some(current.saturating_add(len).min(self.0.body_limit))
                            })
                            .unwrap_or_default(),
                    };
                    let remaining = usize::try_from(self.0.body_limit.saturating_sub(stored))
                        .unwrap_or(usize::MAX);
                    let captured = data.slice(..data.len().min(remaining));
                    if !captured.is_empty() {
                        let record = match direction {
                            BodyDirection::Request => StoredRecord::RequestBody {
                                data: captured.clone(),
                            },
                            BodyDirection::Response => StoredRecord::ResponseBody {
                                data: captured.clone(),
                            },
                        };
                        let mut append_guard = CaptureAppendGuard::new(entry.clone(), direction);
                        match self.append(id, &entry, record).await {
                            Ok(true) => append_guard.commit(),
                            Ok(false) => {}
                            Err(error) => rama_core::telemetry::tracing::debug!(
                                "failed to append captured body data: {error}"
                            ),
                        }
                    }
                    match direction {
                        BodyDirection::Request => {
                            saturating_add(&entry.request_bytes, len);
                            if captured.len() < data.len() {
                                entry.request_truncated.store(true, Ordering::Relaxed);
                            }
                        }
                        BodyDirection::Response => {
                            saturating_add(&entry.response_bytes, len);
                            if captured.len() < data.len() {
                                entry.response_truncated.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                    if let Some(connection) = &entry.connection {
                        match direction {
                            BodyDirection::Request => saturating_add(&connection.bytes_in, len),
                            BodyDirection::Response => saturating_add(&connection.bytes_out, len),
                        }
                    }
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        let record = match direction {
                            BodyDirection::Request => StoredRecord::RequestTrailers {
                                headers: trailers.clone(),
                            },
                            BodyDirection::Response => StoredRecord::ResponseTrailers {
                                headers: trailers.clone(),
                            },
                        };
                        let mut append_guard = CaptureAppendGuard::new(entry.clone(), direction);
                        match self.append(id, &entry, record).await {
                            Ok(true) => append_guard.commit(),
                            Ok(false) => {}
                            Err(error) => rama_core::telemetry::tracing::debug!(
                                "failed to append captured body trailers: {error}"
                            ),
                        }
                    }
                }
            },
            BodyCaptureEvent::End(outcome) => {
                let record = match direction {
                    BodyDirection::Request => StoredRecord::RequestEnd { outcome },
                    BodyDirection::Response => StoredRecord::ResponseEnd { outcome },
                };
                let mut append_guard = CaptureAppendGuard::new(entry.clone(), direction);
                match self.append(id, &entry, record).await {
                    Ok(true) => append_guard.commit(),
                    Ok(false) => {}
                    Err(error) => rama_core::telemetry::tracing::debug!(
                        "failed to append captured body outcome: {error}"
                    ),
                }
                if direction == BodyDirection::Response
                    && !entry.upgrade_lifecycle_started.load(Ordering::Acquire)
                {
                    self.finish_http_exchange_entry(&entry);
                }
            }
        }
        self.changed();
    }

    pub(super) fn finish_http_exchange(&self, id: u64) {
        let entry = self.0.exchanges.read().entries.get(&id).cloned();
        if let Some(entry) = entry {
            self.finish_http_exchange_entry(&entry);
            self.changed();
        }
    }

    pub(super) fn finish_http_exchange_entry(&self, entry: &CapturedExchange) {
        if entry.active.swap(false, Ordering::Relaxed) {
            _ = entry.completed_at.set(jiff::Timestamp::now());
            self.trim_exchanges();
        }
    }

    pub(super) fn mark_capture_gap(&self, id: u64, direction: BodyDirection) {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        mark_capture_gap_entry(&entry, direction);
    }

    pub async fn record_replay_result(&self, id: u64, result: Result<StatusCode, String>) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return;
        };
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        let record = match result {
            Ok(status) => StoredRecord::ReplayResult {
                status: Some(status),
                error: None,
            },
            Err(error) => StoredRecord::ReplayResult {
                status: None,
                error: Some(error),
            },
        };
        if let Err(error) = self.append(id, &entry, record).await {
            rama_core::telemetry::tracing::debug!("failed to append replay result: {error}");
        }
        self.changed();
    }
}
