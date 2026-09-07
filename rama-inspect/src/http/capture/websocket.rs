use super::*;

impl CaptureStore {
    pub async fn record_websocket_message(
        &self,
        id: u64,
        direction: String,
        kind: String,
        data: Vec<u8>,
        close_code: Option<u16>,
    ) {
        self.record_websocket_message_inner(
            id,
            direction,
            kind,
            data,
            close_code,
            WebSocketMessageOrigin::Peer,
        )
        .await;
    }

    async fn record_websocket_message_inner(
        &self,
        id: u64,
        direction: String,
        kind: String,
        data: Vec<u8>,
        close_code: Option<u16>,
        origin: WebSocketMessageOrigin,
    ) {
        let body_direction = if direction.eq_ignore_ascii_case("ingress") {
            BodyDirection::Request
        } else {
            BodyDirection::Response
        };
        let Some(_permit) = self.0.inspection.try_capture() else {
            if let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() {
                mark_capture_gap_entry(&entry, body_direction);
                self.changed();
            }
            return;
        };
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        match body_direction {
            BodyDirection::Request => saturating_add(&entry.request_bytes, len),
            BodyDirection::Response => saturating_add(&entry.response_bytes, len),
        }
        if let Some(connection) = &entry.connection {
            match body_direction {
                BodyDirection::Request => saturating_add(&connection.bytes_in, len),
                BodyDirection::Response => saturating_add(&connection.bytes_out, len),
            }
        }
        if entry.websocket_truncated.load(Ordering::Acquire) {
            self.changed();
            return;
        }

        let counter = match body_direction {
            BodyDirection::Request => &entry.request_stored,
            BodyDirection::Response => &entry.response_stored,
        };
        if !reserve_capture_bytes(counter, self.0.body_limit, len) {
            mark_websocket_capture_gap_entry(&entry);
            self.changed();
            return;
        }
        if entry
            .websocket_stored
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.0.max_websocket_messages).then(|| current + 1)
            })
            .is_err()
        {
            mark_websocket_capture_gap_entry(&entry);
            self.changed();
            return;
        }

        let record = StoredRecord::WebSocketMessage {
            at: jiff::Timestamp::now().to_string(),
            direction,
            kind,
            data: BASE64.encode(&data),
            close_code,
            replayed: matches!(origin, WebSocketMessageOrigin::Replay),
            injected: matches!(origin, WebSocketMessageOrigin::Injected),
        };
        let mut append_guard = CaptureWebSocketAppendGuard::new(entry.clone());
        match self.append(id, &entry, &record).await {
            Ok(true) => append_guard.commit(),
            Ok(false) => {}
            Err(error) => rama_core::telemetry::tracing::debug!(
                "failed to append captured WebSocket message: {error}"
            ),
        }
        self.changed();
    }

    #[cfg(feature = "websocket")]
    pub fn register_websocket_injector(&self, id: u64, injector: WebSocketRelayInjector) {
        if !injector.is_open() {
            return;
        }
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        let mut current = entry.websocket_injector.write();
        let replace = current.is_none();
        if replace {
            *current = Some(injector);
        }
        drop(current);
        if replace {
            entry.active.store(true, Ordering::Relaxed);
            self.changed();
        }
    }

    #[cfg(feature = "websocket")]
    pub async fn replay_websocket_message(
        &self,
        id: u64,
        message_index: usize,
    ) -> Result<(), WebSocketReplayError> {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return Err(WebSocketReplayError::CaptureNotFound);
        };
        let location = entry
            .websocket_records
            .read()
            .get(message_index)
            .copied()
            .ok_or(WebSocketReplayError::MessageNotFound)?;
        let reader = entry.collection.clone();
        let record = read_record_at(&reader, location)
            .await
            .map_err(WebSocketReplayError::InvalidCapture)?;
        let StoredRecord::WebSocketMessage {
            direction,
            kind,
            data: encoded,
            ..
        } = record
        else {
            return Err(WebSocketReplayError::MessageNotFound);
        };

        let direction = if direction.eq_ignore_ascii_case("ingress") {
            if entry.request_truncated.load(Ordering::Relaxed) {
                return Err(WebSocketReplayError::Truncated);
            }
            WebSocketRelayDirection::Ingress
        } else {
            if entry.response_truncated.load(Ordering::Relaxed) {
                return Err(WebSocketReplayError::Truncated);
            }
            WebSocketRelayDirection::Egress
        };
        let data = BASE64
            .decode(encoded)
            .context("decode captured WebSocket message")
            .map_err(WebSocketReplayError::InvalidCapture)?;
        let message = match kind.as_str() {
            "text" => WebSocketRelayMessage::Text(
                String::from_utf8(data.clone())
                    .context("decode captured WebSocket text")
                    .map_err(WebSocketReplayError::InvalidCapture)?
                    .into(),
            ),
            "binary" => WebSocketRelayMessage::Binary(Bytes::from(data.clone())),
            _ => return Err(WebSocketReplayError::ControlFrame),
        };
        let injector = entry
            .websocket_injector
            .read()
            .clone()
            .filter(WebSocketRelayInjector::is_open)
            .ok_or(WebSocketReplayError::ConnectionClosed)?;
        injector
            .send(direction, message)
            .await
            .map_err(|error| WebSocketReplayError::SendFailed(error.to_string()))?;
        self.record_websocket_message_inner(
            id,
            format!("{direction:?}"),
            kind,
            data,
            None,
            WebSocketMessageOrigin::Replay,
        )
        .await;
        Ok(())
    }

    #[cfg(feature = "websocket")]
    pub async fn send_websocket_message(
        &self,
        id: u64,
        direction: &str,
        kind: &str,
        payload: &str,
    ) -> Result<(), WebSocketReplayError> {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return Err(WebSocketReplayError::CaptureNotFound);
        };
        let direction = match direction {
            "ingress" => WebSocketRelayDirection::Ingress,
            "egress" => WebSocketRelayDirection::Egress,
            _ => {
                return Err(WebSocketReplayError::InvalidMessage(
                    "direction must be ingress or egress".to_owned(),
                ));
            }
        };
        let (kind, data, message) = match kind {
            "text" => {
                let data = payload.as_bytes().to_vec();
                (
                    "text".to_owned(),
                    data,
                    WebSocketRelayMessage::Text(payload.to_owned().into()),
                )
            }
            "binary" => {
                let data = BASE64.decode(payload.trim()).map_err(|error| {
                    WebSocketReplayError::InvalidMessage(format!(
                        "binary payload must be base64: {error}"
                    ))
                })?;
                (
                    "binary".to_owned(),
                    data.clone(),
                    WebSocketRelayMessage::Binary(Bytes::from(data)),
                )
            }
            _ => {
                return Err(WebSocketReplayError::InvalidMessage(
                    "kind must be text or binary".to_owned(),
                ));
            }
        };
        let injector = entry
            .websocket_injector
            .read()
            .clone()
            .filter(WebSocketRelayInjector::is_open)
            .ok_or(WebSocketReplayError::ConnectionClosed)?;
        injector
            .send(direction, message)
            .await
            .map_err(|error| WebSocketReplayError::SendFailed(error.to_string()))?;
        self.record_websocket_message_inner(
            id,
            format!("{direction:?}"),
            kind,
            data,
            None,
            WebSocketMessageOrigin::Injected,
        )
        .await;
        Ok(())
    }
}
