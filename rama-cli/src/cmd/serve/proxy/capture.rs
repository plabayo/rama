//! CLI storage composition for the reusable inspector.

use rama::crypto::inspect::EncryptLayer;
pub(super) use rama::http::ws::inspect::{
    CaptureWebSocketExt, CaptureWebSocketLayer, WebSocketReplayError,
};
use rama::{Layer, error::BoxError};
use rama::{http, tls::inspect::TlsObservation, ua::inspect::ProfileInspector};
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct ProxyCaptureObserver {
    profiles: ProfileInspector,
    websocket_limits: http::ws::inspect::WebSocketLimits,
}
impl ProxyCaptureObserver {
    pub(super) fn new(
        profiles: Arc<rama::ua::profile::UserAgentDatabase>,
        messages: usize,
    ) -> Self {
        Self {
            profiles: ProfileInspector::new(profiles),
            websocket_limits: http::ws::inspect::WebSocketLimits { messages },
        }
    }
}
impl CaptureObserver for ProxyCaptureObserver {
    fn request(&self, parts: &http::request::Parts, metadata: &CaptureMetadata) {
        TlsObservation::capture(&parts.extensions, &metadata.connection);
        if http::ws::inspect::observe_handshake(parts, metadata, self.websocket_limits) {
            parts
                .extensions
                .insert(rama::ua::profile::RequestInitiator::Ws);
        }
        self.profiles.observe(parts, metadata);
    }
    fn matches_search(&self, metadata: &CaptureMetadata, query: &str) -> bool {
        metadata
            .connection
            .get_ref::<TlsObservation>()
            .is_some_and(|tls| tls.matches_search(query))
            || metadata
                .upstream
                .get_ref::<TlsObservation>()
                .is_some_and(|tls| tls.matches_search(query))
            || metadata
                .exchange
                .get_ref::<rama::ua::inspect::UserAgentObservation>()
                .is_some_and(|ua| ua.matches_search(query))
    }
    fn response(&self, parts: &http::response::Parts, metadata: &CaptureMetadata) {
        TlsObservation::capture(&parts.extensions, &metadata.upstream);
    }
}

pub(super) use rama::http::inspect::capture::*;
use rama_inspect::storage::{FileStore, Storage, StorageLimits};

pub(super) fn storage(total_bytes: u64) -> Result<Storage, BoxError> {
    let files = FileStore::temporary(StorageLimits {
        total_bytes,
        record_bytes: 0,
    })?;
    Ok(Storage::new(EncryptLayer::random()?.layer(files)))
}

#[cfg(test)]
pub(super) fn test_store(
    max_connections: usize,
    max_exchanges: usize,
    body_limit: u64,
    profiles: std::sync::Arc<rama::ua::profile::UserAgentDatabase>,
) -> Result<CaptureStore, BoxError> {
    Ok(CaptureStore::with_storage(
        storage(0)?,
        CaptureConfig {
            max_connections,
            max_exchanges,
            body_limit,
            total_limit: 0,
            observer: Arc::new(ProxyCaptureObserver::new(profiles, max_exchanges)),
        },
        rama_inspect::InspectionState::default(),
    ))
}
