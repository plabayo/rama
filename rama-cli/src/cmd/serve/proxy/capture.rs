//! CLI storage composition for the reusable inspector.

use std::sync::Arc;

pub(super) use rama::http::{
    inspect::capture::*,
    ws::inspect::{CaptureWebSocketExt, CaptureWebSocketLayer, WebSocketReplayError},
};
#[cfg(test)]
use rama::inspect::InspectionState;
use rama::{
    Layer,
    crypto::inspect::EncryptStorageLayer,
    error::BoxError,
    http,
    http::ws::inspect::WebSocketLimits,
    inspect::storage::{FileStore, Storage, StorageLimits},
    tls::inspect::TlsObservation,
    ua::{
        inspect::{ProfileInspector, UserAgentObservation},
        profile::{RequestInitiator, UserAgentDatabase},
    },
};

#[derive(Debug)]
pub(super) struct ProxyCaptureObserver {
    profiles: ProfileInspector,
    websocket_limits: WebSocketLimits,
}

impl ProxyCaptureObserver {
    pub(super) fn new(profiles: Arc<UserAgentDatabase>, messages: usize) -> Self {
        Self {
            profiles: ProfileInspector::new(profiles),
            websocket_limits: WebSocketLimits { messages },
        }
    }
}

impl CaptureObserver for ProxyCaptureObserver {
    fn request(&self, parts: &http::request::Parts, metadata: &CaptureMetadata) {
        TlsObservation::capture(&parts.extensions, &metadata.connection);
        if http::ws::inspect::observe_handshake(parts, metadata, self.websocket_limits) {
            parts.extensions.insert(RequestInitiator::Ws);
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
                .get_ref::<UserAgentObservation>()
                .is_some_and(|ua| ua.matches_search(query))
    }

    fn response(&self, parts: &http::response::Parts, metadata: &CaptureMetadata) {
        TlsObservation::capture(&parts.extensions, &metadata.upstream);
    }
}

pub(super) fn storage(total_bytes: u64) -> Result<Storage, BoxError> {
    let files = FileStore::temporary(StorageLimits {
        total_bytes,
        record_bytes: 0,
    })?;
    Ok(Storage::new(EncryptStorageLayer::random()?.layer(files)))
}

#[cfg(test)]
pub(super) fn test_store(
    max_connections: usize,
    max_exchanges: usize,
    body_limit: u64,
    profiles: Arc<UserAgentDatabase>,
) -> Result<CaptureStore, BoxError> {
    Ok(CaptureStore::with_storage(
        storage(0)?,
        CaptureConfig {
            max_connections,
            max_exchanges,
            body_limit,
            total_limit: 0,
            observer: Arc::new(ProxyCaptureObserver::new(profiles, max_exchanges)),
            ..CaptureConfig::default()
        },
        InspectionState::default(),
    ))
}
