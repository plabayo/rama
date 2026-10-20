use std::collections::VecDeque;

use ahash::{HashMap, HashMapExt as _};

#[cfg(feature = "tls")]
use rama_http::Version;
use rama_http::inspect::capture::ExchangeCapture;

use super::*;

/// A pinned selection grouped by observed User-Agent. Only capture handles are
/// sorted and retained; each call constructs one merged profile from stored heads.
pub struct ProfileExport {
    captures: VecDeque<ExchangeCapture>,
    connection_owners: HashMap<u64, u64>,
}

fn user_agent(capture: &ExchangeCapture) -> Option<&str> {
    capture
        .metadata()
        .exchange
        .get_ref::<UserAgentObservation>()?
        .user_agent
        .as_ref()
        .map(UserAgent::header_str)
}

impl ProfileExport {
    pub fn new(
        store: &CaptureStore,
        requests: &BTreeSet<u64>,
        connections: &BTreeSet<u64>,
    ) -> Self {
        let mut selection = store.selected_exchanges(requests, connections);
        let mut captures = Vec::new();
        while let Some(capture) = selection.next_capture() {
            if user_agent(&capture).is_some() {
                captures.push(capture);
            }
        }
        captures.sort_unstable_by(|a, b| {
            user_agent(a)
                .cmp(&user_agent(b))
                .then_with(|| a.id().cmp(&b.id()))
        });
        let mut connection_owners = HashMap::new();
        for capture in &captures {
            let connection = capture.snapshot().connection_id;
            if connection == 0 {
                continue;
            }
            connection_owners
                .entry(connection)
                .and_modify(|id: &mut u64| *id = (*id).min(capture.id()))
                .or_insert(capture.id());
        }
        Self {
            captures: captures.into(),
            connection_owners,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.captures.is_empty()
    }

    /// Consume one group without retaining headers from other user agents.
    /// Incomplete observations are returned as typed input; callers can validate
    /// them with `UserAgentProfileInput::try_into_profile` before publishing.
    /// Cancellation leaves the selection unchanged, so the group can be retried.
    pub async fn next_profile(&mut self) -> Result<Option<UserAgentProfileInput>, BoxError> {
        let Some(header) = self.captures.front().and_then(user_agent) else {
            return Ok(None);
        };
        let mut profile = UserAgentProfileInput::new(header);
        let mut consumed = 0;
        while self.captures.get(consumed).and_then(user_agent) == Some(profile.uastr.as_str()) {
            let capture = &self.captures[consumed];
            consumed += 1;
            let metadata = capture.metadata();
            let Some(observed) = metadata.exchange.get_ref::<UserAgentObservation>() else {
                continue;
            };
            let Some(StoredRecord::RequestHead {
                method,
                url,
                version,
                headers,
            }) = capture.request_head().await?
            else {
                continue;
            };
            #[cfg(feature = "tls")]
            if matches!(
                version,
                Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2
            ) && profile.tls_client_hello.is_none()
            {
                profile.tls_client_hello = metadata
                    .connection
                    .get_ref::<TlsObservation>()
                    .and_then(|tls| tls.client_hello.clone());
            }
            let mut parts = rama_http::request::Parts::default();
            parts.method = method;
            parts.uri = url;
            parts.version = version;
            parts.headers = headers;
            fill_profile(
                &mut profile,
                parts,
                observed.request_initiator,
                observed.h2_settings.clone(),
            );
        }
        self.captures.drain(..consumed);
        Ok(Some(profile))
    }
}

/// Explicitly collect all profiles. Prefer `ProfileExport` for large selections.
pub async fn export_profiles(
    store: &CaptureStore,
    requests: &BTreeSet<u64>,
    connections: &BTreeSet<u64>,
) -> Result<Vec<UserAgentProfileInput>, BoxError> {
    let mut export = ProfileExport::new(store, requests, connections);
    let mut profiles = Vec::new();
    while let Some(profile) = export.next_profile().await? {
        profiles.push(profile);
    }
    Ok(profiles)
}

mod observations;
