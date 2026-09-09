//! Observed user-agent profiles for HTTP inspectors.

use std::{collections::BTreeSet, sync::Arc};

use rama_core::{error::BoxError, extensions::Extension};
use rama_http::{
    HeaderMap,
    headers::{ContentType, HeaderMapExt},
    inspect::capture::{CaptureMetadata, CaptureStore, StoredRecord},
    proto::h2::{PseudoHeaderOrder, frame::EarlyFrameCapture},
};
use rama_inspect::search::matches_display;
#[cfg(feature = "tls")]
use rama_tls::inspect::TlsObservation;

use crate::{
    UserAgent,
    profile::{
        Http1Settings, Http2Settings, RequestInitiator, UserAgentDatabase, UserAgentProfileInput,
    },
};

#[derive(Debug, Clone, Extension, serde::Serialize)]
pub struct UserAgentObservation {
    pub user_agent: Option<UserAgent>,
    /// Only protocol settings are retained here; profile headers are read from storage at export.
    #[serde(skip)]
    pub request_initiator: Option<RequestInitiator>,
    #[serde(skip)]
    pub h2_settings: Option<Http2Settings>,
    pub known_fingerprint: Option<KnownFingerprint>,
}

#[derive(Debug, Clone)]
pub struct ProfileInspector {
    database: Arc<UserAgentDatabase>,
    fingerprints: Arc<fingerprint::FingerprintCache>,
}

impl ProfileInspector {
    pub fn new(database: Arc<UserAgentDatabase>) -> Self {
        Self {
            fingerprints: Arc::new(fingerprint::FingerprintCache::new(&database)),
            database,
        }
    }

    pub fn observe(&self, parts: &rama_http::request::Parts, metadata: &CaptureMetadata) {
        if metadata.exchange.contains::<UserAgentObservation>() {
            return;
        }
        let user_agent = parts
            .headers
            .get(rama_http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok());
        let settings = (parts.version == rama_http::Version::HTTP_2).then(|| Http2Settings {
            http_pseudo_headers: parts.extensions.get_ref::<PseudoHeaderOrder>().cloned(),
            early_frames: parts.extensions.get_ref::<EarlyFrameCapture>().cloned(),
        });
        // The handshake's request initiator is supplied by the WS adapter.
        let websocket =
            parts.extensions.get_ref::<RequestInitiator>() == Some(&RequestInitiator::Ws);
        metadata.exchange.insert(UserAgentObservation {
            known_fingerprint: self.fingerprints.match_request(
                &self.database,
                user_agent,
                parts,
                metadata,
            ),
            user_agent: user_agent.map(UserAgent::new),
            request_initiator: captured_request_initiator(parts, websocket),
            h2_settings: settings,
        });
    }

    pub fn database(&self) -> &UserAgentDatabase {
        &self.database
    }
}

mod export;
pub use export::{ProfileExport, export_profiles};

fn fill_profile(
    profile: &mut UserAgentProfileInput,
    parts: rama_http::request::Parts,
    request_initiator: Option<RequestInitiator>,
    h2_settings: Option<Http2Settings>,
) {
    let destination = if parts.version == rama_http::Version::HTTP_2 {
        if profile.h2_settings.is_none() {
            profile.h2_settings = h2_settings;
        }
        match request_initiator {
            Some(RequestInitiator::Navigate) => &mut profile.h2_headers_navigate,
            Some(RequestInitiator::Fetch) => &mut profile.h2_headers_fetch,
            Some(RequestInitiator::Xhr) => &mut profile.h2_headers_xhr,
            Some(RequestInitiator::Form) => &mut profile.h2_headers_form,
            Some(RequestInitiator::Ws) => &mut profile.h2_headers_ws,
            None => return,
        }
    } else {
        profile.h1_settings.get_or_insert_with(|| Http1Settings {
            title_case_headers: headers_are_title_case(&parts.headers),
        });
        match request_initiator {
            Some(RequestInitiator::Navigate) => &mut profile.h1_headers_navigate,
            Some(RequestInitiator::Fetch) => &mut profile.h1_headers_fetch,
            Some(RequestInitiator::Xhr) => &mut profile.h1_headers_xhr,
            Some(RequestInitiator::Form) => &mut profile.h1_headers_form,
            Some(RequestInitiator::Ws) => &mut profile.h1_headers_ws,
            None => return,
        }
    };
    if destination.is_none() {
        *destination = Some(parts.headers);
    }
}

fn captured_request_initiator(
    parts: &rama_http::request::Parts,
    websocket: bool,
) -> Option<RequestInitiator> {
    if websocket {
        return Some(RequestInitiator::Ws);
    }
    if let Some(initiator) = parts.extensions.get_ref::<RequestInitiator>() {
        return Some(*initiator);
    }
    if parts
        .headers
        .get("x-requested-with")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("xmlhttprequest"))
    {
        return Some(RequestInitiator::Xhr);
    }
    if !parts
        .headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("navigate"))
    {
        return None;
    }
    let is_form = parts
        .headers
        .typed_get::<ContentType>()
        .is_some_and(|content_type| {
            let mime = content_type.mime();
            (mime.type_() == rama_http::mime::APPLICATION
                && mime.subtype() == rama_http::mime::WWW_FORM_URLENCODED)
                || (mime.type_() == rama_http::mime::MULTIPART
                    && mime.subtype() == rama_http::mime::FORM_DATA)
        });
    Some(if is_form {
        RequestInitiator::Form
    } else {
        RequestInitiator::Navigate
    })
}

fn headers_are_title_case(headers: &HeaderMap) -> bool {
    !headers.is_empty()
        && headers.keys().all(|name| {
            name.as_original_str().split('-').all(|part| {
                part.chars().next().is_none_or(|c| c.is_ascii_uppercase())
                    && part.chars().skip(1).all(|c| c.is_ascii_lowercase())
            })
        })
}

/// An exact database User-Agent whose observed TLS or HTTP fingerprint matches.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KnownFingerprint {
    pub kind: crate::UserAgentKind,
    pub version: Option<usize>,
}

impl std::fmt::Display for KnownFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(version) = self.version {
            write!(f, " {version}")?;
        }
        Ok(())
    }
}

impl UserAgentObservation {
    pub fn matches_search(&self, query: &str) -> bool {
        self.user_agent
            .as_ref()
            .is_some_and(|value| matches_display(value, query))
            || self
                .known_fingerprint
                .as_ref()
                .is_some_and(|value| matches_display(value, query))
    }
}
mod fingerprint;

#[cfg(test)]
mod tests;
