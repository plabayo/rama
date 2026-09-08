//! Observed user-agent profiles for HTTP inspectors.
use crate::{
    UserAgent,
    profile::{
        Http1Settings, Http2Settings, RequestInitiator, UserAgentDatabase, UserAgentProfileInput,
    },
};
use rama_core::{error::BoxError, extensions::Extension};
use rama_http::{
    HeaderMap,
    headers::{ContentType, HeaderMapExt},
    inspect::capture::{CaptureMetadata, CaptureStore},
    proto::h2::{PseudoHeaderOrder, frame::EarlyFrameCapture},
};
use rama_inspect::search::matches_display;
#[cfg(feature = "tls")]
use rama_tls::{client::ClientHello, inspect::TlsObservation};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Debug, Clone, Extension, serde::Serialize)]
pub struct UserAgentObservation {
    pub user_agent: Option<UserAgent>,
    pub profile: Option<UserAgentProfileInput>,
    pub known_fingerprint: Option<KnownFingerprint>,
}

#[derive(Debug, Clone)]
pub struct ProfileInspector {
    database: Arc<UserAgentDatabase>,
}
impl ProfileInspector {
    pub fn new(database: Arc<UserAgentDatabase>) -> Self {
        Self { database }
    }
    pub fn observe(&self, parts: &rama_http::request::Parts, metadata: &CaptureMetadata) {
        if metadata.exchange.contains::<UserAgentObservation>() {
            return;
        }
        let user_agent = parts
            .headers
            .get(rama_http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok());
        #[cfg(feature = "tls")]
        let hello = metadata
            .connection
            .get_ref::<TlsObservation>()
            .and_then(|tls| tls.client_hello.clone());
        let settings = (parts.version == rama_http::Version::HTTP_2).then(|| Http2Settings {
            http_pseudo_headers: parts.extensions.get_ref::<PseudoHeaderOrder>().cloned(),
            early_frames: parts.extensions.get_ref::<EarlyFrameCapture>().cloned(),
        });
        // The handshake's request initiator is supplied by the WS adapter.
        let websocket =
            parts.extensions.get_ref::<RequestInitiator>() == Some(&RequestInitiator::Ws);
        metadata.exchange.insert(UserAgentObservation {
            known_fingerprint: known_fingerprint(&self.database, user_agent, parts, metadata),
            user_agent: user_agent.map(UserAgent::new),
            profile: captured_profile(
                parts,
                user_agent,
                #[cfg(feature = "tls")]
                hello,
                settings,
                websocket,
            ),
        });
    }
    pub fn database(&self) -> &UserAgentDatabase {
        &self.database
    }
}

pub async fn export_profiles(
    store: &CaptureStore,
    requests: &BTreeSet<u64>,
    connections: &BTreeSet<u64>,
) -> Result<Vec<UserAgentProfileInput>, BoxError> {
    let mut selected = store.selected_exchanges(requests, connections);
    let mut profiles = BTreeMap::<String, UserAgentProfileInput>::new();
    while let Some(capture) = selected.next_capture() {
        let metadata = capture.metadata();
        let Some(profile) = metadata
            .exchange
            .get_ref::<UserAgentObservation>()
            .and_then(|observation| observation.profile.as_ref())
        else {
            continue;
        };
        if let Some(existing) = profiles.get_mut(&profile.uastr) {
            existing.merge_missing(profile.clone())?;
        } else {
            profiles.insert(profile.uastr.clone(), profile.clone());
        }
    }
    Ok(profiles.into_values().collect())
}
fn captured_profile(
    parts: &rama_http::request::Parts,
    user_agent: Option<&str>,
    #[cfg(feature = "tls")] tls_client_hello: Option<ClientHello>,
    h2_settings: Option<Http2Settings>,
    websocket: bool,
) -> Option<UserAgentProfileInput> {
    let mut profile = UserAgentProfileInput::new(user_agent?);
    #[cfg(feature = "tls")]
    {
        profile.tls_client_hello = tls_client_hello;
    }
    let request_initiator = captured_request_initiator(parts, websocket);
    if parts.version == rama_http::Version::HTTP_2 {
        profile.h2_settings = h2_settings;
        match request_initiator {
            Some(RequestInitiator::Navigate) => {
                profile.h2_headers_navigate = Some(parts.headers.clone())
            }
            Some(RequestInitiator::Fetch) => profile.h2_headers_fetch = Some(parts.headers.clone()),
            Some(RequestInitiator::Xhr) => profile.h2_headers_xhr = Some(parts.headers.clone()),
            Some(RequestInitiator::Form) => profile.h2_headers_form = Some(parts.headers.clone()),
            Some(RequestInitiator::Ws) => profile.h2_headers_ws = Some(parts.headers.clone()),
            None => {}
        }
    } else {
        profile.h1_settings = Some(Http1Settings {
            title_case_headers: headers_are_title_case(&parts.headers),
        });
        match request_initiator {
            Some(RequestInitiator::Navigate) => {
                profile.h1_headers_navigate = Some(parts.headers.clone())
            }
            Some(RequestInitiator::Fetch) => profile.h1_headers_fetch = Some(parts.headers.clone()),
            Some(RequestInitiator::Xhr) => profile.h1_headers_xhr = Some(parts.headers.clone()),
            Some(RequestInitiator::Form) => profile.h1_headers_form = Some(parts.headers.clone()),
            Some(RequestInitiator::Ws) => profile.h1_headers_ws = Some(parts.headers.clone()),
            None => {}
        }
    }
    Some(profile)
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
fn known_fingerprint(
    database: &UserAgentDatabase,
    user_agent: Option<&str>,
    parts: &rama_http::request::Parts,
    metadata: &CaptureMetadata,
) -> Option<KnownFingerprint> {
    let profile = database.get_exact_header_str(user_agent?)?;
    #[cfg(feature = "tls")]
    let tls_matches = metadata
        .connection
        .get_ref::<TlsObservation>()
        .is_some_and(|tls| {
            tls.ja3.as_ref().is_some_and(|actual| {
                profile
                    .tls
                    .compute_ja3(None)
                    .is_ok_and(|expected| &expected == actual)
            }) || tls.ja4.as_ref().is_some_and(|actual| {
                profile
                    .tls
                    .compute_ja4(None)
                    .is_ok_and(|expected| &expected == actual)
            }) || tls.peetprint.as_ref().is_some_and(|actual| {
                profile
                    .tls
                    .compute_peet()
                    .is_ok_and(|expected| &expected == actual)
            })
        });
    #[cfg(not(feature = "tls"))]
    let tls_matches = {
        let _ = metadata;
        false
    };
    let method = Some(parts.method.clone());
    let http_matches = rama_http::fingerprint::Ja4H::compute(parts).is_ok_and(|actual| {
        let fingerprints = if parts.version == rama_http::Version::HTTP_2 {
            [
                Some(profile.http.ja4h_h2_navigate(method.clone())),
                profile.http.ja4h_h2_fetch(method.clone()),
                profile.http.ja4h_h2_xhr(method.clone()),
                profile.http.ja4h_h2_form(method),
            ]
        } else {
            [
                Some(profile.http.ja4h_h1_navigate(method.clone())),
                profile.http.ja4h_h1_fetch(method.clone()),
                profile.http.ja4h_h1_xhr(method.clone()),
                profile.http.ja4h_h1_form(method),
            ]
        };
        fingerprints
            .into_iter()
            .flatten()
            .any(|expected| expected.is_ok_and(|expected| expected == actual))
    });
    (tls_matches || http_matches).then_some(KnownFingerprint {
        kind: profile.ua_kind,
        version: profile.ua_version,
    })
}

#[cfg(test)]
mod tests;
