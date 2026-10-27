//! Recorded protocol shapes of a profile, for comparing live traffic with it.

use rama_core::telemetry::tracing;
use rama_http::{HeaderMap, HeaderValue, Method, Version};
#[cfg(feature = "tls")]
use rama_tls::client::ClientHello;
use rama_utils::octets::kib;

#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits};
use crate::profile::{
    analysis::profile::{AnalyzedProfile, AnalyzedProfileScope},
    capture::{
        headers::{HeaderCapture, HeaderCapturePolicy, HeaderOccurrence, HeaderValueSource},
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
    },
    format::{
        canonical::{CanonicalDomain, CanonicalValue, ProfileDataError},
        legacy::{LegacyFieldCapture, LegacyFieldValue},
    },
    model::{identity::FlowKey, runtime_hints::RequestInitiator, ua::UserAgentProfile},
};

/// Headers of one captured request variant.
#[derive(Debug, Clone)]
pub struct RecordedRequestHeaders {
    pub version: Version,
    pub method: Method,
    pub initiator: Option<RequestInitiator>,
    /// Every captured field in captured order; request-owned fields such as cookies have empty values.
    pub headers: HeaderMap,
}

impl UserAgentProfile {
    /// Every captured HTTP request header variant, in scope order.
    #[must_use]
    pub fn recorded_request_headers(&self) -> Vec<RecordedRequestHeaders> {
        let Some(analysis) = &self.captured else {
            return Vec::new();
        };
        let mut output = Vec::new();
        for (scope, value) in variants(analysis) {
            let decoded = match scope.observations.domain {
                CanonicalDomain::Joint => match &scope.flow {
                    Some(FlowKey::Http {
                        version,
                        method,
                        initiator,
                        ..
                    }) => joint_headers(value).map(|headers| {
                        headers.map(|headers| RecordedRequestHeaders {
                            version: *version,
                            method: method.clone(),
                            initiator: *initiator,
                            headers,
                        })
                    }),
                    _ => Ok(None),
                },
                CanonicalDomain::LegacyField => legacy_headers(value),
                _ => Ok(None),
            };
            match decoded {
                Ok(Some(headers)) => output.push(headers),
                Ok(None) => {}
                Err(error) => tracing::trace!("skip undecodable request headers: {error}"),
            }
        }
        output
    }

    /// One representative ClientHello per distinct captured TCP TLS shape.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn recorded_tcp_client_hellos(&self) -> Vec<ClientHello> {
        self.recorded_client_hellos(CapturedSlotKind::TcpTls)
    }

    /// One representative ClientHello per distinct captured TLS-over-QUIC shape.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn recorded_quic_client_hellos(&self) -> Vec<ClientHello> {
        self.recorded_client_hellos(CapturedSlotKind::QuicTls)
    }

    #[cfg(feature = "tls")]
    fn recorded_client_hellos(&self, transport: CapturedSlotKind) -> Vec<ClientHello> {
        let Some(analysis) = &self.captured else {
            return Vec::new();
        };
        let limits = TlsCaptureLimits::default();
        let mut seen = Vec::new();
        let mut output = Vec::new();
        for (scope, value) in variants(analysis) {
            let captures = match scope.observations.domain {
                CanonicalDomain::Joint if scope.flow.is_none() => joint_tls(value, transport),
                CanonicalDomain::LegacyField if transport == CapturedSlotKind::TcpTls => {
                    LegacyFieldCapture::from_canonical(value, kib(16)).map(|field| {
                        match field.value {
                            LegacyFieldValue::TcpTls(capture) => vec![capture],
                            _ => Vec::new(),
                        }
                    })
                }
                _ => Ok(Vec::new()),
            };
            let captures = match captures {
                Ok(captures) => captures,
                Err(error) => {
                    tracing::trace!("skip undecodable TLS capture: {error}");
                    continue;
                }
            };
            for capture in captures {
                let Ok(structure) = capture.structural(limits) else {
                    continue;
                };
                if !seen.contains(&structure.id) {
                    seen.push(structure.id);
                    output.push(capture.representative_client_hello());
                }
            }
        }
        output
    }
}

fn variants(
    analysis: &AnalyzedProfile,
) -> impl Iterator<Item = (&AnalyzedProfileScope, &CanonicalValue)> {
    analysis.scopes.iter().flat_map(|scope| {
        scope
            .observations
            .variants
            .iter()
            .map(move |variant| (scope, &variant.value))
    })
}

fn joint_headers(value: &CanonicalValue) -> Result<Option<HeaderMap>, ProfileDataError> {
    let joint = JointCapture::from_canonical(value, JointCaptureLimits::default())?;
    let Some(slot) = joint
        .slots
        .iter()
        .find(|slot| slot.kind == CapturedSlotKind::Headers)
    else {
        return Ok(None);
    };
    let captured = HeaderCapture::from_canonical(&slot.value, &HeaderCapturePolicy::default())?;
    profile_headers(&captured.fields).map(Some)
}

fn legacy_headers(
    value: &CanonicalValue,
) -> Result<Option<RecordedRequestHeaders>, ProfileDataError> {
    let field = LegacyFieldCapture::from_canonical(value, kib(16))?;
    let (LegacyFieldValue::Headers(headers), Some((version, method, initiator))) =
        (&field.value, field.field.request_flow())
    else {
        return Ok(None);
    };
    Ok(Some(RecordedRequestHeaders {
        version,
        method,
        initiator: Some(initiator),
        headers: profile_headers(&headers.fields)?,
    }))
}

fn profile_headers(fields: &[HeaderOccurrence]) -> Result<HeaderMap, ProfileDataError> {
    let mut headers = HeaderMap::with_capacity(fields.len());
    for field in fields {
        let value = match &field.value {
            HeaderValueSource::Profile(value) | HeaderValueSource::CaptureSafeProfile(value) => {
                HeaderValue::from_bytes(value)
                    .map_err(|_error| ProfileDataError::Invalid("recorded header value"))?
            }
            HeaderValueSource::Request(_) => HeaderValue::from_static(""),
        };
        headers.append(field.name.clone(), value);
    }
    Ok(headers)
}

#[cfg(feature = "tls")]
fn joint_tls(
    value: &CanonicalValue,
    transport: CapturedSlotKind,
) -> Result<Vec<TlsCapture>, ProfileDataError> {
    JointCapture::from_canonical(value, JointCaptureLimits::default())?
        .slots
        .iter()
        .filter(|slot| slot.kind == transport)
        .map(|slot| TlsCapture::from_canonical(&slot.value, TlsCaptureLimits::default()))
        .collect()
}
