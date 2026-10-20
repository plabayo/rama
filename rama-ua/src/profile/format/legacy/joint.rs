//! Turn one legacy row into the request and connection tuples a live capture records,
//! so user-supplied legacy files can be emulated like counted archives.

use rama_core::telemetry::tracing;
use rama_http::{HeaderMap, Method, Version};

use super::{LegacyField, LegacyFieldCapture, LegacyFieldValue};
#[cfg(feature = "tls")]
use crate::profile::capture::tls::TlsCaptureLimits;
use crate::{
    UserAgent,
    profile::{
        analysis::profile::{AnalyzedProfile, ProfileAnalysisLimits, analyze_profile_evidence},
        capture::{
            completeness::ProfileCaptureCompleteness,
            headers::{HeaderCapture, HeaderCapturePolicy},
            http2::H2CaptureLimits,
            joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture},
            observation::ProfileCapture,
        },
        evidence::{collector::ProfileEvidenceCollector, transaction::CaptureRunId},
        format::{
            canonical::{CanonicalValue, ProfileDataError},
            input::UserAgentProfileInput,
        },
        model::{
            identity::{ConnectionContext, FetchContext, FlowKey, ProfileKey},
            runtime_hints::RequestInitiator,
        },
    },
};

// Fixed so that loading the same file always yields the same analysis.
const LEGACY_DAY: u32 = 1;
const LEGACY_SEED: [u8; 32] = [0; 32];

impl LegacyFieldCapture {
    /// Analyse a legacy row as one observation per recorded field.
    ///
    /// Header fields become request flows with the method the old schema implied for them,
    /// and the H2 settings and TLS ClientHello become connection tuples. Fields that
    /// cannot be captured or cannot form a valid tuple are skipped with a debug trace; `None` means nothing was usable.
    pub fn analyze_row(
        row: &UserAgentProfileInput,
        limits: ProfileAnalysisLimits,
    ) -> Result<Option<AnalyzedProfile>, ProfileDataError> {
        let maximum = limits.metadata_bytes;
        let fields = Self::capture_row_lenient(row, maximum)?;
        if fields.is_empty() {
            return Ok(None);
        }
        let profile = ProfileKey::from_user_agent(&UserAgent::new(row.uastr.clone()));
        let mut collector = ProfileEvidenceCollector::new(
            &profile,
            false,
            CaptureRunId::new(LEGACY_DAY, [0; 12]),
            LEGACY_SEED,
            LEGACY_DAY,
            limits,
        )?;
        for field in &fields {
            collector.observe(
                LEGACY_DAY,
                &ProfileCapture {
                    profile: profile.clone(),
                    flow: None,
                    connection: ConnectionContext::default(),
                    joint: JointCapture {
                        completeness: ProfileCaptureCompleteness::Complete,
                        level: CaptureLevel::Legacy,
                        slots: vec![CapturedSlot {
                            kind: CapturedSlotKind::LegacyField,
                            value: field.canonical(maximum)?,
                        }]
                        .into(),
                    },
                },
            )?;
        }
        for capture in joint_captures(row, &profile, &fields, maximum)? {
            collector.observe(LEGACY_DAY, &capture)?;
        }
        let evidence = collector.finish();
        if evidence.scopes.is_empty() {
            return Ok(None);
        }
        analyze_profile_evidence(&evidence, false, LEGACY_SEED, LEGACY_DAY, 1, limits).map(Some)
    }
}

fn joint_captures(
    row: &UserAgentProfileInput,
    profile: &ProfileKey,
    fields: &[LegacyFieldCapture],
    maximum: usize,
) -> Result<Vec<ProfileCapture>, ProfileDataError> {
    let mut pseudo = None;
    let mut early = None;
    #[cfg_attr(not(feature = "tls"), expect(unused_mut))]
    let mut tls: Option<CanonicalValue> = None;
    for field in fields {
        match &field.value {
            LegacyFieldValue::H2Settings {
                pseudo: order,
                early: frames,
            } => {
                pseudo = order.as_ref();
                early = frames.as_ref();
            }
            #[cfg(feature = "tls")]
            LegacyFieldValue::TcpTls(capture) => {
                tls = Some(capture.canonical(TlsCaptureLimits {
                    bytes: maximum,
                    ..TlsCaptureLimits::default()
                })?);
            }
            _ => {}
        }
    }
    let early = early
        .map(|early| {
            early.canonical(H2CaptureLimits {
                bytes: maximum,
                ..H2CaptureLimits::default()
            })
        })
        .transpose()?;

    let mut captures = Vec::new();
    let mut connections = Vec::new();
    for field in fields {
        let LegacyFieldValue::Headers(headers) = &field.value else {
            continue;
        };
        let (Some((version, method, initiator)), Some(original)) =
            (field.field.request_flow(), row_headers(row, field.field))
        else {
            continue;
        };
        let policy = HeaderCapturePolicy {
            bytes: maximum,
            ..HeaderCapturePolicy::default()
        };
        let mut slots = vec![CapturedSlot {
            kind: CapturedSlotKind::Headers,
            value: HeaderCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                version,
                fields: headers.fields.clone(),
            }
            .canonical(&policy)?,
        }];
        // The single recorded order fits only methods with the same pseudo-header shape.
        if version == Version::HTTP_2
            && let Some(order) = pseudo.filter(|order| order.validate_method(&method).is_ok())
        {
            slots.push(CapturedSlot {
                kind: CapturedSlotKind::PseudoHeaders,
                value: order.canonical(maximum)?,
            });
        }
        let capture = ProfileCapture {
            profile: profile.clone(),
            flow: Some(FlowKey::Http {
                version,
                method,
                initiator: Some(initiator),
                fetch: FetchContext::from_headers(original, maximum)?,
                connection: ConnectionContext::default(),
            }),
            connection: ConnectionContext::default(),
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Request,
                slots: slots.into(),
            },
        };
        match capture.prepare(false, Default::default()) {
            Ok(_) => captures.push(capture),
            Err(error) => {
                tracing::debug!(
                    user_agent = %row.uastr,
                    field = field.field.name(),
                    "legacy header field cannot form a request flow: {error}"
                );
                continue;
            }
        }
        let mut slots = Vec::new();
        if version == Version::HTTP_2
            && let Some(early) = &early
        {
            slots.push(CapturedSlot {
                kind: CapturedSlotKind::Http2EarlyFrames,
                value: early.clone(),
            });
        }
        if let Some(tls) = &tls {
            slots.push(CapturedSlot {
                kind: CapturedSlotKind::TcpTls,
                value: tls.clone(),
            });
        }
        slots.sort_unstable_by_key(|slot| slot.kind);
        let kinds = slots.iter().map(|slot| slot.kind).collect::<Vec<_>>();
        // An empty tuple records cleartext HTTP/1, so these headers also serve plain requests.
        let cleartext = version == Version::HTTP_11 && !connections.contains(&Vec::new());
        if cleartext {
            connections.push(Vec::new());
            captures.push(connection_capture(profile, Vec::new()));
        }
        if !slots.is_empty() && !connections.contains(&kinds) {
            connections.push(kinds);
            captures.push(connection_capture(profile, slots));
        }
    }
    Ok(captures)
}

fn connection_capture(profile: &ProfileKey, slots: Vec<CapturedSlot>) -> ProfileCapture {
    ProfileCapture {
        profile: profile.clone(),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: slots.into(),
        },
    }
}

impl LegacyField {
    /// The request flow a header field was recorded for.
    ///
    /// Methods follow how the old schema sorted requests into these header sets.
    #[must_use]
    pub fn request_flow(self) -> Option<(Version, Method, RequestInitiator)> {
        Some(match self {
            Self::H1Navigate => (Version::HTTP_11, Method::GET, RequestInitiator::Navigate),
            Self::H1Fetch => (Version::HTTP_11, Method::POST, RequestInitiator::Fetch),
            Self::H1Xhr => (Version::HTTP_11, Method::POST, RequestInitiator::Xhr),
            Self::H1Form => (Version::HTTP_11, Method::POST, RequestInitiator::Form),
            Self::H1Ws => (Version::HTTP_11, Method::GET, RequestInitiator::Ws),
            Self::H2Navigate => (Version::HTTP_2, Method::GET, RequestInitiator::Navigate),
            Self::H2Fetch => (Version::HTTP_2, Method::POST, RequestInitiator::Fetch),
            Self::H2Xhr => (Version::HTTP_2, Method::POST, RequestInitiator::Xhr),
            Self::H2Form => (Version::HTTP_2, Method::POST, RequestInitiator::Form),
            Self::H2Ws => (Version::HTTP_2, Method::CONNECT, RequestInitiator::Ws),
            _ => return None,
        })
    }
}

fn row_headers(row: &UserAgentProfileInput, field: LegacyField) -> Option<&HeaderMap> {
    match field {
        LegacyField::H1Navigate => row.h1_headers_navigate.as_ref(),
        LegacyField::H1Fetch => row.h1_headers_fetch.as_ref(),
        LegacyField::H1Xhr => row.h1_headers_xhr.as_ref(),
        LegacyField::H1Form => row.h1_headers_form.as_ref(),
        LegacyField::H1Ws => row.h1_headers_ws.as_ref(),
        LegacyField::H2Navigate => row.h2_headers_navigate.as_ref(),
        LegacyField::H2Fetch => row.h2_headers_fetch.as_ref(),
        LegacyField::H2Xhr => row.h2_headers_xhr.as_ref(),
        LegacyField::H2Form => row.h2_headers_form.as_ref(),
        LegacyField::H2Ws => row.h2_headers_ws.as_ref(),
        _ => None,
    }
}
