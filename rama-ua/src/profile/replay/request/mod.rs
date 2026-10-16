use std::{collections::VecDeque, error::Error, fmt};

use rama_core::extensions::Extension;
use rama_http::{
    HeaderMap, HeaderName, HeaderValue, Version, header::COOKIE, proto::h2::PseudoHeaderOrder,
};
use serde::Serialize;

use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::{HeaderCapture, HeaderCapturePolicy, HeaderValueSource, RequestBinding},
        joint::{CaptureLevel, CapturedSlotKind, JointCapture, JointCaptureLimits},
        pseudo_headers::PseudoHeaderCapture,
    },
    format::canonical::ProfileDataError,
    model::identity::FlowKey,
    selection::variants::{CookieLayoutEvidence, RequestSelection},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Extension)]
#[extension(tags(ua))]
/// Whether replay rejects or reports deviations from the selected capture.
pub enum ProfilePreservationMode {
    /// Reject unsupported replay. Two or more caller cookie pairs require a
    /// captured split-field variant of the same HTTP version; without that
    /// evidence the layout is unknown and strict replay fails.
    #[default]
    Strict,
    /// Retain caller cookie boundaries when their captured layout is unknown,
    /// and report that difference alongside other unsupported replay behavior.
    BestEffort,
}

/// A caller-provided H2 option that can add or change connection wire output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum H2ClientParameter {
    EarlyFrames,
    ReplayEarlyFrames,
    InitialStreamWindowSize,
    InitialConnectionWindowSize,
    KeepAliveInterval,
    KeepAliveTimeout,
    KeepAliveWhileIdle,
    MaximumHeaderListSize,
    MaximumFrameSize,
    MaximumConcurrentStreams,
    AdaptiveWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// One observable difference between the selected capture and emitted request.
pub enum ProfilePreservationDifference {
    /// Reserved SETTINGS were retained without classification evidence.
    UnanalyzedHttp3ReservedSettings,
    /// No capture proves how to lay out several caller cookie pairs; retain
    /// the caller's fields without claiming an exact captured layout.
    UnknownCookieLayout,
    /// The selected capture has no wire compiler in this connector. Its presence
    /// in connection extensions does not establish that it was applied.
    UnsupportedConnectionComponent {
        component: CapturedSlotKind,
    },
    CallerValueOverride {
        name: HeaderName,
        occurrence: u32,
    },
    MissingRequestBinding {
        name: HeaderName,
        occurrence: u32,
        binding: RequestBinding,
    },
    AppendedCallerField {
        name: HeaderName,
        occurrence: u32,
    },
    /// Best-effort replay retained a caller option that can alter H2 wire output.
    RetainedH2ClientParameter {
        parameter: H2ClientParameter,
    },
}

#[derive(Debug, Clone, Default, Serialize, Extension)]
#[extension(tags(ua, http))]
/// Ordered differences accumulated while compiling and replaying a profile.
pub struct ProfilePreservationReport {
    pub differences: Box<[ProfilePreservationDifference]>,
}

impl ProfilePreservationReport {
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.differences.is_empty()
    }

    /// Append later-stage differences while preserving their execution order.
    #[must_use]
    pub fn followed_by(mut self, later: Self) -> Self {
        if self.differences.is_empty() {
            return later;
        }
        if later.differences.is_empty() {
            return self;
        }

        let mut differences = self.differences.into_vec();
        differences.extend(later.differences);
        self.differences = differences.into();
        self
    }

    pub(crate) fn push(&mut self, difference: ProfilePreservationDifference) {
        let mut differences = std::mem::take(&mut self.differences).into_vec();
        differences.push(difference);
        self.differences = differences.into();
    }
}

#[derive(Debug, Clone)]
/// Request metadata rebuilt from a selected captured variant.
pub struct ReplayedRequestProfile {
    pub headers: Option<HeaderMap>,
    pub pseudo_headers: Option<PseudoHeaderOrder>,
    pub report: ProfilePreservationReport,
}

#[derive(Debug)]
/// Failure to replay a selected profile under the requested preservation mode.
pub enum ProfileReplayError {
    Data(ProfileDataError),
    /// A registered backend could not prepare its selected native configuration.
    ConnectionCompilation(rama_core::error::BoxError),
    IncompatibleHeaderVersion {
        captured: Version,
        requested: Version,
    },
    IncompatibleHeaderShape {
        name: HeaderName,
        occurrence: u32,
    },
    IncompatibleH2ClientParameter(H2ClientParameter),
    /// Strict replay cannot continue without applying this selected component.
    UnsupportedConnectionComponent(CapturedSlotKind),
    /// Strict replay needs layout evidence before changing cookie field boundaries.
    UnknownCookieLayout,
}

impl fmt::Display for ProfileReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(error) => error.fmt(f),
            Self::ConnectionCompilation(error) => {
                write!(f, "compile captured connection: {error}")
            }
            Self::UnsupportedConnectionComponent(component) => write!(
                f,
                "selected connection component {component:?} has no supported wire replay"
            ),
            Self::UnknownCookieLayout => {
                f.write_str("captured profile has no cookie layout evidence")
            }
            Self::IncompatibleHeaderVersion {
                captured,
                requested,
            } => write!(
                f,
                "captured header version {captured:?} is incompatible with {requested:?}"
            ),
            Self::IncompatibleHeaderShape { name, occurrence } => write!(
                f,
                "request header {name} occurrence {occurrence} is incompatible with the captured shape"
            ),
            Self::IncompatibleH2ClientParameter(parameter) => write!(
                f,
                "caller H2 parameter {parameter:?} changes strict captured-profile replay"
            ),
        }
    }
}

impl Error for ProfileReplayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConnectionCompilation(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<ProfileDataError> for ProfileReplayError {
    fn from(value: ProfileDataError) -> Self {
        Self::Data(value)
    }
}

impl RequestSelection {
    /// Rebuild request headers in captured order.
    ///
    /// Caller fields absent from the capture are request-owned and are appended
    /// after the captured sequence in their original relative order. Strict
    /// mode still rejects a selected variant whose captured request binding is
    /// missing from the actual request.
    pub fn replay_request(
        &self,
        original: &HeaderMap,
        mode: ProfilePreservationMode,
    ) -> Result<ReplayedRequestProfile, ProfileReplayError> {
        let limits = JointCaptureLimits::default();
        let joint = JointCapture::from_canonical(&self.effective.capture, limits)?;
        if joint.level != CaptureLevel::Request {
            return Err(ProfileDataError::Invalid("request replay capture level").into());
        }
        let (version, method) = match &self.effective.flow {
            FlowKey::Http {
                version, method, ..
            } => (*version, method),
            FlowKey::Other { .. } => {
                return Err(ProfileDataError::Invalid("HTTP replay flow").into());
            }
        };
        let mut headers = None;
        let mut pseudo_headers = None;
        let mut differences = Vec::new();
        for slot in &joint.slots {
            match slot.kind {
                CapturedSlotKind::Headers => {
                    let policy = HeaderCapturePolicy::default();
                    let captured = HeaderCapture::from_canonical(&slot.value, &policy)?;
                    if captured.version != version {
                        return Err(ProfileReplayError::IncompatibleHeaderVersion {
                            captured: captured.version,
                            requested: version,
                        });
                    }
                    headers = Some(replay_headers(
                        &captured,
                        original,
                        self.effective.cookie_layout,
                        mode,
                        &mut differences,
                    )?);
                }
                CapturedSlotKind::PseudoHeaders => {
                    let captured =
                        PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes)?;
                    if captured.version != version {
                        return Err(ProfileReplayError::IncompatibleHeaderVersion {
                            captured: captured.version,
                            requested: version,
                        });
                    }
                    captured.validate_method(method)?;
                    pseudo_headers = Some(captured.fields.iter().map(|field| field.name).collect());
                }
                CapturedSlotKind::RuntimeMetadata => {}
                _ => {
                    return Err(
                        ProfileDataError::Invalid("connection slot in request replay").into(),
                    );
                }
            }
        }
        Ok(ReplayedRequestProfile {
            headers,
            pseudo_headers,
            report: ProfilePreservationReport {
                differences: differences.into(),
            },
        })
    }
}

fn replay_headers(
    captured: &HeaderCapture,
    original: &HeaderMap,
    cookie_layout: CookieLayoutEvidence,
    mode: ProfilePreservationMode,
    differences: &mut Vec<ProfilePreservationDifference>,
) -> Result<HeaderMap, ProfileReplayError> {
    let mut original = original
        .ordered_iter()
        .map(|(name, value)| OriginalHeader {
            name: name.clone(),
            value: value.clone(),
            used: false,
        })
        .collect::<Vec<_>>();
    let cookie_slots = if matches!(captured.version, Version::HTTP_2 | Version::HTTP_3) {
        captured
            .fields
            .iter()
            .filter(|field| {
                field.name == COOKIE
                    && matches!(
                        &field.value,
                        HeaderValueSource::Request(RequestBinding::Cookie)
                    )
            })
            .count()
    } else {
        0
    };
    let mut cookies = replay_cookie_values(
        &mut original,
        cookie_slots,
        cookie_layout,
        mode,
        differences,
    )?;
    let mut cookie_slot = 0;
    let mut output = HeaderMap::with_capacity(captured.fields.len().max(original.len()));
    for field in &captured.fields {
        if field.name == COOKIE
            && matches!(
                &field.value,
                HeaderValueSource::Request(RequestBinding::Cookie)
            )
            && let Some(values) = &mut cookies
        {
            cookie_slot += 1;
            // Keep captured positions where possible. Additional caller pairs
            // occupy the final cookie position; fewer pairs leave no empty slots.
            let count = if cookie_slot == cookie_slots {
                values.len()
            } else {
                1
            };
            for _ in 0..count {
                if let Some(mut value) = values.pop_front() {
                    value.set_sensitive(value.is_sensitive() || field.sensitive);
                    output.append(field.name.clone(), value);
                }
            }
            continue;
        }

        let original_index = occurrence_index(&original, &field.name, field.occurrence);
        let original_value = original_index.map(|index| {
            original[index].used = true;
            original[index].value.clone()
        });
        let value = match &field.value {
            HeaderValueSource::Profile(value) | HeaderValueSource::CaptureSafeProfile(value) => {
                let mut profile = HeaderValue::from_bytes(value)
                    .map_err(|_error| ProfileDataError::Invalid("profile replay header value"))?;
                if mode == ProfilePreservationMode::BestEffort
                    && let Some(caller) = original_value
                {
                    if caller.as_bytes() != profile.as_bytes() {
                        differences.push(ProfilePreservationDifference::CallerValueOverride {
                            name: field.name.clone(),
                            occurrence: field.occurrence,
                        });
                    }
                    caller
                } else {
                    profile.set_sensitive(field.sensitive);
                    profile
                }
            }
            HeaderValueSource::Request(binding) => match original_value {
                Some(value) => value,
                None if mode == ProfilePreservationMode::BestEffort => {
                    differences.push(ProfilePreservationDifference::MissingRequestBinding {
                        name: field.name.clone(),
                        occurrence: field.occurrence,
                        binding: *binding,
                    });
                    continue;
                }
                None => {
                    return Err(ProfileReplayError::IncompatibleHeaderShape {
                        name: field.name.clone(),
                        occurrence: field.occurrence,
                    });
                }
            },
        };
        let mut value = value;
        value.set_sensitive(value.is_sensitive() || field.sensitive);
        output.append(field.name.clone(), value);
    }
    let mut occurrences = ahash::HashMap::<HeaderName, u32>::default();
    for field in original {
        let occurrence = occurrences.entry(field.name.clone()).or_default();
        let current = *occurrence;
        *occurrence += 1;
        if field.used {
            continue;
        }
        differences.push(ProfilePreservationDifference::AppendedCallerField {
            name: field.name.clone(),
            occurrence: current,
        });
        output.append(field.name, field.value);
    }
    HeaderCapturePolicy::default().capture(
        ProfileCaptureCompleteness::Complete,
        captured.version,
        &output,
        None,
    )?;
    Ok(output)
}

/// RFC 9113 §8.2.3 allows Cookie to be split between fields and joined with
/// "; ". Preserve pair order and bytes; only separator whitespace is normalized
/// when reproducing a split capture. Set-Cookie never takes this path.
fn replay_cookie_values(
    original: &mut [OriginalHeader],
    slots: usize,
    layout: CookieLayoutEvidence,
    mode: ProfilePreservationMode,
    differences: &mut Vec<ProfilePreservationDifference>,
) -> Result<Option<VecDeque<HeaderValue>>, ProfileReplayError> {
    if slots == 0 || !original.iter().any(|field| field.name == COOKIE) {
        return Ok(None);
    }

    if slots == 1 && layout == CookieLayoutEvidence::Unknown {
        let pairs = original
            .iter()
            .filter(|field| field.name == COOKIE)
            .map(|field| field.value.as_bytes().split(|byte| *byte == b';').count())
            .sum::<usize>();
        if pairs > 1 {
            if mode == ProfilePreservationMode::Strict {
                return Err(ProfileReplayError::UnknownCookieLayout);
            }
            differences.push(ProfilePreservationDifference::UnknownCookieLayout);
        }
        // Keep the caller's boundaries until a captured variant establishes
        // splitting. A single field is never evidence for joining.
        return Ok(Some(
            original
                .iter_mut()
                .filter(|field| field.name == COOKIE)
                .map(|field| {
                    field.used = true;
                    field.value.clone()
                })
                .collect(),
        ));
    }

    let mut joined = Vec::new();
    let mut sensitive = false;
    let mut first = true;
    for field in original.iter_mut().filter(|field| field.name == COOKIE) {
        if !first {
            joined.extend_from_slice(b"; ");
        }
        first = false;
        joined.extend_from_slice(field.value.as_bytes());
        sensitive |= field.value.is_sensitive();
        field.used = true;
    }
    let make_value = |bytes: &[u8]| {
        let mut value = HeaderValue::from_bytes(bytes)
            .map_err(|_error| ProfileDataError::Invalid("request cookie value"))?;
        value.set_sensitive(sensitive);
        Ok::<_, ProfileReplayError>(value)
    };
    let values = joined
        .split(|byte| *byte == b';')
        .map(|pair| make_value(pair.trim_ascii()))
        .collect::<Result<VecDeque<_>, _>>()?;
    Ok(Some(values))
}

struct OriginalHeader {
    name: HeaderName,
    value: HeaderValue,
    used: bool,
}

fn occurrence_index(
    original: &[OriginalHeader],
    name: &HeaderName,
    occurrence: u32,
) -> Option<usize> {
    let occurrence = usize::try_from(occurrence).ok()?;
    original
        .iter()
        .enumerate()
        .filter(|(_index, field)| field.name == *name)
        .nth(occurrence)
        .map(|(index, _field)| index)
}

#[cfg(test)]
mod tests;
