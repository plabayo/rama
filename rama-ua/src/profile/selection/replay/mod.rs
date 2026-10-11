use std::{error::Error, fmt};

use rama_core::extensions::Extension;
use rama_http::{HeaderMap, HeaderName, HeaderValue, Version, proto::h2::PseudoHeaderOrder};
use serde::Serialize;

use crate::profile::{
    CaptureLevel, CapturedSlotKind, FlowKey, HeaderCapture, HeaderCapturePolicy, HeaderValueSource,
    JointCapture, JointCaptureLimits, ProfileCaptureCompleteness, ProfileDataError,
    PseudoHeaderCapture, RequestBinding, RequestSelection,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Extension)]
#[extension(tags(ua))]
/// Whether replay rejects or reports deviations from the selected capture.
pub enum ProfilePreservationMode {
    #[default]
    Strict,
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
    /// A SETTINGS acknowledgement cannot be emitted until peer SETTINGS arrives.
    DroppedH2SettingsAcknowledgement {
        index: usize,
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
    IncompatibleHeaderVersion {
        captured: Version,
        requested: Version,
    },
    IncompatibleHeaderShape {
        name: HeaderName,
        occurrence: u32,
    },
    IncompatibleH2ClientParameter(H2ClientParameter),
}

impl fmt::Display for ProfileReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(error) => error.fmt(f),
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

impl Error for ProfileReplayError {}

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
                    headers = Some(replay_headers(&captured, original, mode, &mut differences)?);
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
    let mut output = HeaderMap::with_capacity(captured.fields.len().max(original.len()));
    for field in &captured.fields {
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
