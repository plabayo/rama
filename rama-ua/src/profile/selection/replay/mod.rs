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
pub enum ProfilePreservationMode {
    #[default]
    Strict,
    BestEffort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
}

#[derive(Debug, Clone, Default, Serialize, Extension)]
#[extension(tags(ua, http))]
pub struct ProfilePreservationReport {
    pub differences: Box<[ProfilePreservationDifference]>,
}

impl ProfilePreservationReport {
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.differences.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct ReplayedRequestProfile {
    pub headers: Option<HeaderMap>,
    pub pseudo_headers: Option<PseudoHeaderOrder>,
    pub report: ProfilePreservationReport,
}

#[derive(Debug)]
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
        if mode == ProfilePreservationMode::Strict {
            return Err(ProfileReplayError::IncompatibleHeaderShape {
                name: field.name,
                occurrence: current,
            });
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
