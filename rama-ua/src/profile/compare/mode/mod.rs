//! Explicit comparison policies; stored evidence is never rewritten.

use rama_http::proto::h3::observation::{FieldRepresentation, ObservedFieldRepresentation};
use serde::Serialize;
use std::borrow::Cow;

use crate::profile::{
    capture::{
        headers::HeaderCapturePolicy,
        http2::H2CaptureLimits,
        http3::bootstrap::H3BootstrapLimits,
        joint::{CapturedSlotKind, JointCaptureLimits},
    },
    format::{
        canonical::{CanonicalValue, ProfileDataError},
        decoded::DecodedCapture,
    },
};

/// Which retained facts participate in equality.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonMode {
    /// Every retained field, including peer-driven protocol events.
    #[default]
    Literal,
    /// Compare replayable facts across fresh connections.
    ///
    /// Excludes HTTP/2 SETTINGS acknowledgements and QPACK dynamic-table reference
    /// indexes, and the connection-local HTTP/3 initial request stream ID.
    /// QPACK representation families, static indexes, flags, field order,
    /// bindings and complete joint correlation remain exact. Validate dynamic
    /// references against each connection's decoded wire traffic separately.
    Replay,
}

impl ComparisonMode {
    /// Retained facts deliberately excluded by this mode, for user-visible reports.
    #[must_use]
    pub const fn exclusions(self) -> &'static [&'static str] {
        match self {
            Self::Literal => &[],
            Self::Replay => &[
                "HTTP/2 SETTINGS acknowledgements",
                "QPACK dynamic-table reference indexes (connection-local state)",
                "HTTP/3 bootstrap request stream ID (rebound to the fresh first request)",
            ],
        }
    }

    pub(super) fn project<'a>(
        self,
        value: &'a CanonicalValue,
        bytes: usize,
    ) -> Result<Cow<'a, CanonicalValue>, ProfileDataError> {
        if self == Self::Literal {
            return Ok(Cow::Borrowed(value));
        }
        let projected = match super::decode(value, bytes)? {
            DecodedCapture::H2(mut capture) => {
                if !capture
                    .frames
                    .iter()
                    .any(|frame| frame.is_protocol_generated())
                {
                    return Ok(Cow::Borrowed(value));
                }
                capture.frames = capture
                    .frames
                    .into_vec()
                    .into_iter()
                    .filter(|frame| !frame.is_protocol_generated())
                    .collect();
                capture.canonical(H2CaptureLimits {
                    bytes,
                    frames: bytes,
                    settings: bytes,
                })?
            }
            DecodedCapture::Headers(mut capture) => {
                if !project_dynamic_indexes(
                    capture
                        .fields
                        .iter_mut()
                        .map(|field| &mut field.representation),
                ) {
                    return Ok(Cow::Borrowed(value));
                }
                capture.canonical(&HeaderCapturePolicy {
                    bytes,
                    fields: bytes,
                    overrides: Box::default(),
                })?
            }
            DecodedCapture::PseudoHeaders(mut capture) => {
                if !project_dynamic_indexes(
                    capture
                        .fields
                        .iter_mut()
                        .map(|field| &mut field.representation),
                ) {
                    return Ok(Cow::Borrowed(value));
                }
                capture.canonical(bytes)?
            }
            DecodedCapture::H3Bootstrap(mut capture) => {
                // The source stream proves where the initial recipe was observed.
                // A fresh connection binds that same recipe to its own first request.
                // Keep the recipe identity, field count and insertion associations.
                if capture.bindings.stream_id == 0 {
                    return Ok(Cow::Borrowed(value));
                }
                capture.bindings.stream_id = 0;
                capture.canonical(H3BootstrapLimits {
                    bytes,
                    ..Default::default()
                })?
            }
            DecodedCapture::Joint(mut capture) => {
                let mut changed = false;
                for slot in &mut capture.slots {
                    if matches!(
                        slot.kind,
                        CapturedSlotKind::Http2EarlyFrames
                            | CapturedSlotKind::Headers
                            | CapturedSlotKind::PseudoHeaders
                            | CapturedSlotKind::Http3Bootstrap
                    ) && let Cow::Owned(projected) = self.project(&slot.value, bytes)?
                    {
                        slot.value = projected;
                        changed = true;
                    }
                }
                if !changed {
                    return Ok(Cow::Borrowed(value));
                }
                capture.canonical(JointCaptureLimits {
                    bytes,
                    value_bytes: bytes,
                    ..Default::default()
                })?
            }
            _ => return Ok(Cow::Borrowed(value)),
        };
        Ok(Cow::Owned(projected))
    }
}

// Only the comparison copy is changed. Zero is a valid dynamic index placeholder;
// stored bytes and reported identities retain the actual wire indexes.
fn project_dynamic_indexes<'a>(
    fields: impl Iterator<Item = &'a mut Option<ObservedFieldRepresentation>>,
) -> bool {
    let mut changed = false;
    for field in fields.flatten() {
        if matches!(
            field.representation,
            FieldRepresentation::DynamicIndex
                | FieldRepresentation::DynamicPostBaseIndex
                | FieldRepresentation::LiteralDynamicName
                | FieldRepresentation::LiteralPostBaseName
        ) && field.index != Some(0)
        {
            field.index = Some(0);
            changed = true;
        }
    }
    changed
}

#[cfg(test)]
mod tests;
