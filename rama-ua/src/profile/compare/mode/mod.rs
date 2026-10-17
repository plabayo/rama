//! Explicit comparison policies; stored evidence is never rewritten.

use serde::Serialize;
use std::borrow::Cow;

use crate::profile::{
    capture::{
        http2::H2CaptureLimits,
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
    /// Exclude HTTP/2 SETTINGS acknowledgements, as the native replayer does.
    /// All other fields, order, bindings and complete joint correlation remain exact.
    Replay,
}

impl ComparisonMode {
    /// Events deliberately excluded by this mode, for user-visible reports.
    #[must_use]
    pub const fn excluded_events(self) -> &'static [&'static str] {
        match self {
            Self::Literal => &[],
            Self::Replay => &["HTTP/2 SETTINGS acknowledgements"],
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
            DecodedCapture::Joint(mut capture) => {
                let mut changed = false;
                for slot in &mut capture.slots {
                    if slot.kind == CapturedSlotKind::Http2EarlyFrames
                        && let Cow::Owned(projected) = self.project(&slot.value, bytes)?
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

#[cfg(test)]
mod tests;
