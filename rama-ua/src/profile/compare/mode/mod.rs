//! Explicit comparison policies; stored evidence is never rewritten.

use rama_http::Version;
use rama_http::proto::h3::observation::{FieldRepresentation, ObservedFieldRepresentation};
#[cfg(feature = "tls")]
use rama_tls::ExtensionId;
use serde::Serialize;
use std::borrow::Cow;

#[cfg(feature = "tls")]
use crate::profile::capture::tls::{
    TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue,
};
use crate::profile::{
    analysis::profile::AnalyzedProfile,
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
    model::identity::FlowKey,
};

/// Which retained facts participate in equality.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonMode {
    /// Every retained field, including peer-driven protocol events.
    #[default]
    Literal,
    /// Compare replayable facts across fresh connections. Excludes HTTP/2
    /// SETTINGS acknowledgements and QPACK dynamic reference indexes; bootstrap
    /// stream IDs and request correlations remain exact.
    Replay,
    /// Compare native replay with the reference bootstrap rebound to stream zero.
    /// A supplied reference profile also determines its expected single-version TCP offer.
    NativeReplay,
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
            ],
            Self::NativeReplay => &[
                "HTTP/2 SETTINGS acknowledgements",
                "QPACK dynamic-table reference indexes (connection-local state)",
                "reference TCP ALPN narrowed to the sole captured TCP HTTP version",
                "reference HTTP/3 bootstrap stream ID (rebound to native replay stream 0; observed binding stays exact)",
            ],
        }
    }

    /// Use captured flow versions to derive the native replay offer for this archive.
    #[must_use]
    pub fn for_reference(self, profile: &AnalyzedProfile) -> CaptureComparisonPolicy {
        let mut policy = CaptureComparisonPolicy::from(self);
        if self == Self::NativeReplay {
            let mut versions = profile.scopes.iter().filter_map(|scope| match &scope.flow {
                Some(FlowKey::Http { version, .. }) if *version != Version::HTTP_3 => {
                    Some(*version)
                }
                _ => None,
            });
            if let Some(version) = versions.next()
                && versions.all(|other| other == version)
            {
                policy.tcp_alpn = match version {
                    Version::HTTP_11 => Some(b"http/1.1"),
                    Version::HTTP_2 => Some(b"h2"),
                    _ => None,
                };
            }
        }
        policy
    }
}

/// Reference-derived expectations for offline tuple comparison.
#[derive(Debug, Clone, Copy)]
pub struct CaptureComparisonPolicy {
    pub(super) mode: ComparisonMode,
    tcp_alpn: Option<&'static [u8]>,
}

impl From<ComparisonMode> for CaptureComparisonPolicy {
    fn from(mode: ComparisonMode) -> Self {
        Self {
            mode,
            tcp_alpn: None,
        }
    }
}

impl CaptureComparisonPolicy {
    pub(super) fn project<'a>(
        self,
        value: &'a CanonicalValue,
        bytes: usize,
    ) -> Result<Cow<'a, CanonicalValue>, ProfileDataError> {
        self.project_side(value, bytes, true)
    }

    pub(super) fn project_observed<'a>(
        self,
        value: &'a CanonicalValue,
        bytes: usize,
    ) -> Result<Cow<'a, CanonicalValue>, ProfileDataError> {
        self.project_side(value, bytes, false)
    }

    fn project_side<'a>(
        self,
        value: &'a CanonicalValue,
        bytes: usize,
        reference: bool,
    ) -> Result<Cow<'a, CanonicalValue>, ProfileDataError> {
        if self.mode == ComparisonMode::Literal {
            return Ok(Cow::Borrowed(value));
        }
        let projected = match super::decode(value, bytes)? {
            #[cfg(feature = "tls")]
            DecodedCapture::Tls(mut capture)
                if reference && capture.transport == TlsCaptureTransport::Tcp =>
            {
                let Some(protocol) = self.tcp_alpn else {
                    return Ok(Cow::Borrowed(value));
                };
                let Some(offer) = capture
                    .extensions
                    .iter_mut()
                    .find(|extension| {
                        ExtensionId::from(extension.id)
                            == ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                    })
                    .and_then(|extension| match &mut extension.value {
                        TlsCapturedExtensionValue::Protocols(offer) => Some(offer),
                        _ => None,
                    })
                else {
                    return Ok(Cow::Borrowed(value));
                };
                if offer.len() < 2 || !offer.iter().any(|item| item.as_ref() == protocol) {
                    return Ok(Cow::Borrowed(value));
                }
                *offer = Box::new([protocol.into()]);
                // Changing ALPN also restricts application settings to the remaining offer.
                capture.extensions = capture
                    .extensions
                    .into_vec()
                    .into_iter()
                    .filter_map(|mut ext| {
                        if matches!(
                            ExtensionId::from(ext.id),
                            ExtensionId::OLD_APPLICATION_SETTINGS
                                | ExtensionId::APPLICATION_SETTINGS
                        ) && let TlsCapturedExtensionValue::Protocols(settings) = &mut ext.value
                        {
                            let kept: Vec<_> = settings
                                .iter()
                                .filter(|item| item.as_ref() == protocol)
                                .cloned()
                                .collect();
                            if kept.is_empty() {
                                return None;
                            }
                            *settings = kept.into();
                        }
                        Some(ext)
                    })
                    .collect();
                capture.canonical(TlsCaptureLimits::uniform(bytes))?
            }
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
                // Native replay opens its first request on stream zero. Only the
                // reference may be rebound: an observed later stream must not match.
                // Keep the recipe identity, field count and insertion associations.
                if self.mode != ComparisonMode::NativeReplay
                    || !reference
                    || capture.bindings.stream_id == 0
                {
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
                        CapturedSlotKind::TcpTls
                            | CapturedSlotKind::Http2EarlyFrames
                            | CapturedSlotKind::Headers
                            | CapturedSlotKind::PseudoHeaders
                            | CapturedSlotKind::Http3Bootstrap
                    ) && let Cow::Owned(projected) =
                        self.project_side(&slot.value, bytes, reference)?
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

// Zero is a valid dynamic index placeholder; stored bytes retain the wire indexes.
pub(in crate::profile) fn project_dynamic_indexes<'a>(
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
