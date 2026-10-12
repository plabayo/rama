use std::sync::Arc;

use rama_core::extensions::Extension;
use rama_http::proto::{
    h2::frame::EarlyFrame,
    h3::{ClientSettingsProfile, SettingId, Settings},
};

use crate::profile::{
    CanonicalValue, CaptureLevel, CapturedSlotKind, ConnectionSelection, DrawDomain, H2Capture,
    H2CaptureLimits, H3ClientSequenceCapture, H3SequenceCaptureLimits, JointCapture,
    JointCaptureLimits, OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture,
    ProfileDataError, ProfileDraw, ProfileDrawContext, ProfilePreservationDifference,
    ProfilePreservationMode, ProfilePreservationReport, ProfileReplayError, ProfileSeed,
    ProtocolValue, QuicFlightCapture, QuicFlightCaptureLimits,
};
#[cfg(feature = "tls")]
use crate::profile::{TlsCapture, TlsCaptureLimits};

/// Typed, bounded components decoded from one immutable connection selection.
#[derive(Debug, Clone, Extension)]
#[extension(tags(ua))]
pub struct PreparedConnectionComponents {
    #[cfg(feature = "tls")]
    pub tls: Option<TlsCapture>,
    pub quic_parameters: Option<OrderedProtocolCapture>,
    pub h3_peer_settings: Option<OrderedProtocolCapture>,
    pub quic_versions: Option<OrderedProtocolCapture>,
    pub h2_early_frames: Option<Arc<[EarlyFrame]>>,
    pub quic_first_flight: Option<QuicFlightCapture>,
    pub h3_sequence: Option<H3ClientSequenceCapture>,
    /// Differences introduced while compiling the selected connection capture.
    pub preservation_report: ProfilePreservationReport,
}

impl PreparedConnectionComponents {
    /// Compile client SETTINGS, regenerating reserved entries at their captured
    /// positions. Literal samples remain available in the capture for analysis.
    /// The caller supplies an independently keyed connection draw.
    pub fn h3_client_settings(
        &self,
        draw: &mut ProfileDraw,
    ) -> Result<Option<ClientSettingsProfile>, ProfileDataError> {
        let Some(capture) = &self.h3_peer_settings else {
            return Ok(None);
        };
        if !matches!(capture.namespace, OrderNamespace::Http3Setting) {
            return Err(ProfileDataError::Invalid("HTTP/3 SETTINGS namespace"));
        }
        capture.validate_fields(OrderCaptureLimits::default())?;
        let mut settings = Settings::new();
        for field in &capture.fields {
            let ProtocolValue::Literal(bytes) = &field.value else {
                return Err(ProfileDataError::Invalid("HTTP/3 SETTINGS value ownership"));
            };
            let encoded = bytes
                .as_ref()
                .try_into()
                .map_err(|_error| ProfileDataError::Invalid("HTTP/3 SETTINGS value encoding"))?;
            let mut id = SettingId::new(field.id);
            let mut value = u64::from_be_bytes(encoded);
            if id.is_reserved() {
                // QUICHE's control stream uses independent 32-bit draws for
                // the reserved ordinal and value. Do not freeze a sampled pair.
                let mut ordinal = draw.next_u64() as u32;
                loop {
                    id = SettingId::reserved(ordinal);
                    if settings.get(id).is_none()
                        && !capture.fields.iter().any(|field| field.id == id.value())
                    {
                        break;
                    }
                    // At most the bounded captured and emitted entries collide;
                    // advancing avoids an unbounded random-retry loop.
                    ordinal = ordinal.wrapping_add(1);
                }
                value = u64::from(draw.next_u64() as u32);
            }
            settings
                .set(id, value)
                .map_err(|_error| ProfileDataError::Invalid("HTTP/3 SETTINGS value"))?;
        }
        Ok(Some(ClientSettingsProfile(Arc::new(settings))))
    }
}

impl ConnectionSelection {
    /// Prepare input for the built-in HTTP connector's implemented wire compilers.
    /// Strict replay rejects unsupported components before connecting; best-effort
    /// replay retains their evidence and explicitly reports their omission.
    pub fn prepare_for_replay(
        &self,
        mode: ProfilePreservationMode,
    ) -> Result<PreparedConnectionComponents, ProfileReplayError> {
        let joint =
            JointCapture::from_canonical(&self.effective.capture, JointCaptureLimits::default())?;
        let mut report = ProfilePreservationReport::default();
        for slot in &joint.slots {
            check_connection_component(slot.kind, mode, &mut report)?;
        }

        let mut prepared = Self::prepare_joint(&joint)?;
        prepared.preservation_report = report.followed_by(prepared.preservation_report);
        Ok(prepared)
    }

    /// Reproduce this connection's SETTINGS generation independently of request
    /// draws and other layout decisions. A different connection key gives a new draw.
    #[must_use]
    pub fn h3_settings_draw(&self, seed: ProfileSeed) -> ProfileDraw {
        ProfileDraw::new(
            seed,
            ProfileDrawContext {
                profile: self.profile,
                analysis_revision: self.analysis_revision,
                scope: self.effective.scope,
                key: self.draw,
                domain: DrawDomain::Http3Settings,
                slot: 0,
            },
        )
    }

    /// Decode the selected connection tuple once, before a connector consumes it.
    pub fn prepare_components(&self) -> Result<PreparedConnectionComponents, ProfileDataError> {
        let limits = JointCaptureLimits::default();
        let joint = JointCapture::from_canonical(&self.effective.capture, limits)?;
        Self::prepare_joint(&joint)
    }

    fn prepare_joint(
        joint: &JointCapture,
    ) -> Result<PreparedConnectionComponents, ProfileDataError> {
        let limits = JointCaptureLimits::default();
        if joint.level != CaptureLevel::Connection {
            return Err(ProfileDataError::Invalid(
                "connection profile capture level",
            ));
        }
        let orders = OrderCaptureLimits {
            elements: limits.value_bytes,
            bytes: limits.value_bytes,
        };
        let mut prepared = PreparedConnectionComponents {
            #[cfg(feature = "tls")]
            tls: None,
            quic_parameters: None,
            h3_peer_settings: None,
            quic_versions: None,
            h2_early_frames: None,
            quic_first_flight: None,
            h3_sequence: None,
            preservation_report: ProfilePreservationReport::default(),
        };
        for slot in &joint.slots {
            match slot.kind {
                CapturedSlotKind::QuicParameters => {
                    prepared.quic_parameters =
                        Some(order(&slot.value, orders, OrderNamespace::QuicParameter)?);
                }
                CapturedSlotKind::Http3Settings => {
                    prepared.h3_peer_settings =
                        Some(order(&slot.value, orders, OrderNamespace::Http3Setting)?);
                }
                CapturedSlotKind::QuicVersions => {
                    prepared.quic_versions =
                        Some(order(&slot.value, orders, OrderNamespace::QuicVersion)?);
                }
                CapturedSlotKind::TcpTls | CapturedSlotKind::QuicTls => {
                    #[cfg(feature = "tls")]
                    {
                        prepared.tls = Some(TlsCapture::from_canonical(
                            &slot.value,
                            TlsCaptureLimits {
                                elements: limits.value_bytes,
                                bytes: limits.value_bytes,
                            },
                        )?);
                    }

                    #[cfg(not(feature = "tls"))]
                    return Err(ProfileDataError::Unsupported("TLS profile component"));
                }
                CapturedSlotKind::Http2EarlyFrames => {
                    let h2 = H2Capture::from_canonical(
                        &slot.value,
                        H2CaptureLimits {
                            frames: limits.value_bytes,
                            settings: limits.value_bytes,
                            bytes: limits.value_bytes,
                        },
                    )?;
                    prepared.h2_early_frames = Some(
                        h2.replay_frames(H2CaptureLimits {
                            frames: limits.value_bytes,
                            settings: limits.value_bytes,
                            bytes: limits.value_bytes,
                        })?
                        .into(),
                    );
                }
                CapturedSlotKind::QuicFirstFlight => {
                    prepared.quic_first_flight = Some(QuicFlightCapture::from_canonical(
                        &slot.value,
                        QuicFlightCaptureLimits {
                            bytes: limits.value_bytes,
                            ..QuicFlightCaptureLimits::default()
                        },
                    )?);
                }
                CapturedSlotKind::Http3Sequence => {
                    prepared.h3_sequence = Some(H3ClientSequenceCapture::from_canonical(
                        &slot.value,
                        H3SequenceCaptureLimits {
                            bytes: limits.value_bytes,
                            ..H3SequenceCaptureLimits::default()
                        },
                    )?);
                }
                CapturedSlotKind::Headers
                | CapturedSlotKind::PseudoHeaders
                | CapturedSlotKind::RuntimeMetadata
                | CapturedSlotKind::LegacyField => {
                    return Err(ProfileDataError::Invalid(
                        "request slot in connection profile",
                    ));
                }
            }
        }
        Ok(prepared)
    }
}

fn check_connection_component(
    component: CapturedSlotKind,
    mode: ProfilePreservationMode,
    report: &mut ProfilePreservationReport,
) -> Result<(), ProfileReplayError> {
    // These captures contain observations, but no built-in compiler consumes
    // them yet. Never let carrying decoded evidence masquerade as exact replay.
    if matches!(
        component,
        CapturedSlotKind::TcpTls
            | CapturedSlotKind::QuicTls
            | CapturedSlotKind::QuicParameters
            | CapturedSlotKind::QuicVersions
            | CapturedSlotKind::QuicFirstFlight
            | CapturedSlotKind::Http3Sequence
    ) {
        if mode == ProfilePreservationMode::Strict {
            return Err(ProfileReplayError::UnsupportedConnectionComponent(
                component,
            ));
        }
        report.push(ProfilePreservationDifference::UnsupportedConnectionComponent { component });
    }
    Ok(())
}

fn order(
    value: &CanonicalValue,
    limits: OrderCaptureLimits,
    expected: OrderNamespace,
) -> Result<OrderedProtocolCapture, ProfileDataError> {
    let captured = OrderedProtocolCapture::from_canonical(value, limits)?;
    if !matches!(
        (captured.namespace, expected),
        (OrderNamespace::QuicParameter, OrderNamespace::QuicParameter)
            | (OrderNamespace::Http3Setting, OrderNamespace::Http3Setting)
            | (OrderNamespace::QuicVersion, OrderNamespace::QuicVersion)
    ) {
        return Err(ProfileDataError::Invalid("connection component namespace"));
    }
    Ok(captured)
}

#[cfg(test)]
mod tests;
