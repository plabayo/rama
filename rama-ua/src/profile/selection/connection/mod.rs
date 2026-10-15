mod h3_settings;
pub use h3_settings::H3SettingsReplayEvidence;

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
    QuicFlightCapture, QuicFlightCaptureLimits,
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
    pub h3_settings_evidence: Option<H3SettingsReplayEvidence>,
    allow_unanalyzed_h3_settings: bool,
    pub quic_versions: Option<OrderedProtocolCapture>,
    pub h2_early_frames: Option<Arc<[EarlyFrame]>>,
    pub quic_first_flight: Option<QuicFlightCapture>,
    pub h3_sequence: Option<H3ClientSequenceCapture>,
    /// Differences introduced while compiling the selected connection capture.
    pub preservation_report: ProfilePreservationReport,
}

impl PreparedConnectionComponents {
    /// Compile literal or variance-derived SETTINGS using a connection-scoped draw.
    /// Unanalyzed reserved fields require an explicit best-effort difference report.
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
        let fields = if let Some(evidence) = &self.h3_settings_evidence {
            evidence.compile(capture, draw)?
        } else {
            if !self.allow_unanalyzed_h3_settings
                && capture
                    .fields
                    .iter()
                    .any(|field| SettingId::new(field.id).is_reserved())
            {
                return Err(ProfileDataError::Incomplete(
                    "HTTP/3 reserved SETTINGS analysis",
                ));
            }
            capture
                .fields
                .iter()
                .map(|field| Ok((field.id, h3_settings::setting_value(&field.value)?)))
                .collect::<Result<Vec<_>, ProfileDataError>>()?
        };
        let mut settings = Settings::new();
        for (id, value) in fields {
            settings
                .set(SettingId::new(id), value)
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

        let mut prepared = self.prepare_components()?;
        if prepared.h3_settings_evidence.is_none()
            && prepared.h3_peer_settings.as_ref().is_some_and(|capture| {
                capture
                    .fields
                    .iter()
                    .any(|field| SettingId::new(field.id).is_reserved())
            })
        {
            if mode == ProfilePreservationMode::Strict {
                return Err(ProfileReplayError::UnsupportedConnectionComponent(
                    CapturedSlotKind::Http3Settings,
                ));
            }
            report.push(ProfilePreservationDifference::UnanalyzedHttp3ReservedSettings);
            prepared.allow_unanalyzed_h3_settings = true;
        }
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
        let mut prepared = Self::prepare_joint(&joint)?;
        prepared.h3_settings_evidence = self.effective.h3_settings_evidence.clone();
        Ok(prepared)
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
            h3_settings_evidence: None,
            allow_unanalyzed_h3_settings: false,
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
