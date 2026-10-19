pub mod compiler;
pub mod http;
pub mod preparation;

mod h3_settings;
mod h3_startup;
pub use h3_settings::H3SettingsReplayEvidence;

use std::sync::Arc;

use rama_core::{error::BoxError, extensions::Extension};
use rama_http::proto::{
    h2::frame::EarlyFrame,
    h3::{ClientSettingsProfile, SettingId, Settings},
};

#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits};
use crate::profile::{
    capture::{
        http2::{H2Capture, H2CaptureLimits},
        http3::{
            H3ClientSequenceCapture, H3SequenceCaptureLimits,
            bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
        },
        joint::{CaptureLevel, CapturedSlotKind, JointCapture, JointCaptureLimits},
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
        quic::{QuicFlightCapture, QuicFlightCaptureLimits},
    },
    format::canonical::{CanonicalValue, ProfileDataError},
    replay::request::{
        ProfilePreservationDifference, ProfilePreservationReport, ProfileReplayError,
    },
    selection::{
        DrawDomain, ProfileDraw, ProfileDrawContext, ProfileSeed, variants::ConnectionSelection,
    },
};
#[cfg(not(feature = "tls"))]
use rama_core::telemetry::tracing;

/// Typed, bounded components decoded from one immutable connection selection.
#[derive(Debug, Clone, Extension)]
#[extension(tags(ua))]
pub struct PreparedConnectionComponents {
    #[cfg(feature = "tls")]
    pub tls: Option<TlsCapture>,
    pub quic_parameters: Option<OrderedProtocolCapture>,
    pub h3_peer_settings: Option<OrderedProtocolCapture>,
    pub h3_settings_evidence: Option<H3SettingsReplayEvidence>,
    pub quic_versions: Option<OrderedProtocolCapture>,
    pub h2_early_frames: Option<Arc<[EarlyFrame]>>,
    pub quic_first_flight: Option<QuicFlightCapture>,
    pub h3_sequence: Option<H3ClientSequenceCapture>,
    pub h3_bootstrap: Option<H3BootstrapCapture>,
    /// Differences introduced while compiling the selected connection capture.
    pub preservation_report: ProfilePreservationReport,
}

impl PreparedConnectionComponents {
    /// Compile literal or variance-derived SETTINGS using a connection-scoped draw.
    /// Unanalyzed reserved fields are replayed literally and reported at preparation.
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
    /// Unsupported components keep their evidence and are reported as omitted.
    pub fn prepare_for_replay(&self) -> Result<PreparedConnectionComponents, ProfileReplayError> {
        self.prepare_for_replay_with(|_| Ok(()))
            .map(|(prepared, ())| prepared)
    }

    pub fn prepare_for_replay_with<C: compiler::CompiledConnectionProfile>(
        &self,
        compile: impl FnOnce(&mut PreparedConnectionComponents) -> Result<C, BoxError>,
    ) -> Result<(PreparedConnectionComponents, C), ProfileReplayError> {
        let joint =
            JointCapture::from_canonical(&self.effective.capture, JointCaptureLimits::default())?;
        let mut prepared = self.prepare_from_joint(&joint)?;
        let compiled = compile(&mut prepared).map_err(ProfileReplayError::ConnectionCompilation)?;
        let mut report = ProfilePreservationReport::default();
        for slot in &joint.slots {
            check_connection_component(slot.kind, &mut report, &compiled, &prepared);
        }
        if prepared.h3_settings_evidence.is_none()
            && prepared.h3_peer_settings.as_ref().is_some_and(|capture| {
                capture
                    .fields
                    .iter()
                    .any(|field| SettingId::new(field.id).is_reserved())
            })
        {
            report.push(ProfilePreservationDifference::UnanalyzedHttp3ReservedSettings);
        }
        prepared.preservation_report = report.followed_by(prepared.preservation_report);
        Ok((prepared, compiled))
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
        self.prepare_from_joint(&joint)
    }

    fn prepare_from_joint(
        &self,
        joint: &JointCapture,
    ) -> Result<PreparedConnectionComponents, ProfileDataError> {
        let mut prepared = Self::prepare_joint(joint)?;
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
            quic_versions: None,
            h2_early_frames: None,
            quic_first_flight: None,
            h3_sequence: None,
            h3_bootstrap: None,
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

                    // Without TLS support the slot is skipped and admission reports it.
                    #[cfg(not(feature = "tls"))]
                    tracing::debug!(
                        "captured TLS component skipped: TLS support is not compiled in"
                    );
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
                CapturedSlotKind::Http3Bootstrap => {
                    prepared.h3_bootstrap = Some(H3BootstrapCapture::from_canonical(
                        &slot.value,
                        H3BootstrapLimits {
                            bytes: limits.value_bytes,
                            ..Default::default()
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
    report: &mut ProfilePreservationReport,
    compiled: &impl compiler::CompiledConnectionProfile,
    prepared: &PreparedConnectionComponents,
) {
    // Make this exhaustive so a newly added protocol requires an explicit
    // decision about which backend consumes it before it can be advertised.
    let supported = match component {
        CapturedSlotKind::Http2EarlyFrames | CapturedSlotKind::Http3Settings => true,
        CapturedSlotKind::TcpTls
        | CapturedSlotKind::QuicTls
        | CapturedSlotKind::QuicParameters
        | CapturedSlotKind::QuicVersions
        | CapturedSlotKind::QuicFirstFlight => compiled.supports(component),
        CapturedSlotKind::Http3Bootstrap => {
            // The association also identifies a static initial request. Dynamic
            // insertion recipes additionally resolve its fields in apply_http.
            h3_startup::supports(
                prepared.h3_sequence.as_ref(),
                prepared.h3_bootstrap.as_ref(),
            ) || compiled.supports(component)
        }
        CapturedSlotKind::Http3Sequence => {
            h3_startup::supports(
                prepared.h3_sequence.as_ref(),
                prepared.h3_bootstrap.as_ref(),
            ) || compiled.supports(component)
        }
        CapturedSlotKind::Headers
        | CapturedSlotKind::PseudoHeaders
        | CapturedSlotKind::RuntimeMetadata
        | CapturedSlotKind::LegacyField => false,
    };
    if !supported {
        report.push(ProfilePreservationDifference::UnsupportedConnectionComponent { component });
    }
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
