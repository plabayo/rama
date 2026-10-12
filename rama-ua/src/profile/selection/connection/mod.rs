use std::sync::Arc;

use rama_core::extensions::Extension;
use rama_http::proto::{
    h2::frame::EarlyFrame,
    h3::{ClientSettingsProfile, SettingId, Settings},
};

use crate::profile::{
    CanonicalValue, CaptureLevel, CapturedSlotKind, ConnectionSelection, H2Capture,
    H2CaptureLimits, H3ClientSequenceCapture, H3SequenceCaptureLimits, JointCapture,
    JointCaptureLimits, OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture,
    ProfileDataError, ProfilePreservationReport, ProtocolValue, QuicFlightCapture,
    QuicFlightCaptureLimits,
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
    /// Compile the captured client's SETTINGS in their original wire order.
    /// Runtime resource and capability checks belong to the HTTP/3 connector.
    pub fn h3_client_settings(&self) -> Result<Option<ClientSettingsProfile>, ProfileDataError> {
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
            settings
                .set(SettingId::new(field.id), u64::from_be_bytes(encoded))
                .map_err(|_error| ProfileDataError::Invalid("HTTP/3 SETTINGS value"))?;
        }
        Ok(Some(ClientSettingsProfile(Arc::new(settings))))
    }
}

impl ConnectionSelection {
    /// Decode the selected connection tuple once, before a connector consumes it.
    pub fn prepare_components(&self) -> Result<PreparedConnectionComponents, ProfileDataError> {
        let limits = JointCaptureLimits::default();
        let joint = JointCapture::from_canonical(&self.effective.capture, limits)?;
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
