//! Bounded canonical H3 facts retained only by the profile inspector.

use rama_core::extensions::Extension;
use rama_http::{
    inspect::capture::CaptureMetadata,
    proto::{h2::PseudoHeaderOrder, h3::observation::H3RequestObservation},
    request::Parts,
};
use rama_quic_proto::capture::QuicObservation;

use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::HeaderCapturePolicy,
        http3::{H3ClientSequenceCapture, H3SequenceCaptureLimits},
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
        pseudo_headers::PseudoHeaderCapture,
        quic::{QuicFlightCapture, QuicFlightCaptureLimits},
    },
    format::canonical::ProfileDataError,
};

#[derive(Debug, Extension)]
pub(super) struct H3ProfileConnection(pub Result<ConnectionFacts, ProfileDataError>);

#[derive(Debug)]
pub(super) struct ConnectionFacts {
    pub slots: Box<[CapturedSlot]>,
    pub token_present: bool,
    pub client_hello_complete: bool,
}

#[derive(Debug, Extension)]
pub(super) struct H3ProfileRequest(pub Result<Box<[CapturedSlot]>, ProfileDataError>);

pub(super) fn capture(parts: &Parts, metadata: &CaptureMetadata) {
    // A later request may complete a boundary pending peer SETTINGS. Preserve
    // the first actual boundary, without caching a temporary missing-data error.
    if parts
        .extensions
        .get_ref::<H3RequestObservation>()
        .is_none_or(|observed| observed.first_request.get().is_some())
    {
        metadata
            .connection
            .get_or_insert(|| H3ProfileConnection(connection(parts)));
    }
    metadata
        .exchange
        .get_or_insert(|| H3ProfileRequest(request(parts)));
}

fn bounded(
    mut slots: Vec<CapturedSlot>,
    level: CaptureLevel,
) -> Result<Box<[CapturedSlot]>, ProfileDataError> {
    slots.sort_unstable_by_key(|slot| slot.kind);
    let joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level,
        slots: slots.into(),
    };
    joint.canonical(JointCaptureLimits::default())?;
    Ok(joint.slots)
}

fn connection(parts: &Parts) -> Result<ConnectionFacts, ProfileDataError> {
    let quic = parts
        .extensions
        .get_ref::<QuicObservation>()
        .ok_or(ProfileDataError::Incomplete("QUIC observation"))?;
    let observed = parts
        .extensions
        .get_ref::<H3RequestObservation>()
        .ok_or(ProfileDataError::Incomplete("H3 request observation"))?;
    let bounds = JointCaptureLimits::default();
    let flight_limits = QuicFlightCaptureLimits {
        bytes: bounds.value_bytes,
        ..QuicFlightCaptureLimits::default()
    };
    let flight = QuicFlightCapture::capture(quic, flight_limits)?;
    let orders = OrderCaptureLimits {
        bytes: bounds.value_bytes,
        ..OrderCaptureLimits::default()
    };
    let parameters = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::from_complete(quic.completeness.transport_parameters),
        OrderNamespace::QuicParameter,
        quic.transport_parameters
            .iter()
            .map(|parameter| (parameter.id.0, parameter.value.as_slice())),
        orders,
    )?;
    let sequence_limits = H3SequenceCaptureLimits {
        bytes: bounds.value_bytes,
        ..H3SequenceCaptureLimits::default()
    };
    let first_request = observed
        .first_request
        .get()
        .ok_or(ProfileDataError::Incomplete(
            "H3 first request and SETTINGS boundary",
        ))?;
    let sequence =
        H3ClientSequenceCapture::capture_at_request_head(first_request, sequence_limits)?;
    let mut slots = vec![
        CapturedSlot {
            kind: CapturedSlotKind::QuicFirstFlight,
            value: flight.canonical(flight_limits)?,
        },
        CapturedSlot {
            kind: CapturedSlotKind::QuicParameters,
            value: parameters.canonical(orders)?,
        },
        CapturedSlot {
            kind: CapturedSlotKind::Http3Sequence,
            value: sequence.canonical(sequence_limits)?,
        },
    ];
    // The frozen connection boundary contains SETTINGS before it is complete.
    if first_request.settings_received {
        let settings = first_request
            .settings
            .as_ref()
            .ok_or(ProfileDataError::Incomplete("H3 SETTINGS"))?;
        let settings = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::from_complete(observed.connection.completeness.settings),
            OrderNamespace::Http3Setting,
            settings
                .iter()
                .map(|setting| (setting.id, setting.value.to_be_bytes())),
            orders,
        )?;
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::Http3Settings,
            value: settings.canonical(orders)?,
        });
    }
    Ok(ConnectionFacts {
        slots: bounded(slots, CaptureLevel::Connection)?,
        token_present: flight.flight.token_len != 0,
        client_hello_complete: quic.completeness.client_hello,
    })
}

fn request(parts: &Parts) -> Result<Box<[CapturedSlot]>, ProfileDataError> {
    let observed = parts
        .extensions
        .get_ref::<H3RequestObservation>()
        .ok_or(ProfileDataError::Incomplete("H3 request observation"))?;
    let order = parts
        .extensions
        .get_ref::<PseudoHeaderOrder>()
        .ok_or(ProfileDataError::Incomplete("H3 pseudo-header order"))?;
    if !observed.fields_complete || observed.fields.len() < order.len() {
        return Err(ProfileDataError::Incomplete("H3 request fields"));
    }
    let (pseudo_fields, regular_fields) = observed.fields.split_at(order.len());
    let policy = HeaderCapturePolicy {
        bytes: JointCaptureLimits::default().value_bytes,
        ..HeaderCapturePolicy::default()
    };
    let headers = policy.capture(
        ProfileCaptureCompleteness::Complete,
        parts.version,
        &parts.headers,
        Some(regular_fields),
    )?;
    let pseudo = PseudoHeaderCapture::capture(
        ProfileCaptureCompleteness::Complete,
        parts.version,
        order,
        Some(pseudo_fields),
        policy.bytes,
    )?;
    pseudo.validate_method(&parts.method)?;
    bounded(
        vec![
            CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: headers.canonical(&policy)?,
            },
            CapturedSlot {
                kind: CapturedSlotKind::PseudoHeaders,
                value: pseudo.canonical(policy.bytes)?,
            },
        ],
        CaptureLevel::Request,
    )
}

#[cfg(test)]
mod tests;
