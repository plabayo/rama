//! Translate an admitted QPACK prefix into ordinary native preferences.
//!
//! Empty encoder instructions can be reproduced independently of origin QPACK
//! limits. Reserved frames require their complete retained bodies; older
//! metadata-only captures never grant replay support. The current subset has
//! one control stream, SETTINGS, and optional reserved/client-request priority frames.
//! Dynamic prefixes require complete initial-request insertion associations.
//! Later dynamic compression follows native policy after the initial section.

use crate::profile::capture::http3::{
    H3CapturedEvent, H3ClientSequenceCapture, H3SequenceCaptureLimits,
    bootstrap::H3BootstrapCapture,
};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    extensions::Extensions,
};
use rama_http::proto::h3::{
    FrameType, StreamType, VarInt,
    control::{ClientControlFrame, ClientControlPreferences},
    critical_streams::{Order, Preferences, Startup},
    qpack::EncoderPreferences,
};
use rama_quic_proto::{Dir, Side, StreamId};

use super::super::h3_bootstrap;

// Borrow capture bodies during admission; allocate only when installing a recipe.
enum ControlRecipe<'a> {
    Ignored(FrameType, &'a [u8]),
    Priority(StreamId, &'a [u8]),
}

impl ControlRecipe<'_> {
    fn owned(self) -> ClientControlFrame {
        match self {
            Self::Ignored(frame_type, payload) => ClientControlFrame::Ignored {
                frame_type,
                payload: Bytes::copy_from_slice(payload),
            },
            Self::Priority(request, value) => ClientControlFrame::RequestPriority {
                request,
                value: Bytes::copy_from_slice(value),
            },
        }
    }
}

fn control(event: &H3CapturedEvent) -> Option<ControlRecipe<'_>> {
    let H3CapturedEvent::Control {
        frame_type,
        length,
        element_id,
        value,
    } = event
    else {
        return None;
    };
    let frame_type = FrameType::new(*frame_type);
    if frame_type.is_reserved() && element_id.is_none() && value.len() as u64 == *length {
        return Some(ControlRecipe::Ignored(frame_type, value));
    }
    if frame_type != FrameType::PRIORITY_UPDATE_REQUEST {
        return None;
    }
    let request = StreamId::from(VarInt::from_u64((*element_id)?).ok()?);
    if request.initiator() == Side::Client
        && request.dir() == Dir::Bi
        && *length == (VarInt::from(request).size() + value.len()) as u64
    {
        return Some(ControlRecipe::Priority(request, value));
    }
    None
}

pub(super) fn supports(
    sequence: Option<&H3ClientSequenceCapture>,
    bootstrap: Option<&H3BootstrapCapture>,
) -> bool {
    sequence.is_some_and(|sequence| stream_preferences(sequence, bootstrap).is_some())
}

fn stream_preferences(
    sequence: &H3ClientSequenceCapture,
    bootstrap: Option<&H3BootstrapCapture>,
) -> Option<Preferences> {
    let dynamic = !sequence.encoder_instructions.is_empty();
    if dynamic
        && bootstrap
            .and_then(|bootstrap| h3_bootstrap::capacity(bootstrap, sequence))
            .is_none()
    {
        return None;
    }
    let limits = H3SequenceCaptureLimits::default();
    if sequence.events.len() > limits.events {
        return None;
    }
    let [
        H3CapturedEvent::Stream {
            stream_id: 2,
            stream_type: 0,
        },
        H3CapturedEvent::Control {
            frame_type: 4,
            element_id: None,
            value,
            ..
        },
        tail @ ..,
    ] = sequence.events.as_ref()
    else {
        return None;
    };
    if !value.is_empty() {
        return None;
    }
    let mut preferences = Preferences {
        encoder: Startup::OnDemand,
        decoder: Startup::OnDemand,
        ..Preferences::default()
    };
    let mut order = None;
    let mut encoder = false;
    let mut decoder = false;
    let mut bytes = 0usize;
    for event in tail {
        if let H3CapturedEvent::Stream {
            stream_id,
            stream_type,
        } = event
        {
            let requested_order = if *stream_type == StreamType::QPACK_ENCODER.value() && !encoder {
                encoder = true;
                preferences.encoder = if dynamic {
                    Startup::OnDemand
                } else {
                    Startup::Immediate
                };
                match stream_id {
                    6 => Order::EncoderFirst,
                    10 => Order::DecoderFirst,
                    _ => return None,
                }
            } else if *stream_type == StreamType::QPACK_DECODER.value() && !decoder {
                decoder = true;
                preferences.decoder = Startup::Immediate;
                match stream_id {
                    6 => Order::DecoderFirst,
                    10 => Order::EncoderFirst,
                    _ => return None,
                }
            } else {
                return None;
            };
            if order.is_some_and(|order| order != requested_order) {
                return None;
            }
            order = Some(requested_order);
        } else {
            let value = match control(event)? {
                ControlRecipe::Ignored(_, value) | ControlRecipe::Priority(_, value) => value,
            };
            bytes = bytes
                .checked_add(value.len())
                .filter(|bytes| *bytes <= limits.bytes)?;
        }
    }
    if dynamic && !encoder {
        return None;
    }
    if let Some(order) = order {
        preferences.order = order;
    }
    Some(preferences)
}

pub(super) struct NativeStartup {
    streams: Preferences,
    encoding: EncoderPreferences,
    controls: ClientControlPreferences,
}

pub(super) fn prepare(
    input: &Extensions,
    sequence: Option<&H3ClientSequenceCapture>,
    bootstrap: Option<&H3BootstrapCapture>,
    reference_initial_insertions: bool,
) -> Result<Option<NativeStartup>, BoxError> {
    let Some(streams) = sequence.and_then(|sequence| stream_preferences(sequence, bootstrap))
    else {
        return Ok(None);
    };
    if input
        .get_ref::<Preferences>()
        .is_some_and(|caller| *caller != streams)
    {
        return Err(BoxError::from_static_str(
            "caller and captured HTTP/3 startup preferences conflict",
        ));
    }
    let mut encoding = input
        .get_ref::<EncoderPreferences>()
        .copied()
        .unwrap_or_default();
    let defer_dynamic = !reference_initial_insertions;
    if encoding
        .defer_dynamic_first_section
        .is_some_and(|defer| defer != defer_dynamic)
    {
        return Err(BoxError::from_static_str(
            "caller and captured QPACK initial encoding preferences conflict",
        ));
    }
    if let Some(capacity) = bootstrap
        .zip(sequence)
        .and_then(|(bootstrap, sequence)| h3_bootstrap::capacity(bootstrap, sequence))
    {
        if encoding
            .target_capacity
            .is_some_and(|caller| caller != capacity)
        {
            return Err(BoxError::from_static_str(
                "caller and captured QPACK capacity preferences conflict",
            ));
        }
        encoding.target_capacity = Some(capacity);
    }
    // The observed prefix constrains the initial section, not all future traffic.
    // Peer limits, Huffman defaults and later compression follow native policy.
    encoding.defer_dynamic_first_section = Some(defer_dynamic);

    let controls = ClientControlPreferences {
        frames: sequence
            .into_iter()
            .flat_map(|sequence| &sequence.events[2..])
            .filter(|event| !matches!(event, H3CapturedEvent::Stream { .. }))
            .map(|event| {
                control(event).map(ControlRecipe::owned).ok_or_else(|| {
                    BoxError::from_static_str("invalid admitted HTTP/3 control recipe")
                })
            })
            .collect::<Result<_, _>>()?,
    };
    if input
        .get_ref::<ClientControlPreferences>()
        .is_some_and(|caller| *caller != controls)
    {
        return Err(BoxError::from_static_str(
            "caller and captured HTTP/3 control preferences conflict",
        ));
    }
    Ok(Some(NativeStartup {
        streams,
        encoding,
        controls,
    }))
}

impl NativeStartup {
    pub(super) fn apply(self, extensions: &Extensions) {
        extensions.insert(self.streams);
        extensions.insert(self.encoding);
        extensions.insert(self.controls);
    }
}
