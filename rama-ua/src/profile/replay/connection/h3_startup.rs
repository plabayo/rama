//! Translate a static QPACK prefix into ordinary native preferences.
//!
//! Empty encoder instructions can be reproduced independently of origin QPACK
//! limits. Reserved frames require their complete retained bodies; older
//! metadata-only captures never grant replay support. The current subset has
//! one control stream, SETTINGS, and optional reserved/client-request priority frames.
//! Pre-request dynamic instructions and additional streams are not admitted.
//! Later dynamic compression follows native policy after the initial section.

use crate::profile::capture::http3::{
    H3CapturedEvent, H3ClientSequenceCapture, H3SequenceCaptureLimits,
};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    extensions::Extensions,
};
use rama_http::proto::h3::{
    FrameType, StreamType, VarInt,
    control::{ClientControlFrame, ClientControlPreferences},
    critical_streams::{Preferences, Startup},
    qpack::EncoderPreferences,
};
use rama_quic_proto::{Dir, Side, StreamId};

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

pub(super) fn supports(sequence: Option<&H3ClientSequenceCapture>) -> bool {
    let Some(sequence) = sequence else {
        return false;
    };
    let limits = H3SequenceCaptureLimits::default();
    if !sequence.encoder_instructions.is_empty() || sequence.events.len() > limits.events {
        return false;
    }
    let [
        H3CapturedEvent::Stream {
            stream_id,
            stream_type,
        },
        H3CapturedEvent::Control {
            frame_type,
            element_id,
            value,
            ..
        },
        tail @ ..,
    ] = sequence.events.as_ref()
    else {
        return false;
    };
    if *stream_id != u64::from(StreamId::new(Side::Client, Dir::Uni, 0))
        || *stream_type != StreamType::CONTROL.value()
        || *frame_type != FrameType::SETTINGS.value()
        || element_id.is_some()
        || !value.is_empty()
    {
        return false;
    }
    tail.iter()
        .try_fold(0usize, |bytes, event| {
            let value = match control(event)? {
                ControlRecipe::Ignored(_, value) | ControlRecipe::Priority(_, value) => value,
            };
            bytes
                .checked_add(value.len())
                .filter(|bytes| *bytes <= limits.bytes)
        })
        .is_some()
}

pub(super) struct NativeStartup {
    streams: Preferences,
    encoding: EncoderPreferences,
    controls: ClientControlPreferences,
}

pub(super) fn prepare(
    input: &Extensions,
    sequence: Option<&H3ClientSequenceCapture>,
) -> Result<Option<NativeStartup>, BoxError> {
    if !supports(sequence) {
        return Ok(None);
    }
    let streams = Preferences {
        encoder: Startup::OnDemand,
        decoder: Startup::OnDemand,
        ..Preferences::default()
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
    if encoding
        .defer_dynamic_first_section
        .is_some_and(|defer| !defer)
    {
        return Err(BoxError::from_static_str(
            "caller and captured QPACK initial encoding preferences conflict",
        ));
    }
    // An empty observed prefix constrains the initial section, not all future traffic.
    // Leave capacity, Huffman, peer limits and later compression to native policy.
    encoding.defer_dynamic_first_section = Some(true);

    let controls = ClientControlPreferences {
        frames: sequence
            .into_iter()
            .flat_map(|sequence| &sequence.events[2..])
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
