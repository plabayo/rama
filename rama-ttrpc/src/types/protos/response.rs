use super::raw_bytes::{ProstField, RawBytes};
use crate::types::message::{Message, MessageType};
use crate::types::protos::Status;

#[derive(Clone, PartialEq, Debug, Default)]
pub struct Response<Payload: ProstField + Default = RawBytes> {
    pub status: Option<Status>,
    pub payload: Payload,
}

impl<Payload: ProstField + Default> Message for Response<Payload> {
    const TYPE_ID: MessageType = MessageType::Response;
}

impl Response<()> {
    pub fn error(status: Status) -> Self {
        Self {
            status: Some(status),
            payload: (),
        }
    }
}

impl<Payload: ProstField + Default> Response<Payload> {
    pub fn ok(payload: Payload) -> Self {
        let status = None;
        Self { status, payload }
    }
}

/*
Why this is hand-written instead of `#[derive(prost::Message)]`:

Like `Request`, `payload` is generic over our own `ProstField` trait, not `prost::Message`, so the
same payload can be a concrete typed message or an opaque, already-serialized `RawBytes` blob. The
derive only encodes a `#[prost(message)]` field whose type implements `prost::Message`, so it cannot
dispatch through `ProstField::{encode,encoded_len,merge}` — hence the manual impl below.

It is otherwise the code `cargo expand` produces for the derive below, with `payload` re-pointed at
`ProstField` instead of `prost::Message`:
```
#[derive(Clone, PartialEq, prost::Message)]
pub struct Response<Payload: ProstMessage + Default> {
    #[prost(message)]
    pub status: Option<Status>,

    #[prost(message, required)]
    pub payload: Payload,
}
```
*/

impl<Payload: ProstField + Default> ::prost::Message for Response<Payload> {
    fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {
        if let Some(ref msg) = self.status {
            ::prost::encoding::message::encode(1u32, msg, buf);
        }
        self.payload.encode(2u32, buf);
    }
    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: ::prost::encoding::WireType,
        buf: &mut impl ::prost::bytes::Buf,
        ctx: ::prost::encoding::DecodeContext,
    ) -> ::core::result::Result<(), ::prost::DecodeError> {
        const STRUCT_NAME: &str = "Response";
        match tag {
            1u32 => {
                let value = &mut self.status;
                ::prost::encoding::message::merge(
                    wire_type,
                    value.get_or_insert_with(::core::default::Default::default),
                    buf,
                    ctx,
                )
                .map_err(|mut error| {
                    error.push(STRUCT_NAME, "status");
                    error
                })
            }
            2u32 => {
                let value = &mut self.payload;
                value.merge(wire_type, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "payload");
                    error
                })
            }
            _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
        }
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        self.status
            .as_ref()
            .map_or(0, |msg| ::prost::encoding::message::encoded_len(1u32, msg))
            + self.payload.encoded_len(2u32)
    }
    fn clear(&mut self) {
        self.status = ::core::option::Option::None;
        self.payload.clear();
    }
}
