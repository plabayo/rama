use std::borrow::Cow;

use super::raw_bytes::{ProstField, RawBytes};
use crate::types::message::{Message, MessageType};
use crate::types::protos::KeyValue;

#[derive(Clone, PartialEq, Debug, Default)]
pub(crate) struct Request<Payload: ProstField + Default = RawBytes> {
    // `Cow<'static, str>` so the client can pass the generated `&'static str` service/method
    // names without allocating; the server decodes them into `Owned`.
    pub service: Cow<'static, str>,
    pub method: Cow<'static, str>,
    pub payload: Payload,
    pub timeout_nano: i64,
    pub metadata: Vec<KeyValue>,
}

impl<Payload: ProstField + Default> Message for Request<Payload> {
    const TYPE_ID: MessageType = MessageType::Request;
}

/*
Why this is hand-written instead of `#[derive(prost::Message)]` (two reasons):

1. `payload` is generic over our own `ProstField` trait, not `prost::Message`. That is what lets a
   `Request` carry either a concrete typed message (client side) or an opaque, already-serialized
   `RawBytes` blob that the server can route/forward without decoding. The derive only knows how to
   encode a `#[prost(message)]` field whose type implements `prost::Message`, so it cannot dispatch
   through `ProstField::{encode,encoded_len,merge}`.

2. `service`/`method` are `Cow<'static, str>`, not `String`, so the client can pass the generated
   `&'static str` names without allocating. The derive's `#[prost(string)]` codec is `String`-only,
   so those fields are encoded from `&str` by hand (see `encode_str`/`encoded_len_str`).

It is otherwise the code `cargo expand` produces for the derive below, with `payload` re-pointed at
`ProstField` and `service`/`method` changed from `String` to `Cow<'static, str>`:
```
#[derive(Clone, PartialEq, prost::Message)]
pub struct Request<Payload: ProstMessage + Default> {
    #[prost(string)]
    pub service: String,

    #[prost(string)]
    pub method: String,

    #[prost(message, required)]
    pub payload: Payload,

    #[prost(int64)]
    pub timeout_nano: i64,

    #[prost(message, repeated)]
    pub metadata: Vec<KeyValue>,
}
```
*/

impl<Payload: ProstField + Default> ::prost::Message for Request<Payload> {
    fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {
        if !self.service.is_empty() {
            encode_str(1u32, &self.service, buf);
        }
        if !self.method.is_empty() {
            encode_str(2u32, &self.method, buf);
        }
        self.payload.encode(3u32, buf);
        if self.timeout_nano != 0i64 {
            ::prost::encoding::int64::encode(4u32, &self.timeout_nano, buf);
        }
        for msg in &self.metadata {
            ::prost::encoding::message::encode(5u32, msg, buf);
        }
    }
    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: ::prost::encoding::WireType,
        buf: &mut impl ::prost::bytes::Buf,
        ctx: ::prost::encoding::DecodeContext,
    ) -> ::core::result::Result<(), ::prost::DecodeError> {
        const STRUCT_NAME: &str = "Request";
        match tag {
            1u32 => {
                let value = self.service.to_mut();
                ::prost::encoding::string::merge(wire_type, value, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "service");
                    error
                })
            }
            2u32 => {
                let value = self.method.to_mut();
                ::prost::encoding::string::merge(wire_type, value, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "method");
                    error
                })
            }
            3u32 => {
                let value = &mut self.payload;
                value.merge(wire_type, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "payload");
                    error
                })
            }
            4u32 => {
                let value = &mut self.timeout_nano;
                ::prost::encoding::int64::merge(wire_type, value, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "timeout_nano");
                    error
                })
            }
            5u32 => {
                let value = &mut self.metadata;
                ::prost::encoding::message::merge_repeated(wire_type, value, buf, ctx).map_err(
                    |mut error| {
                        error.push(STRUCT_NAME, "metadata");
                        error
                    },
                )
            }
            _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
        }
    }
    #[inline]
    #[expect(clippy::if_not_else)]
    fn encoded_len(&self) -> usize {
        (if !self.service.is_empty() {
            encoded_len_str(1u32, &self.service)
        } else {
            0
        }) + if !self.method.is_empty() {
            encoded_len_str(2u32, &self.method)
        } else {
            0
        } + self.payload.encoded_len(3u32)
            + if self.timeout_nano != 0i64 {
                ::prost::encoding::int64::encoded_len(4u32, &self.timeout_nano)
            } else {
                0
            }
            + ::prost::encoding::message::encoded_len_repeated(5u32, &self.metadata)
    }
    fn clear(&mut self) {
        self.service = Cow::Borrowed("");
        self.method = Cow::Borrowed("");
        self.payload.clear();
        self.timeout_nano = 0i64;
        self.metadata.clear();
    }
}

/// Encode `value` as a protobuf `string` field at `tag`.
///
/// `prost::encoding::string` operates on `&String`; we hold a `Cow<str>`, so we emit the
/// length-delimited field directly from the `&str` to avoid materializing a `String`.
fn encode_str(tag: u32, value: &str, buf: &mut impl ::prost::bytes::BufMut) {
    ::prost::encoding::encode_key(tag, ::prost::encoding::WireType::LengthDelimited, buf);
    ::prost::encoding::encode_varint(value.len() as u64, buf);
    buf.put_slice(value.as_bytes());
}

/// The number of bytes [`encode_str`] writes for `value` at `tag`.
fn encoded_len_str(tag: u32, value: &str) -> usize {
    ::prost::encoding::key_len(tag)
        + ::prost::encoding::encoded_len_varint(value.len() as u64)
        + value.len()
}
