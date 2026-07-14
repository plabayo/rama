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
        // On the wire `payload` is a proto3 `bytes` field: canonical encoding omits it when
        // empty. Emitting a present-but-empty field makes the Go server feed a phantom empty
        // first message to client-streaming handlers (containerd/ttrpc services.go
        // `req.Payload != nil || !info.StreamingClient`, the issue-#126 guard).
        if !self.payload.is_empty() {
            self.payload.encode(3u32, buf);
        }
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
        } + if !self.payload.is_empty() {
            self.payload.encoded_len(3u32)
        } else {
            0
        } + if self.timeout_nano != 0i64 {
            ::prost::encoding::int64::encoded_len(4u32, &self.timeout_nano)
        } else {
            0
        } + ::prost::encoding::message::encoded_len_repeated(5u32, &self.metadata)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::encoding::Encodeable as _;

    // field 3, wire type 2 (length-delimited)
    const PAYLOAD_KEY: u8 = (3 << 3) | 2;

    fn request<P: ProstField + Default>(payload: P) -> Request<P> {
        Request {
            service: Cow::Borrowed("svc"),
            method: Cow::Borrowed("m"),
            payload,
            timeout_nano: 0,
            metadata: vec![],
        }
    }

    /// The Go server feeds `Request.payload` to a client-streaming handler whenever the
    /// field is present on the wire (containerd/ttrpc services.go:
    /// `req.Payload != nil || !info.StreamingClient`, the issue-#126 guard) — and
    /// protobuf-go decodes a present-but-empty `bytes` field to a non-nil slice. An empty
    /// payload must therefore be omitted entirely (canonical proto3), or Go streaming
    /// handlers receive a phantom empty first input message.
    #[test]
    fn empty_payload_field_is_omitted() {
        let request = request(());
        let bytes = request.encode_to_bytes().expect("encode");
        assert!(
            !bytes.contains(&PAYLOAD_KEY),
            "an empty payload must not be present on the wire"
        );
        assert_eq!(
            prost::Message::encoded_len(&request),
            bytes.len(),
            "encoded_len must agree with what encode_raw writes"
        );
    }

    /// Wire-compat oracle: a prost-derived twin with ttRPC's field numbers
    /// (containerd/ttrpc request.pb.go: service=1, method=2, payload=3 bytes,
    /// timeout_nano=4 varint, metadata=5 repeated) must decode everything the
    /// hand-written impl encodes, and vice versa.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct RequestTwin {
        #[prost(string, tag = "1")]
        service: String,
        #[prost(string, tag = "2")]
        method: String,
        #[prost(bytes = "vec", tag = "3")]
        payload: Vec<u8>,
        #[prost(int64, tag = "4")]
        timeout_nano: i64,
        #[prost(message, repeated, tag = "5")]
        metadata: Vec<KeyValue>,
    }

    #[test]
    fn wire_roundtrip_matches_prost_derive() {
        use crate::types::encoding::Decodeable as _;

        let ours = Request::<KeyValue> {
            service: Cow::Borrowed("svc"),
            method: Cow::Borrowed("m"),
            payload: KeyValue {
                key: "k".to_owned(),
                value: "v".to_owned(),
            },
            timeout_nano: 12_345,
            metadata: vec![
                KeyValue {
                    key: "a".to_owned(),
                    value: "1".to_owned(),
                },
                KeyValue {
                    key: "a".to_owned(),
                    value: "2".to_owned(),
                },
            ],
        };

        let bytes = ours.encode_to_bytes().expect("encode");
        let twin = <RequestTwin as prost::Message>::decode(bytes).expect("twin decodes ours");
        assert_eq!(twin.service, "svc");
        assert_eq!(twin.method, "m");
        assert_eq!(twin.timeout_nano, 12_345);
        assert_eq!(twin.metadata, ours.metadata);
        let payload =
            <KeyValue as prost::Message>::decode(&twin.payload[..]).expect("payload decodes");
        assert_eq!(payload, ours.payload);

        // and back: what the twin encodes, the hand-written impl decodes (server view)
        let mut twin_bytes = Vec::new();
        prost::Message::encode(&twin, &mut twin_bytes).expect("twin encodes");
        let back = Request::<RawBytes>::decode(&twin_bytes[..]).expect("we decode the twin");
        assert_eq!(back.service, "svc");
        assert_eq!(back.method, "m");
        assert_eq!(back.timeout_nano, 12_345);
        assert_eq!(back.metadata, ours.metadata);
        assert_eq!(
            back.payload.decode::<KeyValue>().expect("payload decodes"),
            ours.payload
        );
    }

    #[test]
    fn non_empty_payload_field_is_encoded() {
        let request = request(KeyValue {
            key: "k".to_owned(),
            value: "v".to_owned(),
        });
        let bytes = request.encode_to_bytes().expect("encode");
        assert!(bytes.contains(&PAYLOAD_KEY), "payload field expected");
        assert_eq!(prost::Message::encoded_len(&request), bytes.len());

        let decoded: Request<KeyValue> =
            crate::types::encoding::Decodeable::decode(bytes).expect("decode");
        assert_eq!(decoded, request);
    }
}
