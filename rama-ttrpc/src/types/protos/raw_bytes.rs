use prost::bytes::{Buf, BufMut, Bytes};
use prost::encoding::{DecodeContext, WireType};

use crate::types::encoding::{DecodeError, Decodeable, Encodeable, InvalidInput};

#[derive(Clone, Debug, Default)]
pub struct RawBytes(Bytes);

impl RawBytes {
    #[inline]
    pub fn decode<Msg: prost::Message + Default>(&self) -> Result<Msg, DecodeError> {
        Ok(Msg::decode(self.0.clone())?)
    }
}

impl Buf for RawBytes {
    #[inline]
    fn remaining(&self) -> usize {
        self.0.remaining()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.0.chunk()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        self.0.advance(cnt);
    }
}

/// A single protobuf message field, abstracted over how its payload is (de)serialized.
///
/// This lets a frame carry either a concrete `prost::Message` (encoded as a
/// length-delimited nested message) or an already-serialized [`RawBytes`] blob
/// (encoded as a `bytes` field) behind one interface, without the frame knowing which.
/// All methods operate on the field identified by `tag` within the surrounding message and
/// mirror the corresponding `prost::encoding` free functions.
pub trait ProstField: Send + Sync {
    /// Append this field — its `tag`, wire type and payload — to `buf`.
    ///
    /// Must write exactly [`encoded_len(tag)`](ProstField::encoded_len) bytes.
    fn encode(&self, tag: u32, buf: &mut impl BufMut);

    /// The number of bytes [`encode`](ProstField::encode) will write for this field at
    /// `tag`, including the key (tag + wire type) and any length prefix.
    fn encoded_len(&self, tag: u32) -> usize;

    /// Reset the value to its default/empty state (as after `Default::default`), so the
    /// same instance can be reused for a subsequent [`merge`](ProstField::merge).
    fn clear(&mut self);

    /// Decode one occurrence of this field from `buf` and merge it into `self`.
    ///
    /// `wire_type` and `ctx` come from the surrounding message decoder; `buf` is positioned
    /// just after the field key. Implementations must consume exactly this field's bytes and
    /// return an error (leaving `self` unspecified) on malformed input.
    fn merge(
        &mut self,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), prost::DecodeError>;
}

impl<T: prost::Message> ProstField for T {
    #[inline]
    fn encode(&self, tag: u32, buf: &mut impl BufMut) {
        prost::encoding::message::encode(tag, self, buf);
    }
    #[inline]
    fn encoded_len(&self, tag: u32) -> usize {
        prost::encoding::message::encoded_len(tag, self)
    }
    #[inline]
    fn clear(&mut self) {
        prost::Message::clear(self);
    }
    #[inline]
    fn merge(
        &mut self,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), prost::DecodeError> {
        prost::encoding::message::merge(wire_type, self, buf, ctx)
    }
}

impl ProstField for RawBytes {
    #[inline]
    fn encode(&self, tag: u32, buf: &mut impl BufMut) {
        prost::encoding::bytes::encode(tag, &self.0, buf);
    }
    #[inline]
    fn encoded_len(&self, tag: u32) -> usize {
        prost::encoding::bytes::encoded_len(tag, &self.0)
    }
    #[inline]
    fn clear(&mut self) {
        prost::Message::clear(&mut self.0);
    }
    #[inline]
    fn merge(
        &mut self,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), prost::DecodeError> {
        prost::encoding::bytes::merge(wire_type, &mut self.0, buf, ctx)
    }
}

impl Encodeable for RawBytes {
    #[inline]
    fn encode_raw(&self, buf: &mut impl BufMut) -> Result<(), InvalidInput> {
        buf.put(self.0.clone());
        Ok(())
    }

    #[inline]
    fn encoded_len(&self) -> usize {
        self.0.len()
    }
}

impl Decodeable for RawBytes {
    #[inline]
    fn decode_raw(mut buf: impl Buf) -> Result<Self, DecodeError> {
        Ok(Self(buf.copy_to_bytes(buf.remaining())))
    }
}
