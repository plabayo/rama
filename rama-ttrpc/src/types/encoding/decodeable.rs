use prost::bytes::Buf;

use super::{BufExt as _, DecodeError, TryIntoBuf};

pub trait Decodeable: Sized {
    fn decode_raw(buf: impl Buf) -> Result<Self, DecodeError>;
    fn decode(buf: impl TryIntoBuf) -> Result<Self, DecodeError> {
        let mut buf = buf.try_into_buf()?;
        let val = Self::decode_raw(&mut buf)?;
        buf.ensure_empty()?;
        Ok(val)
    }
}

impl<T: prost::Message + Default> Decodeable for T {
    fn decode_raw(buf: impl Buf) -> Result<Self, DecodeError> {
        Ok(prost::Message::decode(buf)?)
    }
}
