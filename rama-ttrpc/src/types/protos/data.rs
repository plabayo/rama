use prost::bytes::{Buf, BufMut};

use super::raw_bytes::RawBytes;
use crate::types::encoding::{DecodeError, Decodeable, Encodeable, InvalidInput};
use crate::types::message::{Message, MessageType};

#[derive(Clone, PartialEq, Debug, Default)]
pub(crate) struct Data<Payload = RawBytes> {
    pub payload: Payload,
}

impl<Payload> Message for Data<Payload> {
    const TYPE_ID: MessageType = MessageType::Data;
}

impl<Payload: Encodeable> Encodeable for Data<Payload> {
    fn encode_raw(&self, buf: &mut impl BufMut) -> Result<(), InvalidInput> {
        Encodeable::encode_raw(&self.payload, buf)
    }
    fn encoded_len(&self) -> usize {
        Encodeable::encoded_len(&self.payload)
    }
}

impl<Payload: Decodeable> Decodeable for Data<Payload> {
    fn decode_raw(buf: impl Buf) -> Result<Self, DecodeError> {
        let payload = Payload::decode(buf)?;
        Ok(Self { payload })
    }
}
