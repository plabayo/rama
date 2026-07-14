use prost::bytes::{BufMut, Bytes, BytesMut};

use super::{BufMutExt, EncodeError, InvalidInput};

pub trait Encodeable {
    fn encode_raw(&self, buf: &mut impl BufMut) -> Result<(), InvalidInput>;
    fn encoded_len(&self) -> usize;

    fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        buf.ensure_capacity(self.encoded_len())?;
        self.encode_raw(buf)?;
        Ok(())
    }

    fn encode_to_bytes(&self) -> Result<Bytes, InvalidInput> {
        let length = self.encoded_len();
        let mut buf = BytesMut::with_capacity(length);
        self.encode_raw(&mut buf)?;
        Ok(buf.into())
    }
}

impl<T: prost::Message> Encodeable for T {
    fn encode_raw(&self, buf: &mut impl BufMut) -> Result<(), InvalidInput> {
        prost::Message::encode_raw(self, buf);
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        prost::Message::encoded_len(self)
    }
}
