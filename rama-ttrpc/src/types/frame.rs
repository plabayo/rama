use std::cmp::min;
use std::fmt::Debug;
use std::io::Result as IoResult;

use prost::bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::types::encoding::{BufExt as _, DecodeError, Decodeable, Encodeable, InvalidInput};
use crate::types::flags::Flags;
use crate::types::message::{FallibleBytesMessage, Message};
use crate::types::protos::raw_bytes::ProstField;
use crate::types::protos::{Response, Status};

const MAX_DATA_LENGTH: usize = 4 << 20;
const HEADER_LENGTH: usize = 10;
const DISCARD_PAGE_SIZE: usize = 4 << 10;

#[derive(Clone, Debug)]
pub struct Frame<Msg = FallibleBytesMessage> {
    pub id: u32,
    pub flags: Flags,
    pub message: Msg,
}

#[derive(Clone, Debug)]
pub struct StreamFrame<Msg = FallibleBytesMessage> {
    pub flags: Flags,
    pub message: Msg,
}

impl<Msg> StreamFrame<Msg> {
    pub fn into_frame(self, id: u32) -> Frame<Msg> {
        let flags = self.flags;
        let message = self.message;
        Frame { id, flags, message }
    }
}

impl<Msg> Frame<Msg> {
    pub fn into_stream_frame(self) -> StreamFrame<Msg> {
        let flags = self.flags;
        let message = self.message;
        StreamFrame { flags, message }
    }
}

impl<Payload: ProstField + Default> From<Response<Payload>> for StreamFrame<Response<Payload>> {
    fn from(message: Response<Payload>) -> Self {
        let flags = Flags::empty();
        Self { flags, message }
    }
}

impl From<Status> for StreamFrame<Response<()>> {
    fn from(status: Status) -> Self {
        let flags = Flags::empty();
        let message = Response::error(status);
        Self { flags, message }
    }
}

impl<Msg: Message + Encodeable> Encodeable for Frame<Msg> {
    fn encode_raw(&self, mut buf: &mut impl BufMut) -> Result<(), InvalidInput> {
        let length = self.message.encoded_len();
        if length > MAX_DATA_LENGTH {
            let msg = format!("Oversized payload: {length} bytes > {MAX_DATA_LENGTH} bytes");
            return Err(msg.into());
        }

        #[expect(clippy::cast_possible_truncation)]
        buf.put_u32(length as u32);
        buf.put_u32(self.id);
        buf.put_u8(u8::from(Msg::TYPE_ID));
        buf.put_u8(self.flags.bits());
        self.message.encode_raw(&mut buf)?;

        Ok(())
    }

    fn encoded_len(&self) -> usize {
        HEADER_LENGTH + self.message.encoded_len()
    }
}

impl Decodeable for Frame<FallibleBytesMessage> {
    fn decode_raw(mut buf: impl Buf) -> Result<Self, DecodeError> {
        buf.ensure_remaining(HEADER_LENGTH)?;

        let length = buf.get_u32() as usize;
        let id = buf.get_u32();
        let ty = buf.get_u8().into();
        let flags = Flags::from_bits_retain(buf.get_u8());

        let bytes = if length > MAX_DATA_LENGTH {
            let msg = format!("Oversized payload: {length} bytes > {MAX_DATA_LENGTH} bytes");
            Err(DecodeError::InvalidInput(msg.into()))
        } else {
            buf.ensure_remaining(length)
                .map(|_| buf.copy_to_bytes(length))
        };
        let bytes = bytes.into();
        let message = FallibleBytesMessage { ty, bytes };

        Ok(Self { id, flags, message })
    }
}

pub(crate) async fn read_frame_bytes(readable: &mut (impl AsyncRead + Unpin)) -> IoResult<Bytes> {
    let mut buf = BytesMut::zeroed(HEADER_LENGTH);
    readable.read_exact(&mut buf).await?;

    let data_length = (&buf[0..4]).get_u32() as usize;
    if data_length > MAX_DATA_LENGTH {
        discard_bytes(readable, data_length).await?;
        // Return the buffer without the oversized payload
        // This should fail during the decode step
        return Ok(buf.into());
    }

    buf.resize(HEADER_LENGTH + data_length, 0);
    readable.read_exact(&mut buf[HEADER_LENGTH..]).await?;

    Ok(buf.into())
}

async fn discard_bytes(reader: &mut (impl AsyncRead + Unpin), mut n_bytes: usize) -> IoResult<()> {
    let mut buf = [0u8; DISCARD_PAGE_SIZE];
    while n_bytes > 0 {
        let bytes_to_read = min(buf.len(), n_bytes);
        n_bytes -= reader.read(&mut buf[..bytes_to_read]).await?;
    }
    Ok(())
}
