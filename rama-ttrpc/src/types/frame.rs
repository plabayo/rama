use std::cmp::min;
use std::fmt::Debug;
use std::io::Result as IoResult;

use prost::bytes::{Buf, BufMut, Bytes, BytesMut};
use rama_utils::octets::{kib, mib};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::types::encoding::{BufExt as _, DecodeError, Decodeable, Encodeable, InvalidInput};
use crate::types::flags::Flags;
use crate::types::message::{FallibleBytesMessage, Message};
use crate::types::protos::raw_bytes::ProstField;
use crate::types::protos::{Response, Status};

const MAX_DATA_LENGTH: usize = mib(4);
pub(crate) const HEADER_LENGTH: usize = 10;
const DISCARD_PAGE_SIZE: usize = kib(4);

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
        let n = reader.read(&mut buf[..bytes_to_read]).await?;
        if n == 0 {
            // EOF before the announced payload was drained: the peer under-delivered. Surface
            // it instead of looping forever on `read` == 0.
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed while discarding an oversized ttRPC frame",
            ));
        }
        n_bytes -= n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer can announce an oversized `data_length` and then close the connection before
    /// sending that many bytes. `discard_bytes` must treat the resulting `read` == 0 (EOF) as
    /// an error instead of spinning forever, or the connection task hangs and burns CPU.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_frame_bytes_errors_on_oversized_length_then_eof() {
        let mut header = [0u8; HEADER_LENGTH];
        // data_length in bytes 0..4 (big-endian), one MiB past the cap so we hit the discard path.
        let oversized = (MAX_DATA_LENGTH + mib(1)) as u32;
        header[0..4].copy_from_slice(&oversized.to_be_bytes());

        let handle = tokio::spawn(async move {
            // An owned reader that yields only the 10-byte header, then EOF (`read` -> Ok(0)).
            let mut reader = std::io::Cursor::new(header.to_vec());
            read_frame_bytes(&mut reader).await
        });

        let result = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;

        let joined =
            result.expect("read_frame_bytes hung discarding an oversized frame that ended early");
        assert!(
            joined.expect("read task panicked").is_err(),
            "expected an early-EOF error, not a silent success"
        );
    }
}
