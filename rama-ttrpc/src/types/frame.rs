use std::fmt::Debug;
use std::io::Result as IoResult;

use prost::bytes::{Buf, BufMut, Bytes, BytesMut};
use rama_utils::octets::mib;
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::types::encoding::{BufExt as _, DecodeError, Decodeable, Encodeable, InvalidInput};
use crate::types::flags::Flags;
use crate::types::message::{FallibleBytesMessage, Message};
use crate::types::protos::raw_bytes::ProstField;
use crate::types::protos::{Response, Status};

const MAX_DATA_LENGTH: usize = mib(4);
pub(crate) const HEADER_LENGTH: usize = 10;

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
            Err(DecodeError::OversizedMessage {
                length,
                max: MAX_DATA_LENGTH,
            })
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
        // Discard the oversized payload to stay frame-synced and keep the connection (and its
        // other in-flight calls) alive; decoding the header-only frame yields an
        // `OversizedMessage` error that is reported per-stream as `RESOURCE_EXHAUSTED`,
        // matching the Go implementation (containerd/ttrpc channel.go `recv`: `Discard` +
        // `codes.ResourceExhausted`).
        let mut limited = (&mut *readable).take(data_length as u64);
        let discarded = tokio::io::copy(&mut limited, &mut tokio::io::sink()).await?;
        if discarded != data_length as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed while discarding an oversized ttRPC frame",
            ));
        }
        return Ok(buf.into());
    }

    buf.resize(HEADER_LENGTH + data_length, 0);
    readable.read_exact(&mut buf[HEADER_LENGTH..]).await?;

    Ok(buf.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oversized_header(data_length: usize) -> Vec<u8> {
        let mut data = vec![0u8; HEADER_LENGTH];
        // data_length in bytes 0..4 (big-endian).
        #[expect(clippy::cast_possible_truncation)]
        data[0..4].copy_from_slice(&(data_length as u32).to_be_bytes());
        data[8] = 1; // message type: Request
        data
    }

    /// Go parity (containerd/ttrpc channel.go `recv`): an oversized frame is discarded from
    /// the wire — keeping the connection frame-synced for the frames behind it — and decodes
    /// to a deferred `OversizedMessage` error instead of killing the connection.
    #[tokio::test]
    async fn read_frame_bytes_discards_oversized_payload_and_stays_synced() {
        let oversized = MAX_DATA_LENGTH + mib(1);
        let mut data = oversized_header(oversized);
        data.resize(HEADER_LENGTH + oversized, 0);
        // A well-formed empty frame behind the oversized one.
        data.extend_from_slice(&oversized_header(0));

        let mut reader = std::io::Cursor::new(data);

        let bytes = read_frame_bytes(&mut reader)
            .await
            .expect("oversized frame must not kill the connection");
        assert_eq!(
            reader.position(),
            (HEADER_LENGTH + oversized) as u64,
            "the full declared payload must be discarded to stay frame-synced"
        );
        let frame = Frame::decode(bytes).expect("header-only frame decodes");
        assert!(
            matches!(
                frame.message.decode::<crate::types::protos::Request>(),
                Err(DecodeError::OversizedMessage { .. })
            ),
            "accessing the message must yield the deferred oversized error"
        );

        // The connection is still usable: the next frame parses cleanly.
        let next = read_frame_bytes(&mut reader).await.expect("next frame");
        assert_eq!(next.len(), HEADER_LENGTH);
    }

    /// A peer that closes mid-payload while we discard must surface an EOF error rather
    /// than hang or succeed.
    #[tokio::test]
    async fn read_frame_bytes_errors_on_eof_while_discarding_oversized_frame() {
        let mut data = oversized_header(MAX_DATA_LENGTH + mib(1));
        // Only part of the declared payload is ever sent.
        data.resize(HEADER_LENGTH + 100_000, 0);

        let mut reader = std::io::Cursor::new(data);
        let err = read_frame_bytes(&mut reader)
            .await
            .expect_err("truncated oversized frame must error");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
