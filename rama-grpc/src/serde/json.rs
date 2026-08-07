use ::serde::{Serialize, de::DeserializeOwned};
use rama_core::bytes::{Buf, BufMut};
use rama_core::error::BoxError;

use super::{SerdeCodec, SerdeFormat};
use crate::codec::{DecodeBuf, EncodeBuf};

/// The JSON [`SerdeFormat`], as implemented by [`serde_json`].
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct JsonFormat;

impl SerdeFormat for JsonFormat {
    fn serialize<T: Serialize>(item: &T, buf: &mut EncodeBuf<'_>) -> Result<(), BoxError> {
        serde_json::to_writer(buf.writer(), item).map_err(Into::into)
    }

    fn deserialize<T: DeserializeOwned>(buf: &mut DecodeBuf<'_>) -> Result<T, BoxError> {
        let item = serde_json::from_slice(buf.chunk())?;

        let len = buf.remaining();
        buf.advance(len);

        Ok(item)
    }
}

/// A [`SerdeCodec`] which encodes `T` and decodes `U` as JSON.
pub type JsonCodec<T, U> = SerdeCodec<JsonFormat, T, U>;

#[cfg(test)]
mod tests {
    use rama_core::bytes::BytesMut;
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::Code;
    use crate::codec::{Codec as _, Decoder as _, Encoder as _};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Message {
        answer: u8,
        question: String,
    }

    fn message() -> Message {
        Message {
            answer: 42,
            question: "?".to_owned(),
        }
    }

    #[test]
    fn round_trip() {
        let mut codec = JsonCodec::<Message, Message>::default();

        let mut buf = BytesMut::new();
        codec
            .encoder()
            .encode(message(), &mut EncodeBuf::new(&mut buf))
            .unwrap();
        assert_eq!(buf, br#"{"answer":42,"question":"?"}"#[..]);

        let len = buf.len();
        let decoded = codec
            .decoder()
            .decode(&mut DecodeBuf::new(&mut buf, len))
            .unwrap();

        assert_eq!(decoded, Some(message()));
    }

    #[test]
    fn decode_of_malformed_message_errors_as_internal() {
        let mut buf = BytesMut::from(&b"{\"answer\":"[..]);
        let len = buf.len();

        let status = JsonCodec::<Message, Message>::default()
            .decoder()
            .decode(&mut DecodeBuf::new(&mut buf, len))
            .unwrap_err();

        assert_eq!(status.code(), Code::Internal);
    }
}
