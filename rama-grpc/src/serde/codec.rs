use std::marker::PhantomData;

use ::serde::{Serialize, de::DeserializeOwned};
use rama_core::error::BoxError;

use crate::Status;
use crate::codec::{BufferSettings, Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};

/// The wire format used by a [`SerdeCodec`].
///
/// The `JsonFormat` in crate implements this trait for JSON,
/// and is the reference for implementing it for another format.
pub trait SerdeFormat: Send + Sync + 'static {
    /// Serialize `item` into `buf`.
    fn serialize<T: Serialize>(item: &T, buf: &mut EncodeBuf<'_>) -> Result<(), BoxError>;

    /// Deserialize a message from `buf`, which contains exactly one full message.
    ///
    /// The buffer has to be consumed: whatever is left in it is read back as the start of
    /// the next message.
    fn deserialize<T: DeserializeOwned>(buf: &mut DecodeBuf<'_>) -> Result<T, BoxError>;
}

/// A [`Codec`] which encodes `T` and decodes `U` using serde and the format `F` (: [`SerdeFormat`]).
pub struct SerdeCodec<F, T, U> {
    _pd: PhantomData<fn() -> (F, T, U)>,
}

impl<F, T, U> SerdeCodec<F, T, U> {
    /// Create a new [`SerdeCodec`].
    #[must_use]
    pub fn new() -> Self {
        Self { _pd: PhantomData }
    }
}

impl<F, T, U> Default for SerdeCodec<F, T, U> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F, T, U> Clone for SerdeCodec<F, T, U> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<F, T, U> std::fmt::Debug for SerdeCodec<F, T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerdeCodec").finish()
    }
}

impl<F, T, U> Codec for SerdeCodec<F, T, U>
where
    F: SerdeFormat,
    T: Serialize + Send + Sync + 'static,
    U: DeserializeOwned + Send + Sync + 'static,
{
    type Encode = T;
    type Decode = U;

    type Encoder = SerdeEncoder<F, T>;
    type Decoder = SerdeDecoder<F, U>;

    fn encoder(&mut self) -> Self::Encoder {
        SerdeEncoder::new(BufferSettings::default())
    }

    fn decoder(&mut self) -> Self::Decoder {
        SerdeDecoder::new(BufferSettings::default())
    }
}

/// An [`Encoder`] which knows how to serialize `T` using the format `F`.
pub struct SerdeEncoder<F, T> {
    _pd: PhantomData<fn() -> (F, T)>,
    buffer_settings: BufferSettings,
}

impl<F, T> SerdeEncoder<F, T> {
    /// Get a new encoder with explicit buffer settings
    #[must_use]
    pub fn new(buffer_settings: BufferSettings) -> Self {
        Self {
            _pd: PhantomData,
            buffer_settings,
        }
    }
}

impl<F, T> std::fmt::Debug for SerdeEncoder<F, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerdeEncoder")
            .field("buffer_settings", &self.buffer_settings)
            .finish()
    }
}

impl<F: SerdeFormat, T: Serialize> Encoder for SerdeEncoder<F, T> {
    type Item = T;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, buf: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        F::serialize(&item, buf).map_err(Status::from_error_generic)
    }

    fn buffer_settings(&self) -> BufferSettings {
        self.buffer_settings
    }
}

/// A [`Decoder`] which knows how to deserialize `U` using the format `F`.
pub struct SerdeDecoder<F, U> {
    _pd: PhantomData<fn() -> (F, U)>,
    buffer_settings: BufferSettings,
}

impl<F, U> SerdeDecoder<F, U> {
    /// Get a new decoder with explicit buffer settings
    #[must_use]
    pub fn new(buffer_settings: BufferSettings) -> Self {
        Self {
            _pd: PhantomData,
            buffer_settings,
        }
    }
}

impl<F, U> std::fmt::Debug for SerdeDecoder<F, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerdeDecoder")
            .field("buffer_settings", &self.buffer_settings)
            .finish()
    }
}

impl<F: SerdeFormat, U: DeserializeOwned> Decoder for SerdeDecoder<F, U> {
    type Item = U;
    type Error = Status;

    fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        // A malformed message is reported as an error rather than as `Ok(None)`,
        // which would make us wait for bytes that are never coming.
        F::deserialize(buf)
            .map(Some)
            .map_err(|err| Status::internal(err.to_string()))
    }

    fn buffer_settings(&self) -> BufferSettings {
        self.buffer_settings
    }
}
