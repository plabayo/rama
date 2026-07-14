use prost::bytes::{Buf, Bytes};

use super::DecodeError;

pub trait TryIntoBuf {
    type Buf: Buf;
    fn try_into_buf(self) -> Result<Self::Buf, DecodeError>;
}

impl<B: Buf> TryIntoBuf for B {
    type Buf = B;
    fn try_into_buf(self) -> Result<Self::Buf, DecodeError> {
        Ok(self)
    }
}

#[derive(Debug)]
pub struct FallibleBuf<B: Buf = Bytes>(Result<B, DecodeError>);

impl<B: Buf> TryIntoBuf for FallibleBuf<B> {
    type Buf = B;
    fn try_into_buf(self) -> Result<Self::Buf, DecodeError> {
        self.0
    }
}

impl<'b, B: Buf> TryIntoBuf for &'b mut FallibleBuf<B> {
    type Buf = &'b mut B;
    fn try_into_buf(self) -> Result<Self::Buf, DecodeError> {
        self.0.as_mut().map_err(|err| err.clone())
    }
}

impl<B: Buf> From<Result<B, DecodeError>> for FallibleBuf<B> {
    fn from(value: Result<B, DecodeError>) -> Self {
        Self(value)
    }
}

impl<B: Buf + Clone> Clone for FallibleBuf<B> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
