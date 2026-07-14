use prost::bytes::Buf;

use super::DecodeError;

pub(crate) trait BufExt: Buf {
    fn ensure_empty(&self) -> Result<(), DecodeError> {
        let remaining = self.remaining();
        if remaining != 0 {
            return Err(DecodeError::RemainingBytes(remaining));
        }
        Ok(())
    }

    fn ensure_remaining(&self, required: usize) -> Result<(), DecodeError> {
        let remaining = self.remaining();
        if remaining < required {
            return Err(DecodeError::UnexpectedEof);
        }
        Ok(())
    }
}

impl<B: Buf> BufExt for B {}
