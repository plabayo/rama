use prost::bytes::{Buf, BufMut};

use super::{DecodeError, EncodeError};

pub(crate) trait BufMutExt: BufMut {
    fn ensure_capacity(&self, required: usize) -> Result<(), EncodeError> {
        let capacity = self.remaining_mut();
        if capacity < required {
            return Err(EncodeError::InsuficientCapacity { required, capacity });
        }
        Ok(())
    }
}

impl<B: BufMut> BufMutExt for B {}

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
