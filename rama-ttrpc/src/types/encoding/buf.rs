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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_empty_and_remaining_guard_boundaries() {
        let empty: &[u8] = &[];
        empty.ensure_empty().expect("empty buffer is empty");
        empty.ensure_remaining(0).expect("zero bytes remain");
        assert!(matches!(
            empty.ensure_remaining(1),
            Err(DecodeError::UnexpectedEof)
        ));

        let two: &[u8] = &[1, 2];
        assert!(matches!(
            two.ensure_empty(),
            Err(DecodeError::RemainingBytes(2))
        ));
        two.ensure_remaining(2).expect("two bytes remain");
        assert!(matches!(
            two.ensure_remaining(3),
            Err(DecodeError::UnexpectedEof)
        ));
    }
}
