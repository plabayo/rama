use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Debug, Copy)]
    pub struct Flags: u8 {
        const REMOTE_CLOSED = 0x01;
        const REMOTE_OPEN = 0x02;
        const NO_DATA = 0x04;
    }
}

impl Flags {
    /// Whether these flags are valid on an incoming Data frame: per the ttRPC spec a Data frame
    /// may carry only `REMOTE_CLOSED` and/or `NO_DATA` (and no undefined bits).
    pub(crate) fn is_valid_data_frame(self) -> bool {
        self.difference(Self::REMOTE_CLOSED | Self::NO_DATA)
            .is_empty()
    }

    /// Whether these flags are valid on an incoming Response frame: per the spec no Response flags
    /// are defined, so they must be empty.
    pub(crate) fn is_valid_response_frame(self) -> bool {
        self.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::Flags;

    #[test]
    fn data_frame_flags() {
        assert!(Flags::empty().is_valid_data_frame());
        assert!(Flags::REMOTE_CLOSED.is_valid_data_frame());
        assert!(Flags::NO_DATA.is_valid_data_frame());
        assert!((Flags::REMOTE_CLOSED | Flags::NO_DATA).is_valid_data_frame());
        // REMOTE_OPEN and undefined bits are not permitted on Data frames.
        assert!(!Flags::REMOTE_OPEN.is_valid_data_frame());
        assert!(!(Flags::REMOTE_CLOSED | Flags::REMOTE_OPEN).is_valid_data_frame());
        assert!(!Flags::from_bits_retain(0x08).is_valid_data_frame());
    }

    #[test]
    fn response_frame_flags() {
        assert!(Flags::empty().is_valid_response_frame());
        assert!(!Flags::REMOTE_CLOSED.is_valid_response_frame());
        assert!(!Flags::NO_DATA.is_valid_response_frame());
        assert!(!Flags::from_bits_retain(0x08).is_valid_response_frame());
    }
}
