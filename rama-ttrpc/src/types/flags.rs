use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Debug, Copy)]
    pub struct Flags: u8 {
        const REMOTE_CLOSED = 0x01;
        const REMOTE_OPEN = 0x02;
        const NO_DATA = 0x04;
    }
}
