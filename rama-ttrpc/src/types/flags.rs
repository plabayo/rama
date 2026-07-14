use bitflags::bitflags;

bitflags! {
    /// ttRPC frame flags. Undefined bits are reserved by the spec; like the Go
    /// implementation (containerd/ttrpc server.go/client.go, which only ever test
    /// individual bits with `&`), we ignore unknown bits instead of rejecting them.
    #[derive(Clone, Debug, Copy)]
    pub struct Flags: u8 {
        const REMOTE_CLOSED = 0x01;
        const REMOTE_OPEN = 0x02;
        const NO_DATA = 0x04;
    }
}
