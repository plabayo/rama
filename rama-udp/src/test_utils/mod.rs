//! Utilities for testing datagram protocols without operating-system sockets.

mod memory;
pub use memory::{
    MemoryDatagramControl, MemoryDatagramFaultStats, MemoryDatagramSender, MemoryDatagramSocket,
};

/// The native "message too large" send error, as the socket layer reports it after
/// `EMSGSIZE`, for injecting oversized-send failures into tests.
///
/// Classified as [`crate::SendFailure::TooLarge`] on platforms with a native code.
pub fn message_too_large_error() -> std::io::Error {
    #[cfg(unix)]
    {
        std::io::Error::from_raw_os_error(libc::EMSGSIZE)
    }
    #[cfg(windows)]
    {
        std::io::Error::from_raw_os_error(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::io::Error::other("message too large")
    }
}
