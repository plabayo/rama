/// Encode a stable numeric tag for [`std::io::ErrorKind`].
#[must_use]
pub fn io_error_kind_code(kind: std::io::ErrorKind) -> u32 {
    match kind {
        std::io::ErrorKind::NotFound => 1,
        std::io::ErrorKind::PermissionDenied => 2,
        std::io::ErrorKind::ConnectionRefused => 3,
        std::io::ErrorKind::ConnectionReset => 4,
        std::io::ErrorKind::HostUnreachable => 5,
        std::io::ErrorKind::NetworkUnreachable => 6,
        std::io::ErrorKind::ConnectionAborted => 7,
        std::io::ErrorKind::NotConnected => 8,
        std::io::ErrorKind::AddrInUse => 9,
        std::io::ErrorKind::AddrNotAvailable => 10,
        std::io::ErrorKind::BrokenPipe => 11,
        std::io::ErrorKind::AlreadyExists => 12,
        std::io::ErrorKind::WouldBlock => 13,
        std::io::ErrorKind::InvalidInput => 14,
        std::io::ErrorKind::InvalidData => 15,
        std::io::ErrorKind::TimedOut => 16,
        std::io::ErrorKind::WriteZero => 17,
        std::io::ErrorKind::Interrupted => 18,
        std::io::ErrorKind::Unsupported => 19,
        std::io::ErrorKind::UnexpectedEof => 20,
        std::io::ErrorKind::OutOfMemory => 21,
        _ => u32::MAX,
    }
}

/// Extract a raw OS error code from an I/O error when available.
#[must_use]
pub fn io_error_raw_os_code(error: &std::io::Error) -> Option<i64> {
    error.raw_os_error().map(i64::from)
}
