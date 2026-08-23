use super::core::SockRef;

/// Borrow a platform socket as a [`SockRef`].
///
/// The blanket implementations cover standard, Tokio, and Rama socket types
/// through their platform-native borrowed socket traits.
pub trait AsSocketRef {
    /// Return a non-owning reference to this socket.
    fn as_socket_ref(&self) -> SockRef<'_>;
}

#[cfg(target_family = "unix")]
impl<T: std::os::fd::AsFd> AsSocketRef for T {
    #[inline]
    fn as_socket_ref(&self) -> SockRef<'_> {
        SockRef::from(self)
    }
}

#[cfg(target_os = "windows")]
impl<T: std::os::windows::io::AsSocket> AsSocketRef for T {
    #[inline]
    fn as_socket_ref(&self) -> SockRef<'_> {
        SockRef::from(self)
    }
}
