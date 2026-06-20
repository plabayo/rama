//! Utilities that operate on a [`Stream`]
//!
//! [`Stream`]: rama_core::io::Io

pub mod matcher;

pub mod layer;
pub mod service;

mod socket;
#[doc(inline)]
pub use socket::{Socket, SocketInfo};

/// Implements [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`] for a
/// pin-projected newtype by delegating every method to the named inner field.
///
/// The wrapped type must obtain its projection through `pin_project!` with
/// `$field` marked `#[pin]`. Used by the `TcpStream`/`UnixStream` wrappers,
/// which only differ in the inner stream they hold.
#[doc(hidden)]
#[macro_export]
macro_rules! rama_delegate_async_read_write {
    ($ty:ty => $field:ident) => {
        #[warn(clippy::missing_trait_methods)]
        impl ::tokio::io::AsyncRead for $ty {
            fn poll_read(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
                buf: &mut ::tokio::io::ReadBuf<'_>,
            ) -> ::std::task::Poll<::std::io::Result<()>> {
                self.project().$field.poll_read(cx, buf)
            }
        }

        #[warn(clippy::missing_trait_methods)]
        impl ::tokio::io::AsyncWrite for $ty {
            fn poll_write(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
                buf: &[u8],
            ) -> ::std::task::Poll<::std::io::Result<usize>> {
                self.project().$field.poll_write(cx, buf)
            }

            fn poll_write_vectored(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
                bufs: &[::std::io::IoSlice<'_>],
            ) -> ::std::task::Poll<::std::io::Result<usize>> {
                self.project().$field.poll_write_vectored(cx, bufs)
            }

            fn poll_flush(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
            ) -> ::std::task::Poll<::std::io::Result<()>> {
                self.project().$field.poll_flush(cx)
            }

            fn poll_shutdown(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
            ) -> ::std::task::Poll<::std::io::Result<()>> {
                self.project().$field.poll_shutdown(cx)
            }

            fn is_write_vectored(&self) -> bool {
                self.$field.is_write_vectored()
            }
        }
    };
}

pub mod dep {
    //! Dependencies for rama stream modules.
    //!
    //! Exported for your convenience.

    pub mod ipnet {
        //! Re-export of the [`ipnet`] crate.
        //!
        //! Types for IPv4 and IPv6 network addresses.
        //!
        //! [`ipnet`]: https://docs.rs/ipnet

        #[doc(inline)]
        pub use ipnet::*;
    }
}
