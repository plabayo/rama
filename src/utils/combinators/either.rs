use std::fmt;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, Error as IoError, ReadBuf, Result as IoResult};

#[macro_export]
#[doc(hidden)]
/// Implement the `Either` type for the available number of type parameters,
/// using the given macro to define each variant.
macro_rules! __impl_either {
    ($macro:ident) => {
        $macro!(Either, A, B,);
        $macro!(Either3, A, B, C,);
        $macro!(Either4, A, B, C, D,);
        $macro!(Either5, A, B, C, D, E,);
        $macro!(Either6, A, B, C, D, E, F,);
        $macro!(Either7, A, B, C, D, E, F, G,);
        $macro!(Either8, A, B, C, D, E, F, G, H,);
        $macro!(Either9, A, B, C, D, E, F, G, H, I,);
    };
}

#[doc(inline)]
pub use crate::__impl_either as impl_either;

macro_rules! define_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        /// A type to allow you to use multiple types as a single type.
        ///
        /// and will delegate the functionality to the type that is wrapped in the `Either` type.
        /// To keep it easy all wrapped types are expected to work with the same inputs and outputs.
        ///
        /// You can use [`crate::utils::combinators::impl_either`] to
        /// implement the `Either` type for the available number of type parameters
        /// on your own Trait implementations.
        pub enum $id<$($param),+> {
            $(
                /// one of the Either variants
                $param($param),
            )+
        }

        impl<$($param),+> Clone for $id<$($param),+>
        where
            $($param: Clone),+
        {
            fn clone(&self) -> Self {
                match self {
                    $(
                        $id::$param(s) => $id::$param(s.clone()),
                    )+
                }
            }
        }

        impl<$($param),+> fmt::Debug for $id<$($param),+>
        where
            $($param: fmt::Debug),+
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(
                        $id::$param(s) => write!(f, "{:?}", s),
                    )+
                }
            }
        }

        impl<$($param),+> fmt::Display for $id<$($param),+>
        where
            $($param: fmt::Display),+
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(
                        $id::$param(s) => write!(f, "{}", s),
                    )+
                }
            }
        }
    };
}

impl_either!(define_either);

macro_rules! impl_iterator_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, Item> Iterator for $id<$($param),+>
        where
            $($param: Iterator<Item = Item>),+,
        {
            type Item = Item;

            fn next(&mut self) -> Option<Item> {
                match self {
                    $(
                        $id::$param(iter) => iter.next(),
                    )+
                }
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                match self {
                    $(
                        $id::$param(iter) => iter.size_hint(),
                    )+
                }
            }
        }
    };
}

impl_either!(impl_iterator_either);

macro_rules! impl_async_read_write_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> AsyncRead for $id<$($param),+>
        where
            $($param: AsyncRead + Unpin),+,
        {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<IoResult<()>> {
                match &mut *self {
                    $(
                        $id::$param(reader) => Pin::new(reader).poll_read(cx, buf),
                    )+
                }
            }
        }

        impl<$($param),+> AsyncWrite for $id<$($param),+>
        where
            $($param: AsyncWrite + Unpin),+,
        {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, IoError>> {
                match &mut *self {
                    $(
                        $id::$param(writer) => Pin::new(writer).poll_write(cx, buf),
                    )+
                }
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), IoError>> {
                match &mut *self {
                    $(
                        $id::$param(writer) => Pin::new(writer).poll_flush(cx),
                    )+
                }
            }

            fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), IoError>> {
                match &mut *self {
                    $(
                        $id::$param(writer) => Pin::new(writer).poll_shutdown(cx),
                    )+
                }
            }

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                bufs: &[IoSlice<'_>],
            ) -> Poll<Result<usize, IoError>> {
                match &mut *self {
                    $(
                        $id::$param(writer) => Pin::new(writer).poll_write_vectored(cx, bufs),
                    )+
                }
            }

            fn is_write_vectored(&self) -> bool {
                match self {
                    $(
                        $id::$param(reader) => reader.is_write_vectored(),
                    )+
                }
            }
        }
    };
}

impl_either!(impl_async_read_write_either);
