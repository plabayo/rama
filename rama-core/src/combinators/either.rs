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

#[macro_export]
#[doc(hidden)]
macro_rules! __define_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        /// A type to allow you to use multiple types as a single type.
        ///
        /// and will delegate the functionality to the type that is wrapped in the `Either` type.
        /// To keep it easy all wrapped types are expected to work with the same inputs and outputs.
        ///
        /// You can use [`crate::combinators::impl_either`] to
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


        impl<$($param),+> $id<$($param),+> {
            /// Convert `Pin<&mut Either<A, B>>` to `Either<Pin<&mut A>, Pin<&mut B>>`,
            /// pinned projections of the inner variants.
            fn as_pin_mut(self: Pin<&mut Self>) -> $id<$(Pin<&mut $param>),+> {
                // SAFETY: `get_unchecked_mut` is fine because we don't move anything.
                // We can use `new_unchecked` because the `inner` parts are guaranteed
                // to be pinned, as they come from `self` which is pinned, and we never
                // offer an unpinned `&mut A` or `&mut B` through `Pin<&mut Self>`. We
                // also don't have an implementation of `Drop`, nor manual `Unpin`.
                unsafe {
                    match self.get_unchecked_mut() {
                        $(
                            Self::$param(inner) => $id::$param(Pin::new_unchecked(inner)),
                        )+
                    }
                }
            }
        }

        impl<$($param),+, Output> std::future::Future for $id<$($param),+>
        where
            $($param: Future<Output = Output>),+
        {
            type Output = Output;

            fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
                match self.as_pin_mut() {
                    $(
                        $id::$param(fut) => fut.poll(cx),
                    )+
                }
            }
        }
    };
}

#[doc(inline)]
pub use crate::__define_either as define_either;

impl_either!(define_either);

#[macro_export]
#[doc(hidden)]
macro_rules! __impl_iterator_either {
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

#[doc(inline)]
pub use crate::__impl_iterator_either as impl_iterator_either;

impl_either!(impl_iterator_either);

#[macro_export]
#[doc(hidden)]
macro_rules! __impl_async_read_write_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        #[warn(clippy::missing_trait_methods)]
        impl<$($param),+> AsyncRead for $id<$($param),+>
        where
            $($param: AsyncRead),+,
        {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<IoResult<()>> {
                match self.as_pin_mut() {
                    $(
                        $id::$param(reader) => reader.poll_read(cx, buf),
                    )+
                }
            }
        }

        #[warn(clippy::missing_trait_methods)]
        impl<$($param),+> AsyncWrite for $id<$($param),+>
        where
            $($param: AsyncWrite),+,
        {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, IoError>> {
                match self.as_pin_mut() {
                    $(
                        $id::$param(writer) => writer.poll_write(cx, buf),
                    )+
                }
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), IoError>> {
                match self.as_pin_mut() {
                    $(
                        $id::$param(writer) => writer.poll_flush(cx),
                    )+
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), IoError>> {
                match self.as_pin_mut() {
                    $(
                        $id::$param(writer) => writer.poll_shutdown(cx),
                    )+
                }
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                bufs: &[IoSlice<'_>],
            ) -> Poll<Result<usize, IoError>> {
                match self.as_pin_mut() {
                    $(
                        $id::$param(writer) => writer.poll_write_vectored(cx, bufs),
                    )+
                }
            }

            fn is_write_vectored(&self) -> bool {
                match self {
                    $(
                        $id::$param(writer) => writer.is_write_vectored(),
                    )+
                }
            }
        }
    };
}

#[doc(inline)]
pub use crate::__impl_async_read_write_either as impl_async_read_write_either;

impl_either!(impl_async_read_write_either);
