// Forked from the `http-body` crate — vendored so its `Frame` trailers use
// rama's `HeaderMap`. See `docs/thirdparty/fork/README.md`.
// Fork-style lint allows (also cover the `frame`/`size_hint` child modules).
#![allow(
    unreachable_pub,
    clippy::allow_attributes,
    clippy::style,
    clippy::complexity,
    clippy::perf,
    clippy::suspicious,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::get_unwrap,
    clippy::assertions_on_result_states,
    clippy::let_underscore_must_use,
    clippy::multiple_unsafe_ops_per_block,
    clippy::unnecessary_safety_comment,
    clippy::map_err_ignore,
    dead_code,
    mismatched_lifetime_syntaxes,
    unsafe_op_in_unsafe_fn
)]

//! Asynchronous HTTP request or response body.
//!
//! See [`Body`] for more details.
//!
//! [`Body`]: trait.Body.html

mod frame;
mod size_hint;

pub use self::frame::Frame;
pub use self::size_hint::SizeHint;

use bytes::{Buf, Bytes};
use std::convert::Infallible;
use std::ops;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Trait representing a streaming body of a Request or Response.
///
/// Individual frames are streamed via the `poll_frame` function, which asynchronously yields
/// instances of [`Frame<Data>`].
///
/// Frames can contain a data buffer of type `Self::Data`. Frames can also contain an optional
/// set of trailers used to finalize the request/response exchange. This is mostly used when using
/// the HTTP/2.0 protocol.
///
/// The `size_hint` function provides insight into the total number of bytes that will be streamed.
pub trait Body {
    /// Values yielded by the `Body`.
    type Data: Buf;

    /// The error type this `Body` might generate.
    type Error;

    #[allow(clippy::type_complexity)]
    /// Attempt to pull out the next data buffer of this stream.
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>>;

    /// Returns `true` when the end of stream has been reached.
    ///
    /// An end of stream means that `poll_frame` will return `None`.
    ///
    /// A return value of `false` **does not** guarantee that a value will be
    /// returned from `poll_frame`.
    fn is_end_stream(&self) -> bool {
        false
    }

    /// Returns the bounds on the remaining length of the stream.
    ///
    /// When the **exact** remaining length of the stream is known, the upper bound will be set and
    /// will equal the lower bound.
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl<T: Body + Unpin + ?Sized> Body for &mut T {
    type Data = T::Data;
    type Error = T::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut **self).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        Pin::new(&**self).is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        Pin::new(&**self).size_hint()
    }
}

impl<P> Body for Pin<P>
where
    P: Unpin + ops::DerefMut,
    P::Target: Body,
{
    type Data = <<P as ops::Deref>::Target as Body>::Data;
    type Error = <<P as ops::Deref>::Target as Body>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::get_mut(self).as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.as_ref().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.as_ref().size_hint()
    }
}

impl<T: Body + Unpin + ?Sized> Body for Box<T> {
    type Data = T::Data;
    type Error = T::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut **self).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.as_ref().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.as_ref().size_hint()
    }
}

impl Body for String {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if !self.is_empty() {
            let s = std::mem::take(&mut *self);
            Poll::Ready(Some(Ok(Frame::data(s.into_bytes().into()))))
        } else {
            Poll::Ready(None)
        }
    }

    fn is_end_stream(&self) -> bool {
        self.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len() as u64)
    }
}

#[cfg(test)]
fn _assert_bounds() {
    fn can_be_trait_object(_: &dyn Body<Data = std::io::Cursor<Vec<u8>>, Error = std::io::Error>) {}
}
