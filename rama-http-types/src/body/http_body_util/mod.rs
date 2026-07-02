// Forked from the `http-body-util` crate — vendored alongside the forked
// `http-body`. See `docs/thirdparty/fork/README.md`. Fork-style lint allows
// (also cover the child combinator modules).
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

//! Utilities for [`crate::body::http_body::Body`].
//!
//! [`BodyExt`] adds extensions to the common trait.
//!
//! [`Empty`] and [`Full`] provide simple implementations.

pub mod channel;
mod collect_error;
mod collect_with;
mod collected;
pub mod combinators;
mod either;
mod empty;
mod full;
mod limited;
mod stream;

mod util;

use self::combinators::{BoxBody, MapErr, MapFrame, UnsyncBoxBody};
use rama_core::error::BoxError;

pub use self::channel::Channel;
pub use self::collect_error::{CollectError, CollectErrorKind};
pub use self::collect_with::{CollectOptions, CollectWith};
pub use self::collected::Collected;
pub use self::either::Either;
pub use self::empty::Empty;
pub use self::full::Full;
pub use self::limited::{LengthLimitError, Limited};
pub use self::stream::{BodyDataStream, BodyStream, StreamBody};

/// An extension trait for [`crate::body::http_body::Body`] adding various combinators and adapters
pub trait BodyExt: crate::body::http_body::Body {
    /// Returns a future that resolves to the next [`Frame`], if any.
    ///
    /// [`Frame`]: combinators::Frame
    fn frame(&mut self) -> combinators::Frame<'_, Self>
    where
        Self: Unpin,
    {
        combinators::Frame(self)
    }

    /// Maps this body's frame to a different kind.
    fn map_frame<F, B>(self, f: F) -> MapFrame<Self, F>
    where
        Self: Sized,
        F: FnMut(crate::body::http_body::Frame<Self::Data>) -> crate::body::http_body::Frame<B>,
        B: bytes::Buf,
    {
        MapFrame::new(self, f)
    }

    /// A body that calls a function with a reference to each frame before yielding it.
    fn inspect_frame<F>(self, f: F) -> combinators::InspectFrame<Self, F>
    where
        Self: Sized,
        F: FnMut(&crate::body::http_body::Frame<Self::Data>),
    {
        combinators::InspectFrame::new(self, f)
    }

    /// Maps this body's error value to a different value.
    fn map_err<F, E>(self, f: F) -> MapErr<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Error) -> E,
    {
        MapErr::new(self, f)
    }

    /// A body that calls a function with a reference to an error before yielding it.
    fn inspect_err<F>(self, f: F) -> combinators::InspectErr<Self, F>
    where
        Self: Sized,
        F: FnMut(&Self::Error),
    {
        combinators::InspectErr::new(self, f)
    }

    /// Turn this body into a boxed trait object.
    fn boxed(self) -> BoxBody<Self::Data, Self::Error>
    where
        Self: Sized + Send + Sync + 'static,
    {
        BoxBody::new(self)
    }

    /// Turn this body into a boxed trait object that is !Sync.
    fn boxed_unsync(self) -> UnsyncBoxBody<Self::Data, Self::Error>
    where
        Self: Sized + Send + 'static,
    {
        UnsyncBoxBody::new(self)
    }

    /// Turn this body into [`Collected`] body which will collect all the DATA frames
    /// and trailers.
    ///
    /// On a body stream error the returned future yields a [`CollectError`] that
    /// still carries the bytes read before the failure. Use [`collect_with`] to
    /// additionally bound the size and/or time and keep the unread remainder
    /// forwardable.
    ///
    /// [`collect_with`]: BodyExt::collect_with
    fn collect(self) -> combinators::Collect<Self>
    where
        Self: Sized,
    {
        combinators::Collect {
            body: self,
            collected: Some(crate::body::http_body_util::Collected::default()),
        }
    }

    /// Collect this body, but bounded by the size cap and/or timeout in
    /// [`CollectOptions`].
    ///
    /// On success returns the [`Collected`] body, exactly like [`collect`]. When
    /// a bound is hit it stops early with a [`CollectError`] that retains the
    /// bytes read so far *and* the unread remainder — call
    /// [`CollectError::into_full_body`] to reassemble and forward the body on
    /// untouched (handy for proxies).
    ///
    /// This is the soft, recoverable counterpart to [`Limited`]: where `Limited`
    /// hard-fails with a [`LengthLimitError`] and discards the body the moment
    /// its cap is crossed, `collect_with` loses nothing — the bytes read and the
    /// remainder are both preserved.
    ///
    /// [`collect`]: BodyExt::collect
    /// [`Limited`]: crate::body::http_body_util::Limited
    /// [`LengthLimitError`]: crate::body::http_body_util::LengthLimitError
    /// [`CollectError::into_full_body`]: crate::body::http_body_util::CollectError::into_full_body
    fn collect_with(self, opts: CollectOptions) -> CollectWith<Self>
    where
        Self: Sized
            + crate::body::http_body::Body<Data = bytes::Bytes, Error: Into<BoxError>>
            + Send
            + Sync
            + Unpin
            + 'static,
    {
        CollectWith::new(self, opts)
    }

    /// Add trailers to the body.
    ///
    /// The trailers will be sent when all previous frames have been sent and the `trailers` future
    /// resolves.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_types::HeaderMap;
    /// use rama_http_types::body::util::{Full, BodyExt};
    /// use rama_core::bytes::Bytes;
    ///
    /// # #[tokio::main]
    /// async fn main() {
    /// let (tx, rx) = tokio::sync::oneshot::channel::<HeaderMap>();
    ///
    /// let body = Full::<Bytes>::from("Hello, World!")
    ///     // add trailers via a future
    ///     .with_trailers(async move {
    ///         match rx.await {
    ///             Ok(trailers) => Some(Ok(trailers)),
    ///             Err(_err) => None,
    ///         }
    ///     });
    ///
    /// // compute the trailers in the background
    /// tokio::spawn(async move {
    ///     let _ = tx.send(compute_trailers().await);
    /// });
    ///
    /// async fn compute_trailers() -> HeaderMap {
    ///     // ...
    ///     # unimplemented!()
    /// }
    /// # }
    /// ```
    fn with_trailers<F>(self, trailers: F) -> combinators::WithTrailers<Self, F>
    where
        Self: Sized,
        F: std::future::Future<Output = Option<Result<crate::HeaderMap, Self::Error>>>,
    {
        combinators::WithTrailers::new(self, trailers)
    }

    /// Turn this body into [`BodyDataStream`].
    fn into_data_stream(self) -> BodyDataStream<Self>
    where
        Self: Sized,
    {
        BodyDataStream::new(self)
    }

    /// Turn this body into [`BodyStream`].
    fn into_stream(self) -> BodyStream<Self>
    where
        Self: Sized,
    {
        BodyStream::new(self)
    }

    /// Creates a fused body.
    ///
    /// This [`Body`][crate::body::http_body::Body] yields `Poll::Ready(None)` forever after the
    /// underlying body yields `Poll::Ready(None)`, or an error `Poll::Ready(Some(Err(_)))`, once.
    ///
    /// See [`Fuse<B>`][combinators::Fuse] for more information.
    fn fuse(self) -> combinators::Fuse<Self>
    where
        Self: Sized,
    {
        combinators::Fuse::new(self)
    }
}

impl<T: ?Sized> BodyExt for T where T: crate::body::http_body::Body {}
