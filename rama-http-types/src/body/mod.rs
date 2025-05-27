//! HTTP body utilities.

use crate::dep::{
    http_body::{self, Body as _, Frame},
    http_body_util::{self, BodyExt},
};
use futures_core::TryStream;
use futures_lite::stream::Stream;
use pin_project_lite::pin_project;
use rama_core::bytes::Bytes;
use rama_error::{BoxError, OpaqueError};
use std::pin::Pin;
use std::task::{Context, Poll};
use sync_wrapper::SyncWrapper;

mod limit;
pub use limit::BodyLimit;

mod ext;
pub use ext::BodyExtractExt;

pub mod sse;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

fn boxed<B>(body: B) -> BoxBody
where
    B: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    try_downcast(body).unwrap_or_else(|body| body.map_err(Into::into).boxed())
}

pub(crate) fn try_downcast<T, K>(k: K) -> Result<T, K>
where
    T: 'static,
    K: Send + 'static,
{
    let mut k = Some(k);
    if let Some(k) = <dyn std::any::Any>::downcast_mut::<Option<T>>(&mut k) {
        Ok(k.take().unwrap())
    } else {
        Err(k.unwrap())
    }
}

/// The body type used in rama requests and responses.
#[derive(Debug)]
pub struct Body(BoxBody);

impl Body {
    /// Create a new `Body` that wraps another [`http_body::Body`].
    pub fn new<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        try_downcast(body).unwrap_or_else(|body| Self(boxed(body)))
    }

    /// Create a new `Body` with a maximum size limit.
    pub fn with_limit<B>(body: B, limit: usize) -> Self
    where
        B: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        Self::new(crate::dep::http_body_util::Limited::new(body, limit))
    }

    /// Create an empty body.
    pub fn empty() -> Self {
        Self::new(http_body_util::Empty::new())
    }

    /// Create a new `Body` from a [`Stream`].
    ///
    /// [`Stream`]: https://docs.rs/futures-core/latest/futures_core/stream/trait.Stream.html
    pub fn from_stream<S>(stream: S) -> Self
    where
        S: TryStream<Ok: Into<Bytes>, Error: Into<BoxError>> + Send + 'static,
    {
        Self::new(StreamBody {
            stream: SyncWrapper::new(stream),
        })
    }

    // TODO
    // pub fn from_event_stream<S, E, T>(stream: S) -> Self
    // where
    //     S: Stream<Item = Result<sse::Event<T>, E>> + Send + 'static,
    //     E: Into<BoxError>,
    //     T: EventData,
    // {
    //     Self::new(SseBody::new(stream))
    // }

    /// Create a new [`Body`] from a [`Stream`] with a maximum size limit.
    pub fn limited(self, limit: usize) -> Self {
        Self::new(crate::dep::http_body_util::Limited::new(self.0, limit))
    }

    /// Convert the body into a [`Stream`] of data frames.
    ///
    /// Non-data frames (such as trailers) will be discarded. Use [`http_body_util::BodyStream`] if
    /// you need a [`Stream`] of all frame types.
    ///
    /// [`http_body_util::BodyStream`]: https://docs.rs/http-body-util/latest/http_body_util/struct.BodyStream.html
    pub fn into_data_stream(self) -> BodyDataStream {
        BodyDataStream { inner: self }
    }

    /// Stream a chunk of the response body.
    ///
    /// When the response body has been exhausted, this will return `None`.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, BoxError> {
        // loop to ignore unrecognized frames
        loop {
            if let Some(res) = self.frame().await {
                let frame = res?;
                if let Ok(buf) = frame.into_data() {
                    return Ok(Some(buf));
                }
                // else continue
            } else {
                return Ok(None);
            }
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<()> for Body {
    fn from(_: ()) -> Self {
        Self::empty()
    }
}

macro_rules! body_from_impl {
    ($ty:ty) => {
        impl From<$ty> for Body {
            fn from(buf: $ty) -> Self {
                Self::new(http_body_util::Full::from(buf))
            }
        }
    };
}

body_from_impl!(&'static [u8]);
body_from_impl!(std::borrow::Cow<'static, [u8]>);
body_from_impl!(Vec<u8>);

body_from_impl!(&'static str);
body_from_impl!(std::borrow::Cow<'static, str>);
body_from_impl!(String);

body_from_impl!(Bytes);

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = OpaqueError;

    #[inline]
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.0)
            .poll_frame(cx)
            .map_err(OpaqueError::from_boxed)
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }
}

/// A stream of data frames.
///
/// Created with [`Body::into_data_stream`].
#[derive(Debug)]
pub struct BodyDataStream {
    inner: Body,
}

impl Stream for BodyDataStream {
    type Item = Result<Bytes, BoxError>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match futures_lite::ready!(Pin::new(&mut self.inner).poll_frame(cx)?) {
                Some(frame) => match frame.into_data() {
                    Ok(data) => return Poll::Ready(Some(Ok(data))),
                    Err(_frame) => {}
                },
                None => return Poll::Ready(None),
            }
        }
    }
}

impl http_body::Body for BodyDataStream {
    type Data = Bytes;
    type Error = BoxError;

    #[inline]
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx).map_err(Into::into)
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

pin_project! {
    struct StreamBody<S> {
        #[pin]
        stream: SyncWrapper<S>,
    }
}

impl<S> http_body::Body for StreamBody<S>
where
    S: TryStream<Ok: Into<Bytes>, Error: Into<BoxError>>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let stream = self.project().stream.get_pin_mut();
        match futures_lite::ready!(stream.try_poll_next(cx)) {
            Some(Ok(chunk)) => Poll::Ready(Some(Ok(Frame::data(chunk.into())))),
            Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
            None => Poll::Ready(None),
        }
    }
}

// /// A stream of Server-Side Events (SSE).
// ///
// /// Created with [`Body::into_event_stream`].
// #[derive(Debug)]
// pub struct BodyEventStream {
//     inner: Body,
// }

// impl Stream for BodyEventStream {
//     type Item = Result<sse::Event, BoxError>;

//     #[inline]
//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         loop {
//             match futures_lite::ready!(Pin::new(&mut self.inner).poll_frame(cx)?) {
//                 Some(frame) => match frame.into_data() {
//                     Ok(data) => return Poll::Ready(Some(Ok(data))),
//                     Err(_frame) => {}
//                 },
//                 None => return Poll::Ready(None),
//             }
//         }
//     }
// }

// impl http_body::Body for BodyEventStream {
//     type Data = Bytes;
//     type Error = BoxError;

//     #[inline]
//     fn poll_frame(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//     ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
//         Pin::new(&mut self.inner).poll_frame(cx).map_err(Into::into)
//     }

//     #[inline]
//     fn is_end_stream(&self) -> bool {
//         self.inner.is_end_stream()
//     }

//     #[inline]
//     fn size_hint(&self) -> http_body::SizeHint {
//         self.inner.size_hint()
//     }
// }

#[test]
fn test_try_downcast() {
    assert_eq!(try_downcast::<i32, _>(5_u32), Err(5_u32));
    assert_eq!(try_downcast::<i32, _>(5_i32), Ok(5_i32));
}
