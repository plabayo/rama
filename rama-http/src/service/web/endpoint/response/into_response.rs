use super::{IntoResponseParts, ResponseParts};
use crate::Response;
use crate::body::{Body, Frame, SizeHint, StreamingBody};
use crate::service::web::response::Headers;
use crate::{
    StatusCode,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use rama_core::bytes::{Buf, Bytes, BytesMut, buf::Chain};
use rama_core::error::BoxError;
use rama_core::extensions::{Extensions, ExtensionsMut};
use rama_core::telemetry::tracing;
use rama_error::OpaqueError;
use rama_http_headers::{ContentDisposition, ContentType};
use rama_http_types::InfiniteReader;
use rama_http_types::mime;
use rama_utils::macros::all_the_tuples_no_last_special_case;
use std::{
    borrow::Cow,
    convert::Infallible,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

/// Trait for generating responses.
///
/// Types that implement `IntoResponse` can be returned from handlers.
///
/// # Implementing `IntoResponse`
///
/// You generally shouldn't have to implement `IntoResponse` manually, as rama
/// provides implementations for many common types.
pub trait IntoResponse {
    /// Create a response.
    fn into_response(self) -> Response;
}

/// Wrapper that can be used to turn an `IntoResponse` type into
/// something that implements `Into<Response>`.
pub struct StaticResponseFactory<T>(pub T);

impl<T: IntoResponse> From<StaticResponseFactory<T>> for Response {
    fn from(value: StaticResponseFactory<T>) -> Self {
        value.0.into_response()
    }
}

impl<T: fmt::Debug> fmt::Debug for StaticResponseFactory<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StaticResponseFactory")
            .field(&self.0)
            .finish()
    }
}

impl<T: Clone> Clone for StaticResponseFactory<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl IntoResponse for StatusCode {
    fn into_response(self) -> Response {
        let mut res = ().into_response();
        *res.status_mut() = self;
        res
    }
}

impl IntoResponse for () {
    fn into_response(self) -> Response {
        Body::empty().into_response()
    }
}

impl IntoResponse for Infallible {
    fn into_response(self) -> Response {
        match self {}
    }
}

impl IntoResponse for OpaqueError {
    // do not expose error in response for security reasons
    fn into_response(self) -> Response {
        tracing::debug!("unexpected error in HTTP handler: {self}; return 500 status code");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl<T, E> IntoResponse for Result<T, E>
where
    T: IntoResponse,
    E: IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Ok(value) => value.into_response(),
            Err(err) => err.into_response(),
        }
    }
}

impl<B> IntoResponse for Response<B>
where
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    fn into_response(self) -> Response {
        self.map(Body::new)
    }
}

impl IntoResponse for crate::response::Parts {
    fn into_response(self) -> Response {
        Response::from_parts(self, Body::empty())
    }
}

impl IntoResponse for Body {
    fn into_response(self) -> Response {
        Response::new(self)
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        Cow::Borrowed(self).into_response()
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        Cow::<'static, str>::Owned(self).into_response()
    }
}

impl IntoResponse for Box<str> {
    fn into_response(self) -> Response {
        String::from(self).into_response()
    }
}

impl IntoResponse for Cow<'static, str> {
    fn into_response(self) -> Response {
        let mut res = Body::from(self).into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(mime::TEXT_PLAIN_UTF_8.as_ref()),
        );
        res
    }
}

impl IntoResponse for Bytes {
    fn into_response(self) -> Response {
        let mut res = Body::from(self).into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(mime::APPLICATION_OCTET_STREAM.as_ref()),
        );
        res
    }
}

impl IntoResponse for BytesMut {
    fn into_response(self) -> Response {
        self.freeze().into_response()
    }
}

impl IntoResponse for InfiniteReader {
    fn into_response(self) -> Response {
        (
            Headers((ContentDisposition::inline(), ContentType::octet_stream())),
            self.into_body(),
        )
            .into_response()
    }
}

impl<T, U> IntoResponse for Chain<T, U>
where
    T: Buf + Unpin + Send + Sync + 'static,
    U: Buf + Unpin + Send + Sync + 'static,
{
    fn into_response(self) -> Response {
        let (first, second) = self.into_inner();
        let mut res = Response::new(Body::new(BytesChainBody {
            first: Some(first),
            second: Some(second),
        }));
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(mime::APPLICATION_OCTET_STREAM.as_ref()),
        );
        res
    }
}

struct BytesChainBody<T, U> {
    first: Option<T>,
    second: Option<U>,
}

impl<T, U> StreamingBody for BytesChainBody<T, U>
where
    T: Buf + Unpin,
    U: Buf + Unpin,
{
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(mut buf) = self.first.take() {
            let bytes = buf.copy_to_bytes(buf.remaining());
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }

        if let Some(mut buf) = self.second.take() {
            let bytes = buf.copy_to_bytes(buf.remaining());
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }

        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.first.is_none() && self.second.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        match (self.first.as_ref(), self.second.as_ref()) {
            (Some(first), Some(second)) => {
                let total_size = first.remaining() + second.remaining();
                SizeHint::with_exact(total_size as u64)
            }
            (Some(buf), None) => SizeHint::with_exact(buf.remaining() as u64),
            (None, Some(buf)) => SizeHint::with_exact(buf.remaining() as u64),
            (None, None) => SizeHint::with_exact(0),
        }
    }
}

impl IntoResponse for &'static [u8] {
    fn into_response(self) -> Response {
        Cow::Borrowed(self).into_response()
    }
}

impl<const N: usize> IntoResponse for &'static [u8; N] {
    fn into_response(self) -> Response {
        self.as_slice().into_response()
    }
}

impl<const N: usize> IntoResponse for [u8; N] {
    fn into_response(self) -> Response {
        self.to_vec().into_response()
    }
}

impl IntoResponse for Vec<u8> {
    fn into_response(self) -> Response {
        Cow::<'static, [u8]>::Owned(self).into_response()
    }
}

impl IntoResponse for Box<[u8]> {
    fn into_response(self) -> Response {
        Vec::from(self).into_response()
    }
}

impl IntoResponse for Cow<'static, [u8]> {
    fn into_response(self) -> Response {
        let mut res = Body::from(self).into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(mime::APPLICATION_OCTET_STREAM.as_ref()),
        );
        res
    }
}

impl<R> IntoResponse for (StatusCode, R)
where
    R: IntoResponse,
{
    fn into_response(self) -> Response {
        let mut res = self.1.into_response();
        *res.status_mut() = self.0;
        res
    }
}

impl IntoResponse for HeaderMap {
    fn into_response(self) -> Response {
        let mut res = ().into_response();
        *res.headers_mut() = self;
        res
    }
}

impl IntoResponse for Extensions {
    fn into_response(self) -> Response {
        let mut res = ().into_response();
        *res.extensions_mut() = self;
        res
    }
}

impl<K, V, const N: usize> IntoResponse for [(K, V); N]
where
    K: TryInto<HeaderName, Error: fmt::Display>,
    V: TryInto<HeaderValue, Error: fmt::Display>,
{
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}

impl<R> IntoResponse for (crate::response::Parts, R)
where
    R: IntoResponse,
{
    fn into_response(self) -> Response {
        let (parts, res) = self;
        (parts.status, parts.headers, parts.extensions, res).into_response()
    }
}

impl<R> IntoResponse for (crate::response::Response<()>, R)
where
    R: IntoResponse,
{
    fn into_response(self) -> Response {
        let (template, res) = self;
        let (parts, ()) = template.into_parts();
        (parts, res).into_response()
    }
}

impl<R> IntoResponse for (R,)
where
    R: IntoResponse,
{
    fn into_response(self) -> Response {
        let (res,) = self;
        res.into_response()
    }
}

macro_rules! impl_into_response {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<R, $($ty,)*> IntoResponse for ($($ty),*, R)
        where
            $( $ty: IntoResponseParts, )*
            R: IntoResponse,
        {
            fn into_response(self) -> Response {
                let ($($ty),*, res) = self;

                let res = res.into_response();
                let parts = ResponseParts { res };

                $(
                    let parts = match $ty.into_response_parts(parts) {
                        Ok(parts) => parts,
                        Err(err) => {
                            return err.into_response();
                        }
                    };
                )*

                parts.res
            }
        }

        #[allow(non_snake_case)]
        impl<R, $($ty,)*> IntoResponse for (StatusCode, $($ty),*, R)
        where
            $( $ty: IntoResponseParts, )*
            R: IntoResponse,
        {
            fn into_response(self) -> Response {
                let (status, $($ty),*, res) = self;

                let res = res.into_response();
                let parts = ResponseParts { res };

                $(
                    let parts = match $ty.into_response_parts(parts) {
                        Ok(parts) => parts,
                        Err(err) => {
                            return err.into_response();
                        }
                    };
                )*

                (status, parts.res).into_response()
            }
        }

        #[allow(non_snake_case)]
        impl<R, $($ty,)*> IntoResponse for (crate::response::Parts, $($ty),*, R)
        where
            $( $ty: IntoResponseParts, )*
            R: IntoResponse,
        {
            fn into_response(self) -> Response {
                let (outer_parts, $($ty),*, res) = self;

                let res = res.into_response();
                let parts = ResponseParts { res };
                $(
                    let parts = match $ty.into_response_parts(parts) {
                        Ok(parts) => parts,
                        Err(err) => {
                            return err.into_response();
                        }
                    };
                )*

                (outer_parts, parts.res).into_response()
            }
        }

        #[allow(non_snake_case)]
        impl<R, $($ty,)*> IntoResponse for (crate::response::Response<()>, $($ty),*, R)
        where
            $( $ty: IntoResponseParts, )*
            R: IntoResponse,
        {
            fn into_response(self) -> Response {
                let (template, $($ty),*, res) = self;
                let (parts, ()) = template.into_parts();
                (parts, $($ty),*, res).into_response()
            }
        }
    }
}

all_the_tuples_no_last_special_case!(impl_into_response);

macro_rules! impl_into_response_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> IntoResponse for rama_core::combinators::$id<$($param),+>
        where
            $($param: IntoResponse),+
        {
            fn into_response(self) -> Response {
                match self {
                    $(
                        rama_core::combinators::$id::$param(val) => val.into_response(),
                    )+
                }
            }
        }
    };
}

rama_core::combinators::impl_either!(impl_into_response_either);

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::combinators::Either;

    #[test]
    fn test_either_into_response() {
        let left: Either<&'static str, Vec<u8>> = Either::A("hello");
        let right: Either<&'static str, Vec<u8>> = Either::B(vec![1, 2, 3]);

        let left_res = left.into_response();
        assert_eq!(
            left_res.headers().get(header::CONTENT_TYPE).unwrap(),
            mime::TEXT_PLAIN_UTF_8.as_ref()
        );

        let right_res = right.into_response();
        assert_eq!(
            right_res.headers().get(header::CONTENT_TYPE).unwrap(),
            mime::APPLICATION_OCTET_STREAM.as_ref()
        );
    }

    #[test]
    fn test_either3_into_response() {
        use rama_core::combinators::Either3;

        let a: Either3<&'static str, Vec<u8>, StatusCode> = Either3::A("hello");
        let b: Either3<&'static str, Vec<u8>, StatusCode> = Either3::B(vec![1, 2, 3]);
        let c: Either3<&'static str, Vec<u8>, StatusCode> = Either3::C(StatusCode::NOT_FOUND);

        let a_res = a.into_response();
        assert_eq!(
            a_res.headers().get(header::CONTENT_TYPE).unwrap(),
            mime::TEXT_PLAIN_UTF_8.as_ref()
        );

        let b_res = b.into_response();
        assert_eq!(
            b_res.headers().get(header::CONTENT_TYPE).unwrap(),
            mime::APPLICATION_OCTET_STREAM.as_ref()
        );

        let c_res = c.into_response();
        assert_eq!(c_res.status(), StatusCode::NOT_FOUND);
    }
}
