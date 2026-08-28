#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use super::{ForceStatusCode, IntoResponseFailed, IntoResponseParts, ResponseParts};
use crate::Response;
use crate::body::{Body, Frame, SizeHint, StreamingBody};
use crate::service::web::response::Headers;
use crate::{
    StatusCode,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use rama_core::bytes::{Buf, Bytes, BytesMut, buf::Chain};
use rama_core::error::BoxError;
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::telemetry::tracing;
use rama_http_headers::{ContentDisposition, ContentLength, ContentType, HeaderMapExt};
use rama_http_types::InfiniteReader;
use rama_http_types::mime;
use rama_utils::macros::all_the_tuples_no_last_special_case;
use rama_utils::str::arcstr::ArcStr;
use std::{
    borrow::Cow,
    convert::Infallible,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

/// Implement [`IntoResponse`] for an owned, sized body type by streaming it
/// through [`Body`] and tagging the response with the given `Content-Type` plus
/// an exact `Content-Length` (from the value's `len()`).
macro_rules! impl_into_response_sized_body {
    ($t:ty, $content_type:expr) => {
        impl IntoResponse for $t {
            fn into_response(self) -> Response {
                let len = self.len();
                let mut res = Body::from(self).into_response();
                res.headers_mut().typed_insert($content_type);
                res.headers_mut().typed_insert(ContentLength(len as u64));
                res
            }
        }
    };
}

/// Trait for generating responses.
///
/// Types that implement `IntoResponse` can be returned from handlers.
///
/// # Implementing `IntoResponse`
///
/// You generally shouldn't have to implement `IntoResponse` manually, as rama
/// provides implementations for many common types.
#[diagnostic::on_unimplemented(
    note = "See `rama_http::service::web::response::IntoResponse` for supported response types"
)]
pub trait IntoResponse {
    /// Create a response.
    #[must_use]
    fn into_response(self) -> Response;
}

/// Wrapper that can be used to turn an `IntoResponse` type into
/// something that implements `Into<Response>`.
#[derive(Debug, Clone)]
#[must_use]
pub struct StaticResponseFactory<T>(pub T);

impl<T: IntoResponse> From<StaticResponseFactory<T>> for Response {
    fn from(value: StaticResponseFactory<T>) -> Self {
        value.0.into_response()
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

impl IntoResponse for BoxError {
    // do not expose error in response for security reasons
    fn into_response(self) -> Response {
        tracing::debug!("unexpected error in HTTP handler: {self}; return 500 status code");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl IntoResponse for rama_core::layer::limit::policy::RateLimitReached {
    fn into_response(self) -> Response {
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        let secs = self.retry_after.as_secs() + u64::from(self.retry_after.subsec_nanos() > 0);
        response
            .headers_mut()
            .typed_insert(rama_http_headers::RetryAfter::delay(
                rama_http_headers::util::Seconds::new(secs),
            ));
        response
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
    #[inline(always)]
    fn into_response(self) -> Response {
        Cow::Borrowed(self).into_response()
    }
}

impl IntoResponse for String {
    #[inline(always)]
    fn into_response(self) -> Response {
        Cow::<'static, str>::Owned(self).into_response()
    }
}

impl IntoResponse for Box<str> {
    #[inline(always)]
    fn into_response(self) -> Response {
        String::from(self).into_response()
    }
}

impl_into_response_sized_body!(Cow<'static, str>, ContentType::text_utf8());
impl_into_response_sized_body!(ArcStr, ContentType::text_utf8());
impl_into_response_sized_body!(&ArcStr, ContentType::text_utf8());
impl_into_response_sized_body!(Bytes, ContentType::octet_stream());

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
    #[inline(always)]
    fn into_response(self) -> Response {
        self.as_slice().into_response()
    }
}

impl<const N: usize> IntoResponse for [u8; N] {
    #[inline(always)]
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

impl_into_response_sized_body!(Cow<'static, [u8]>, ContentType::octet_stream());

impl<R> IntoResponse for (StatusCode, R)
where
    R: IntoResponse,
{
    fn into_response(self) -> Response {
        let mut res = self.1.into_response();
        if res.extensions().get_ref::<IntoResponseFailed>().is_none() {
            *res.status_mut() = self.0;
        }
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
        let res = ().into_response();
        res.extensions().extend(&self);
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
                let failure_status = res
                    .extensions()
                    .get_ref::<IntoResponseFailed>()
                    .map(|_| res.status());
                let parts = ResponseParts { res };
                let mut parts = match ($($ty,)*).into_response_parts(parts) {
                    Ok(parts) => parts,
                    Err(err) => return err.into_response(),
                };
                if let Some(status) = failure_status {
                    *parts.res.status_mut() = status;
                }
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
                let failure_status = res
                    .extensions()
                    .get_ref::<IntoResponseFailed>()
                    .map(|_| res.status());
                let parts = ResponseParts { res };
                let mut parts = match ($($ty,)*).into_response_parts(parts) {
                    Ok(parts) => parts,
                    Err(err) => return err.into_response(),
                };
                *parts.res.status_mut() = failure_status.unwrap_or(status);
                parts.res
            }
        }

        #[allow(non_snake_case)]
        impl<R, $($ty,)*> IntoResponse for (ForceStatusCode, $($ty),*, R)
        where
            $( $ty: IntoResponseParts, )*
            R: IntoResponse,
        {
            fn into_response(self) -> Response {
                let (status, $($ty),*, res) = self;

                let res = res.into_response();
                let parts = ResponseParts { res };
                let parts = match ($($ty,)*).into_response_parts(parts) {
                    Ok(parts) => parts,
                    Err(err) => return err.into_response(),
                };

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
                let failure_status = res
                    .extensions()
                    .get_ref::<IntoResponseFailed>()
                    .map(|_| res.status());
                let parts = ResponseParts { res };
                let mut parts = match ($($ty,)*).into_response_parts(parts) {
                    Ok(parts) => parts,
                    Err(err) => return err.into_response(),
                };
                *parts.res.status_mut() = failure_status.unwrap_or(outer_parts.status);
                parts.res.headers_mut().extend(outer_parts.headers);
                parts.res.extensions().extend(&outer_parts.extensions);
                parts.res
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
    use rama_http_types::body::util::BodyExt as _;
    use rama_utils::str::arcstr::arcstr;
    use serde::Serialize;

    #[derive(Debug, Clone, Copy)]
    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom(
                "intentional serialization failure",
            ))
        }
    }

    #[test]
    fn outer_status_does_not_hide_response_conversion_failures() {
        for response in [
            (StatusCode::CREATED, super::super::Json(FailingSerialize)).into_response(),
            (StatusCode::CREATED, super::super::Form(FailingSerialize)).into_response(),
            (StatusCode::CREATED, super::super::Csv([FailingSerialize])).into_response(),
        ] {
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(
                response
                    .extensions()
                    .get_ref::<IntoResponseFailed>()
                    .is_some()
            );
        }
    }

    #[test]
    fn response_parts_survive_inner_failure_without_hiding_status() {
        #[derive(Debug, Clone, Copy, rama_core::extensions::Extension)]
        struct TestResponseExtension;

        let extensions = rama_core::extensions::Extensions::new();
        extensions.insert(TestResponseExtension);
        let response = (
            [("x-error-context", "preserved")],
            extensions,
            super::super::Json(FailingSerialize),
        )
            .into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()["x-error-context"], "preserved");
        assert!(
            response
                .extensions()
                .get_ref::<TestResponseExtension>()
                .is_some()
        );

        for response in [
            (
                super::super::Redirect::temporary("/next"),
                super::super::Json(FailingSerialize),
            )
                .into_response(),
            (
                StatusCode::CREATED,
                super::super::Redirect::temporary("/next"),
                super::super::Json(FailingSerialize),
            )
                .into_response(),
        ] {
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(response.headers()[crate::header::LOCATION], "/next");
        }

        let template = Response::builder()
            .status(StatusCode::CREATED)
            .header("x-template-context", "preserved")
            .body(())
            .unwrap();
        template.extensions().insert(TestResponseExtension);
        let response = (template, super::super::Json(FailingSerialize)).into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()["x-template-context"], "preserved");
        assert!(
            response
                .extensions()
                .get_ref::<TestResponseExtension>()
                .is_some()
        );
    }

    #[test]
    fn response_part_failure_is_marked() {
        let response = (
            StatusCode::CREATED,
            [("x-invalid", "line one\nline two")],
            "body",
        )
            .into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            response
                .extensions()
                .get_ref::<IntoResponseFailed>()
                .is_some()
        );
    }

    #[test]
    fn force_status_code_explicitly_overrides_failure() {
        let response = (
            ForceStatusCode(StatusCode::IM_A_TEAPOT),
            [("x-forced", "true")],
            super::super::Json(FailingSerialize),
        )
            .into_response();

        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(response.headers()["x-forced"], "true");

        let response = ForceStatusCode(StatusCode::ACCEPTED).into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[test]
    fn ordinary_outer_status_still_overrides_success() {
        let response = (StatusCode::CREATED, "created").into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[test]
    fn response_parts_exposes_status_accessors() {
        let mut parts = ResponseParts {
            res: StatusCode::ACCEPTED.into_response(),
        };
        assert_eq!(parts.status(), StatusCode::ACCEPTED);
        *parts.status_mut() = StatusCode::NO_CONTENT;
        assert_eq!(parts.status(), StatusCode::NO_CONTENT);
    }

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

    macro_rules! test_content_length_content_type {
        ($val:expr, $len:expr, $ct:expr) => {{
            let n = $len;
            let resp = $val.into_response();
            let content_length: usize = resp
                .headers()
                .get("content-length")
                .unwrap()
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(n, content_length);
            let ct: ContentType = resp.headers().typed_get().unwrap();
            assert_eq!($ct, ct);
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(n, bytes.len());
        }};
    }

    #[tokio::test]
    async fn test_content_length_types_into_response() {
        test_content_length_content_type!("str", 3, ContentType::text_utf8());
        test_content_length_content_type!("string".to_owned(), 6, ContentType::text_utf8());
        test_content_length_content_type!(
            Cow::Borrowed("Cow::Borrowed"),
            13,
            ContentType::text_utf8()
        );
        test_content_length_content_type!(
            Cow::Borrowed("Cow::Owned").into_owned(),
            10,
            ContentType::text_utf8()
        );
        test_content_length_content_type!(
            Bytes::from_static(b"Bytes::from_static"),
            18,
            ContentType::octet_stream()
        );
        test_content_length_content_type!(
            Bytes::from("Bytes::from"),
            11,
            ContentType::octet_stream()
        );
        test_content_length_content_type!(b"&[u8]", 5, ContentType::octet_stream());
        test_content_length_content_type!(*b"[u8]", 4, ContentType::octet_stream());
        test_content_length_content_type!(b"Vec<u8>".to_vec(), 7, ContentType::octet_stream());
        test_content_length_content_type!(
            Cow::Borrowed(b"Cow::Borrowed::<u8>"),
            19,
            ContentType::octet_stream()
        );
        test_content_length_content_type!(
            Cow::Borrowed(b"Cow::Owned::<u8>").into_owned(),
            16,
            ContentType::octet_stream()
        );
        test_content_length_content_type!(arcstr!("ArcStr"), 6, ContentType::text_utf8());
    }
}
