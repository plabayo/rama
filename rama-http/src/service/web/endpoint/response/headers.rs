use super::{IntoResponse, IntoResponseParts, ResponseParts};
use crate::Response;
use crate::headers::{Header, HeaderMapExt};
use rama_utils::macros::all_the_tuples_no_last_special_case;

/// Use typed [`Header`]s i a response.
pub struct Headers<T>(pub T);

impl<H: Header> Headers<(H,)> {
    /// Create a Header singleton tuple.
    pub fn single(h: H) -> Self {
        Self((h,))
    }
}

macro_rules! headers_into_response {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty),+> IntoResponse for Headers<($($ty),+,)>
        where
            $(
                $ty: $crate::headers::Header,
            )+
        {
            fn into_response(self) -> Response {
                (self, ()).into_response()
            }
        }
    }
}

all_the_tuples_no_last_special_case!(headers_into_response);

macro_rules! headers_into_response_parts {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty),+> IntoResponseParts for Headers<($($ty),+,)>
        where
            $(
                $ty: $crate::headers::Header,
            )+
        {
            type Error = std::convert::Infallible;

            fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
                let Headers((
                    $($ty),+
                    ,
                )) = self;
                $(
                    res.headers_mut().typed_insert(&$ty);
                )+
                Ok(res)
            }
        }
    }
}

all_the_tuples_no_last_special_case!(headers_into_response_parts);
