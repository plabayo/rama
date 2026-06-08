use super::core::IntoHtml;
use crate::Response;
use crate::headers::ContentType;
use crate::service::web::response::{Headers, IntoResponse};

/// The output of an element macro (`html!`, `div!`, ..., `custom!`).
///
/// `HtmlBuf<T>` is a thin newtype around the macro-generated tuple `T`
/// that implements both [`IntoHtml`] (so it can be nested in larger
/// templates) and
/// [`IntoResponse`](crate::service::web::response::IntoResponse) (so a
/// rendered page can be returned directly from a handler with
/// `Content-Type: text/html; charset=utf-8`).
///
/// Users normally do not name this type — they receive it from the
/// macros and either compose it further or return it. It is, however,
/// public so that handler signatures can mention it explicitly when
/// desired.
#[derive(Debug, Clone, Copy)]
pub struct HtmlBuf<T>(pub T);

impl<T: IntoHtml> IntoHtml for HtmlBuf<T> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self.0
    }

    #[inline]
    fn escape_and_write(self, buf: &mut String)
    where
        Self: Sized,
    {
        self.0.escape_and_write(buf);
    }

    #[inline]
    fn size_hint(&self) -> usize {
        self.0.size_hint()
    }
}

impl<T: IntoHtml> IntoResponse for HtmlBuf<T> {
    fn into_response(self) -> Response {
        let body = self.0.into_string();
        (Headers::single(ContentType::html_utf8()), body).into_response()
    }
}
