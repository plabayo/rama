//! Private (internal) implementation of the HTML rendering primitives.
//!
//! This module is a lightly simplified, permanent fork of
//! [`vy-core`](https://github.com/JonahLund/vy). The original `Either*`
//! types have been removed in favour of [`rama_core::combinators::Either`]
//! and friends (see [`super::either_impls`]). `no_std` support, `Cow`,
//! `IpAddr`, etc. impls have been dropped — we have full `std`/`alloc`
//! available and `rama-http` already provides richer ways of plugging in
//! arbitrary values.

#![expect(
    clippy::allow_attributes,
    reason = "vendored from `vy-core`: macro-internal `#[allow(non_snake_case)]` attrs whose underlying lint fires only for some tuple-arity expansions"
)]

use std::{
    borrow::Cow,
    fmt::{self, Write as _},
};

/// A type that can be rendered as a fragment of HTML.
///
/// This is the central trait of the HTML templating support. Built-in
/// scalars (e.g. `&str`, `String`, `bool`, integers, floats) all
/// implement it; new types can implement it either by returning a
/// composition of other [`IntoHtml`] values, or — for "leaf" types —
/// by overriding [`IntoHtml::escape_and_write`] directly.
///
/// # Examples
///
/// Compose nested HTML elements using macros:
///
/// ```ignore
/// use rama_http::html::*;
///
/// struct Article { title: String, content: String, author: String }
///
/// impl IntoHtml for Article {
///     fn into_html(self) -> impl IntoHtml {
///         article!(
///             h1!(self.title),
///             p!(class = "content", self.content),
///             footer!("Written by ", self.author),
///         )
///     }
/// }
/// ```
///
/// For leaf types, **return `self`** to terminate the rendering chain
/// and override [`IntoHtml::escape_and_write`]:
///
/// ```ignore
/// use rama_http::html::{IntoHtml, escape_into};
///
/// struct TextNode(String);
///
/// impl IntoHtml for TextNode {
///     fn into_html(self) -> impl IntoHtml { self }
///     fn escape_and_write(self, buf: &mut String) { escape_into(buf, &self.0); }
///     fn size_hint(&self) -> usize { self.0.len() }
/// }
/// ```
pub trait IntoHtml {
    /// Convert this value into another [`IntoHtml`] value. Used for
    /// composition; leaf types should return `self`.
    fn into_html(self) -> impl IntoHtml;

    /// Append the rendered (escaped) HTML to `buf`.
    #[inline]
    fn escape_and_write(self, buf: &mut String)
    where
        Self: Sized,
    {
        self.into_html().escape_and_write(buf);
    }

    /// Best-effort estimate of the rendered byte length, used to
    /// pre-allocate the output buffer.
    #[inline]
    fn size_hint(&self) -> usize {
        0
    }

    /// Render to a freshly allocated `String`.
    fn into_string(self) -> String
    where
        Self: Sized,
    {
        let html = self.into_html();
        let size = html.size_hint();
        let mut buf = String::with_capacity(size + (size / 10));
        html.escape_and_write(&mut buf);
        buf
    }
}

/// HTML-escape `input` into `output` (`&`, `<`, `>`, `"`, `'`).
///
/// Escaping `'` as `&#x27;` is required so that interpolating untrusted
/// strings into single-quoted attribute contexts (e.g. `<input value='…'>`)
/// is safe. `&apos;` is intentionally not used because it is not part of
/// HTML4 and some older agents do not recognize it.
#[inline]
pub fn escape_into(output: &mut String, input: &str) {
    for ch in input.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            _ => output.push(ch),
        }
    }
}

/// HTML-escape `input` and return the resulting `String`.
#[inline]
pub fn escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    escape_into(&mut output, input);
    output
}

/// Wrapper that marks its inner value as already-escaped HTML — i.e. it
/// will be written verbatim instead of going through [`escape_into`].
///
/// This is the type the macros emit for the static (literal) parts of a
/// template; users normally only construct it explicitly when they want
/// to splice trusted HTML into a template (e.g. an icon SVG).
#[derive(Debug, Clone, Copy)]
pub struct PreEscaped<T>(pub T);

impl<T: fmt::Display> fmt::Display for PreEscaped<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl IntoHtml for PreEscaped<&str> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        buf.push_str(self.0);
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.0.len()
    }
}

impl IntoHtml for PreEscaped<String> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        buf.push_str(&self.0);
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.0.len()
    }
}

impl IntoHtml for PreEscaped<char> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        buf.push(self.0);
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.0.len_utf8()
    }
}

impl IntoHtml for PreEscaped<Cow<'static, str>> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        buf.push_str(&self.0);
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.0.len()
    }
}

// ---- scalar / std impls ----------------------------------------------------

impl IntoHtml for &str {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        escape_into(buf, self)
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.len()
    }
}

impl IntoHtml for char {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        escape_into(buf, self.encode_utf8(&mut [0; 4]));
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.len_utf8()
    }
}

impl IntoHtml for String {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        escape_into(buf, &self)
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.len()
    }
}

impl IntoHtml for &String {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        escape_into(buf, self)
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.len()
    }
}

impl IntoHtml for Cow<'static, str> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        escape_into(buf, self.as_ref())
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.as_ref().len()
    }
}

impl IntoHtml for bool {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        if self { "true" } else { "false" }
    }
    #[inline]
    fn size_hint(&self) -> usize {
        5
    }
}

impl<T: IntoHtml> IntoHtml for Option<T> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        if let Some(x) = self {
            x.escape_and_write(buf)
        }
    }
    #[inline]
    fn size_hint(&self) -> usize {
        match self {
            Some(x) => x.size_hint(),
            None => 0,
        }
    }
}

impl IntoHtml for () {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, _: &mut String) {}
}

impl<F: FnOnce(&mut String)> IntoHtml for F {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        (self)(buf)
    }
}

impl<B: IntoHtml, I: ExactSizeIterator, F> IntoHtml for std::iter::Map<I, F>
where
    F: FnMut(I::Item) -> B,
{
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        let len = self.len();
        for (i, x) in self.enumerate() {
            if i == 0 {
                buf.reserve(len * x.size_hint());
            }
            x.escape_and_write(buf);
        }
    }
}

impl<T: IntoHtml> IntoHtml for Vec<T> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        for x in self {
            x.escape_and_write(buf);
        }
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.iter().map(IntoHtml::size_hint).sum()
    }
}

impl<T: IntoHtml, const N: usize> IntoHtml for [T; N] {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        for x in self {
            x.escape_and_write(buf);
        }
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.iter().map(IntoHtml::size_hint).sum()
    }
}

// ---- tuples ----------------------------------------------------------------

macro_rules! impl_tuple {
    ( ( $($i:ident,)+ ) ) => {
        impl<$($i,)+> IntoHtml for ($($i,)+)
        where
            $($i: IntoHtml,)+
        {
            #[inline]
            fn into_html(self) -> impl IntoHtml {
                #[allow(non_snake_case)]
                let ($($i,)+) = self;
                ($($i.into_html(),)+)
            }

            #[inline]
            fn escape_and_write(self, buf: &mut String) {
                #[allow(non_snake_case)]
                let ($($i,)+) = self;
                $( $i.escape_and_write(buf); )+
            }

            #[inline]
            fn size_hint(&self) -> usize {
                #[allow(non_snake_case)]
                let ($($i,)+) = self;
                let mut n = 0;
                $( n += $i.size_hint(); )+
                n
            }
        }
    };
    ($f:ident) => {
        impl_tuple!(($f,));
    };
    ($f:ident $($i:ident)+) => {
        impl_tuple!(($f, $($i,)+));
        impl_tuple!($($i)+);
    };
}

impl_tuple!(A B C D E F G H I J K L M N O P Q R S T U V W X Y Z A_ B_ C_ D_ E_ F_ G_ H_ I_ J_ K_);

// ---- numbers ---------------------------------------------------------------

// Numeric impls. None of `Display` for these types can produce a character
// that needs HTML-escaping, so we write directly into `buf`.
macro_rules! via_display {
    ($($ty:ty)*) => {
        $(
            impl IntoHtml for $ty {
                #[inline]
                fn into_html(self) -> impl IntoHtml { self }
                #[inline]
                fn escape_and_write(self, buf: &mut String) {
                    _ = write!(buf, "{self}");
                }
            }
        )*
    };
}

via_display! { isize i8 i16 i32 i64 i128 usize u8 u16 u32 u64 u128 f32 f64 }
