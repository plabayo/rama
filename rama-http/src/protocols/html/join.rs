//! Render an iterator of values as a separated (e.g. comma-separated) list,
//! without the element type having to know anything about HTML.

use std::fmt::{self, Write as _};

use super::core::{IntoHtml, escape_into};

/// Render the items of `iter` into HTML, separated by `sep`.
///
/// Each item is rendered through its [`Display`](std::fmt::Display) impl and
/// HTML-escaped, so the element type only needs `Display` — it does **not**
/// need to implement [`IntoHtml`]. The separator is written verbatim: it is
/// treated as trusted, developer-provided structure, exactly like the static
/// parts of a template (so the *data* is escaped, the *structure* is not).
///
/// This is the idiomatic way to build a CSV-style attribute value (or body)
/// straight from an iterator, instead of pre-joining into a `String`:
///
/// ```ignore
/// use rama_http::protocols::html::*;
///
/// // any `Display` iterator works; here: a list of language tags
/// let langs = ["en", "fr", "de"];
/// let tag = meta!("http-equiv" = "Content-Language", content = join_display(langs, ", "));
/// assert_eq!(
///     tag.into_string(),
///     r#"<meta http-equiv="Content-Language" content="en, fr, de">"#,
/// );
/// ```
pub fn join_display<I, S>(iter: I, sep: S) -> impl IntoHtml
where
    I: IntoIterator,
    I::Item: fmt::Display,
    S: AsRef<str>,
{
    // A `FnOnce(&mut String)` is itself `IntoHtml` (see `core`), so the
    // closure is all we need — it renders lazily at write time.
    move |buf: &mut String| {
        let sep = sep.as_ref();
        for (i, item) in iter.into_iter().enumerate() {
            if i > 0 {
                buf.push_str(sep);
            }
            // `Display` straight into the buffer, escaping on the fly so we
            // never allocate a per-item scratch `String`.
            _ = write!(EscapeWriter(buf), "{item}");
        }
    }
}

/// A [`fmt::Write`] that HTML-escapes everything written through it into the
/// wrapped buffer. Escaping per write is correct because every escapable byte
/// is a single ASCII byte, so chunk boundaries never split one.
struct EscapeWriter<'a>(&'a mut String);

impl fmt::Write for EscapeWriter<'_> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        escape_into(self.0, s);
        Ok(())
    }
}
