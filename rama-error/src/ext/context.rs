use std::fmt::{self, Write as _};

use crate::BoxError;

pub(super) struct ErrorWithContext {
    source: BoxError,
    fields: Option<Vec<ContextField>>,
}

impl ErrorWithContext {
    pub(super) fn new(source: BoxError) -> Self {
        Self {
            source,
            fields: None,
        }
    }

    pub(super) fn insert_value<T>(&mut self, value: T)
    where
        T: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        self.fields.get_or_insert_default().push(ContextField {
            key: None,
            value: Box::new(value),
        });
    }

    pub(super) fn insert_key_value<T>(&mut self, key: &'static str, value: T)
    where
        T: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        let key = key.trim();
        if key.is_empty() {
            self.insert_value(value);
        } else {
            self.fields.get_or_insert_default().push(ContextField {
                key: Some(key),
                value: Box::new(value),
            });
        }
    }

    #[inline(always)]
    pub(super) fn insert_key_value_str<T>(&mut self, key: &'static str, value: T)
    where
        T: Into<String>,
    {
        let str = value.into();
        self.insert_key_value(key, str);
    }
}

trait ContextValue: fmt::Debug + fmt::Display + Send + Sync + 'static {}
impl<T: ?Sized + fmt::Debug + fmt::Display + Send + Sync + 'static> ContextValue for T {}

type BoxContextValue = Box<dyn ContextValue>;

#[derive(Debug)]
struct ContextField {
    key: Option<&'static str>,
    value: BoxContextValue,
}

struct DisplayAsDebug<'a>(&'a dyn fmt::Display);

impl<'a> fmt::Debug for DisplayAsDebug<'a> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0, f)
    }
}

pub(super) struct DebugContextValue<T: fmt::Debug + Send + Sync + 'static>(pub(super) T);

impl<T: fmt::Debug + Send + Sync + 'static> fmt::Debug for DebugContextValue<T> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: fmt::Debug + Send + Sync + 'static> fmt::Display for DebugContextValue<T> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

struct LogfmtEscaper<'a, 'b> {
    f: &'a mut fmt::Formatter<'b>,
}

impl<'a, 'b> fmt::Write for LogfmtEscaper<'a, 'b> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            match ch {
                '\\' => self.f.write_str("\\\\")?,
                '"' => self.f.write_str("\\\"")?,
                '\n' => self.f.write_str("\\n")?,
                '\r' => self.f.write_str("\\r")?,
                '\t' => self.f.write_str("\\t")?,
                c => self.f.write_char(c)?,
            }
        }
        Ok(())
    }
}

fn write_logfmt_display_value_always_quoted(
    f: &mut fmt::Formatter<'_>,
    v: &dyn fmt::Display,
) -> fmt::Result {
    f.write_str("\"")?;
    {
        let mut esc = LogfmtEscaper { f };
        write!(&mut esc, "{v}")?;
    }
    f.write_str("\"")
}

impl fmt::Display for ContextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.key {
            Some(key) => {
                write!(f, "{key}=")?;
                write_logfmt_display_value_always_quoted(f, self.value.as_ref())
            }
            None => write_logfmt_display_value_always_quoted(f, self.value.as_ref()),
        }
    }
}

struct DebugFields<'a>(&'a [ContextField]);

impl fmt::Debug for DebugFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for field in self.0 {
            match field.key {
                Some(key) => map.entry(&key, &DisplayAsDebug(field.value.as_ref())),
                None => map.entry(&"<none>", &DisplayAsDebug(field.value.as_ref())),
            };
        }
        map.finish()
    }
}

impl fmt::Debug for ErrorWithContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ErrorWithContext");
        ds.field("source", &self.source);

        if let Some(fields) = self.fields.as_ref().filter(|v| !v.is_empty()) {
            ds.field("fields", &DebugFields(fields.as_slice()));
        } else {
            ds.field("fields", &None::<()>);
        }

        ds.finish()
    }
}

impl ErrorWithContext {
    fn fmt_inline_fields(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(fields) = self.fields.as_ref().filter(|v| !v.is_empty()) {
            f.write_str(" | ")?;
            let mut fields_iter = fields.iter();
            if let Some(field) = fields_iter.next() {
                write!(f, "{field}")?;
            }
            for field in fields_iter {
                write!(f, " {field}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for ErrorWithContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            write!(f, "{}", self.source)?;
            self.fmt_inline_fields(f)?;
            return Ok(());
        }

        writeln!(f, "{}", self.source)?;
        if let Some(fields) = self.fields.as_ref().filter(|v| !v.is_empty()) {
            writeln!(f, "Context:")?;
            for field in fields {
                writeln!(f, "  {field}")?;
            }
        }

        let mut idx = 0usize;
        let mut cur = self.source.as_ref().source();
        if cur.is_some() {
            writeln!(f, "Caused by:")?;
        }
        while let Some(err) = cur {
            writeln!(f, "  {idx}: {err}")?;
            idx += 1;
            cur = err.source();
        }

        Ok(())
    }
}

impl crate::StdError for ErrorWithContext {
    fn source(&self) -> Option<&(dyn crate::StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{ErrorExt, StdError};

    use std::io;

    #[test]
    fn display_non_alternate_without_fields_is_source_only() {
        let src = io::Error::other("boom");
        let err = ErrorWithContext::new(BoxError::from(src));

        assert_eq!(format!("{err}"), "boom");
    }

    #[test]
    fn empty_keys_are_seen_as_simple_values_and_keys_are_trimmed() {
        let err = BoxError::from("test error")
            .context_field("foo  ", "bar")
            .context_field("  ", "baz")
            .context_field("", 42);

        assert_eq!(format!("{err}"), "test error | foo=\"bar\" \"baz\" \"42\"");
    }

    #[test]
    fn display_non_alternate_with_fields_is_single_line_logfmt() {
        let src = io::Error::other("boom");
        let mut err = ErrorWithContext::new(BoxError::from(src));

        err.insert_key_value("path", "/a,b/c");
        err.insert_key_value("note", "hello \"world\"\nnext");
        err.insert_value("bare,value");

        let s = format!("{err}");

        // Source first
        assert!(s.starts_with("boom"), "got: {s:?}");

        // Inline context separator
        assert!(s.contains(" | "), "got: {s:?}");

        // Always quoted key/value
        assert!(
            s.contains(r#"path="/a,b/c""#),
            "expected quoted path, got: {s:?}"
        );

        // Escaping for quotes and newline
        assert!(
            s.contains(r#"note="hello \"world\"\nnext""#),
            "expected escaped note, got: {s:?}"
        );

        // Unkeyed value uses quotes too
        assert!(
            s.contains(r#""bare,value""#),
            "expected quoted unkeyed value, got: {s:?}"
        );

        // Fields are separated by spaces, not commas
        assert!(!s.contains(", "), "unexpected comma delimiter, got: {s:?}");
    }

    #[test]
    fn display_alternate_includes_context_block_when_fields_exist() {
        let src = io::Error::other("boom");
        let mut err = ErrorWithContext::new(BoxError::from(src));

        err.insert_key_value("path", "/a,b/c");
        err.insert_value("bare");

        let s = format!("{err:#}");

        // Prints source on its own line
        assert!(s.starts_with("boom\n"), "got: {s:?}");

        // Context section
        assert!(s.contains("Context:\n"), "got: {s:?}");

        // Indented entries
        assert!(
            s.contains(r#"  path="/a,b/c""#),
            "expected indented kv entry, got: {s:?}"
        );
        assert!(
            s.contains(r#"  "bare""#),
            "expected indented unkeyed entry, got: {s:?}"
        );
    }

    #[test]
    fn display_alternate_prints_cause_chain_when_source_has_source() {
        #[derive(Debug)]
        struct Outer {
            inner: io::Error,
        }

        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "outer")
            }
        }

        impl StdError for Outer {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(&self.inner)
            }
        }

        let src = Outer {
            inner: io::Error::other("inner"),
        };

        let mut err = ErrorWithContext::new(BoxError::from(src));
        err.insert_key_value("k", "v");

        let s = format!("{err:#}");

        // We should see the cause chain section and indexed causes.
        assert!(s.contains("Caused by:\n"), "got: {s:?}");
        assert!(s.contains("  0: inner\n"), "got: {s:?}");
    }

    #[test]
    fn debug_includes_type_name_and_fields_map() {
        let src = io::Error::other("boom");
        let mut err = ErrorWithContext::new(BoxError::from(src));
        err.insert_key_value("path", "/a,b/c");
        err.insert_value("bare");

        let s = format!("{err:?}");

        assert!(s.contains("ErrorWithContext"), "got: {s:?}");
        assert!(s.contains("source"), "got: {s:?}");
        assert!(s.contains("fields"), "got: {s:?}");

        // DebugFields prints a debug_map with keys; unkeyed uses "<none>"
        assert!(s.contains("path"), "got: {s:?}");
        assert!(s.contains("<none>"), "got: {s:?}");
    }

    #[test]
    fn source_returns_inner_error() {
        let src = io::Error::other("boom");
        let err = ErrorWithContext::new(BoxError::from(src));

        let src_ref = err.source().expect("source should exist");
        assert_eq!(src_ref.to_string(), "boom");
    }
}
