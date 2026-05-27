use core::fmt::{self, Write as _};

use crate::{
    BoxError,
    std::{Box, String},
};

pub(super) struct ErrorWithContext {
    source: BoxError,
    fields: Option<crate::std::Vec<ContextField>>,
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
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<T: fmt::Debug + Send + Sync + 'static> fmt::Display for DebugContextValue<T> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

pub(super) struct HexContextValue<T: fmt::Debug + Send + Sync + 'static>(pub(super) T);

impl<T: fmt::Debug + Send + Sync + 'static> fmt::Debug for HexContextValue<T> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x?}", &self.0)
    }
}

impl<T: fmt::Debug + Send + Sync + 'static> fmt::Display for HexContextValue<T> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

struct LogfmtEscaper<'a, 'b> {
    f: &'a mut fmt::Formatter<'b>,
}

impl<'a, 'b> fmt::Write for LogfmtEscaper<'a, 'b> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Emit runs of "clean" characters in a single write_str, only breaking
        // out for characters that need escaping. This keeps formatter overhead
        // low while ensuring control characters (incl. ANSI ESC \x1b and other
        // C0/C1 controls) are neutralized to prevent terminal-escape / log
        // injection when error context contains attacker-controlled data.
        let mut rest = s;
        loop {
            let mut found = None;
            for (i, ch) in rest.char_indices() {
                if needs_escape(ch) {
                    found = Some((i, ch));
                    break;
                }
            }
            let Some((i, ch)) = found else {
                if !rest.is_empty() {
                    self.f.write_str(rest)?;
                }
                return Ok(());
            };
            if i > 0 {
                self.f.write_str(&rest[..i])?;
            }
            write_escaped(self.f, ch)?;
            rest = &rest[i + ch.len_utf8()..];
        }
    }
}

#[inline]
fn needs_escape(ch: char) -> bool {
    // Backslash and quote are the logfmt structural escapes; everything that
    // is a Unicode control (C0, DEL, C1) is escaped to avoid terminal-escape
    // injection and to keep log records single-line and printable.
    matches!(ch, '\\' | '"') || ch.is_control()
}

fn write_escaped(f: &mut fmt::Formatter<'_>, ch: char) -> fmt::Result {
    match ch {
        '\\' => f.write_str("\\\\"),
        '"' => f.write_str("\\\""),
        '\n' => f.write_str("\\n"),
        '\r' => f.write_str("\\r"),
        '\t' => f.write_str("\\t"),
        c => write!(f, "\\u{{{:x}}}", c as u32),
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

        // Cap the cause-chain walk so a malformed Error impl that returns a
        // cycle from .source() cannot produce an unbounded loop here.
        const MAX_CAUSE_DEPTH: usize = 64;
        let mut idx = 0usize;
        let mut cur = self.source.as_ref().source();
        if cur.is_some() {
            writeln!(f, "Caused by:")?;
        }
        while let Some(err) = cur {
            if idx >= MAX_CAUSE_DEPTH {
                writeln!(f, "  ... (truncated)")?;
                break;
            }
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

    use crate::{ErrorExt, StdError, extra::OpaqueError};

    #[derive(Debug, Clone)]
    struct BoomError;

    impl fmt::Display for BoomError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "boom")
        }
    }

    impl core::error::Error for BoomError {}

    #[test]
    fn display_non_alternate_without_fields_is_source_only() {
        let src = BoomError;
        let err = ErrorWithContext::new(BoxError::from(src));

        assert_eq!(format!("{err}"), "boom");
    }

    #[test]
    fn empty_keys_are_seen_as_simple_values_and_keys_are_trimmed() {
        let err = OpaqueError::from_static_str("test error")
            .context_field("foo  ", "bar")
            .context_field("  ", "baz")
            .context_field("", 42);

        assert_eq!(format!("{err}"), "test error | foo=\"bar\" \"baz\" \"42\"");
    }

    #[test]
    fn display_non_alternate_with_fields_is_single_line_logfmt() {
        let src = BoomError;
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
        let src = BoomError;
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
            inner: BoomError,
        }

        impl core::fmt::Display for Outer {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "outer")
            }
        }

        impl StdError for Outer {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(&self.inner)
            }
        }

        let src = Outer { inner: BoomError };

        let mut err = ErrorWithContext::new(BoxError::from(src));
        err.insert_key_value("k", "v");

        let s = format!("{err:#}");

        // We should see the cause chain section and indexed causes.
        assert!(s.contains("Caused by:\n"), "got: {s:?}");
        assert!(s.contains("  0: boom\n"), "got: {s:?}");
    }

    #[test]
    fn debug_includes_type_name_and_fields_map() {
        let src = BoomError;
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
        let src = BoomError;
        let err = ErrorWithContext::new(BoxError::from(src));

        let src_ref = err.source().expect("source should exist");
        assert_eq!(src_ref.to_string(), "boom");
    }

    #[test]
    fn logfmt_escapes_ansi_and_control_chars() {
        // ANSI ESC (\x1b), NUL, DEL, BEL, C1 CSI — none of these may appear
        // literally in formatted output, to prevent terminal-escape / log
        // injection when error context contains attacker-controlled bytes.
        let src = BoomError;
        let mut err = ErrorWithContext::new(BoxError::from(src));

        err.insert_key_value("ansi", "\x1b[31mred\x1b[0m");
        err.insert_key_value("nul", "a\x00b");
        err.insert_key_value("del", "a\x7fb");
        err.insert_key_value("bel", "a\x07b");
        err.insert_key_value("c1", "a\u{9b}b");

        let s = format!("{err}");

        // No literal control bytes leaked through.
        for bad in ['\x00', '\x07', '\x1b', '\x7f', '\u{9b}'] {
            assert!(
                !s.contains(bad),
                "raw control char {bad:?} leaked into output: {s:?}"
            );
        }

        // Escaped forms are present.
        assert!(s.contains(r"\u{1b}"), "got: {s:?}");
        assert!(s.contains(r"\u{0}"), "got: {s:?}");
        assert!(s.contains(r"\u{7f}"), "got: {s:?}");
        assert!(s.contains(r"\u{7}"), "got: {s:?}");
        assert!(s.contains(r"\u{9b}"), "got: {s:?}");

        // Existing structural escapes still work.
        let src2 = BoomError;
        let mut err2 = ErrorWithContext::new(BoxError::from(src2));
        err2.insert_key_value("q", "a\"b\\c");
        let s2 = format!("{err2}");
        assert!(s2.contains(r#"q="a\"b\\c""#), "got: {s2:?}");
    }

    #[test]
    fn cause_chain_is_capped_to_avoid_unbounded_loops() {
        // A malicious Error impl can return a cycle from .source(); make sure
        // alternate Display still terminates.
        struct Cycle;
        impl fmt::Debug for Cycle {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("cycle")
            }
        }
        impl fmt::Display for Cycle {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("cycle")
            }
        }
        impl StdError for Cycle {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                // Self-cycle: returns itself as its own source.
                Some(self)
            }
        }

        let err = ErrorWithContext::new(Box::new(Cycle));
        let s = format!("{err:#}");
        assert!(s.contains("(truncated)"), "got: {s:?}");
    }
}
