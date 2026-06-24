use std::sync::Arc;

/// Consumer of TLS keylog lines.
///
/// Each call carries one complete NSS-format keylog line, including
/// its trailing `\n`. Implementations must persist the bytes verbatim
/// and must NOT block the caller — TLS handshakes feed this synchronously
/// from inside the crypto stack. Disk I/O belongs on a background worker.
///
/// Object-safe; sinks are usually held behind `Arc<dyn KeyLogSink>` at
/// the `KeyLogIntent::Custom` boundary. The [`Arc`] blanket below lets
/// `Arc<MyConcreteSink>` flow through the same APIs unchanged.
pub trait KeyLogSink: Send + Sync + std::fmt::Debug {
    /// Submit one keylog line (`\n`-terminated).
    fn write_line(&self, line: &str);
}

impl<T: KeyLogSink + ?Sized> KeyLogSink for Arc<T> {
    #[inline]
    fn write_line(&self, line: &str) {
        (**self).write_line(line);
    }
}

/// Sink that drops every line. Useful as a placeholder default and for
/// the off-state of [`ToggleableKeyLogSink`] without changing types.
///
/// [`ToggleableKeyLogSink`]: super::ToggleableKeyLogSink
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopKeyLogSink;

impl KeyLogSink for NoopKeyLogSink {
    #[inline]
    fn write_line(&self, _line: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_sink_drops_lines() {
        let s = NoopKeyLogSink;
        s.write_line("CLIENT_RANDOM aaa bbb\n");
    }

    #[test]
    fn arc_blanket_forwards_to_inner() {
        use parking_lot::Mutex;

        #[derive(Debug, Default)]
        struct Capture(Mutex<Vec<String>>);
        impl KeyLogSink for Capture {
            fn write_line(&self, line: &str) {
                self.0.lock().push(line.to_owned());
            }
        }
        let inner = Arc::new(Capture::default());
        let sink: Arc<dyn KeyLogSink> = inner.clone();
        sink.write_line("LINE_A\n");
        sink.write_line("LINE_B\n");
        assert_eq!(inner.0.lock().as_slice(), &["LINE_A\n", "LINE_B\n"]);
    }
}
