use crate::dep::rustls::KeyLog;
use rama_tls::keylog::KeyLogSink;
use std::fmt;
use std::sync::Arc;

/// Adapter that exposes a rama [`KeyLogSink`] as a rustls
/// [`KeyLog`] consumer.
#[derive(Debug, Clone)]
pub struct RamaKeyLog(Arc<dyn KeyLogSink>);

impl RamaKeyLog {
    /// Adapt any sink.
    pub fn new(sink: Arc<dyn KeyLogSink>) -> Self {
        Self(sink)
    }
}

impl KeyLog for RamaKeyLog {
    #[inline]
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = format!(
            "{} {:02x} {:02x}\n",
            label,
            PlainHex {
                slice: client_random
            },
            PlainHex { slice: secret },
        );
        self.0.write_line(&line);
    }
}

struct PlainHex<'a, T: 'a> {
    slice: &'a [T],
}

impl<T: fmt::LowerHex> fmt::LowerHex for PlainHex<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_inner_hex(self.slice, f, fmt::LowerHex::fmt)
    }
}

fn fmt_inner_hex<T, F: Fn(&T, &mut fmt::Formatter) -> fmt::Result>(
    slice: &[T],
    f: &mut fmt::Formatter,
    fmt_fn: F,
) -> fmt::Result {
    for val in slice.iter() {
        fmt_fn(val, f)?;
    }
    Ok(())
}
