use crate::dep::rustls::KeyLog;
use rama_tls::keylog::KeyLogSink;
use rama_utils::fmt::hex;
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
        let line = format!("{label} {} {}\n", hex(client_random), hex(secret));
        self.0.write_line(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keylog_line_preserves_lowercase_pairs_without_prefixes() {
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Debug)]
        struct Sink(AtomicBool);

        impl KeyLogSink for Sink {
            fn write_line(&self, line: &str) {
                assert_eq!(line, "CLIENT_RANDOM 0001abff 00cdef\n");
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let sink = Arc::new(Sink(AtomicBool::new(false)));
        RamaKeyLog::new(sink.clone()).log(
            "CLIENT_RANDOM",
            &[0x00, 0x01, 0xab, 0xff],
            &[0x00, 0xcd, 0xef],
        );
        assert!(sink.0.load(Ordering::Relaxed));
    }
}
