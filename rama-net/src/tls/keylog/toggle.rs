//! Toggle wrapper for any [`KeyLogSink`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::sink::KeyLogSink;

/// Wraps any [`KeyLogSink`] in an atomic on/off switch. When off,
/// `write_line` is a single relaxed-cost atomic load that drops the
/// argument. When on, it forwards to the inner sink.
///
/// Generic on `S` to avoid double dynamic dispatch — the only erasure
/// in the keylog stack happens at the `KeyLogIntent::Custom` boundary.
///
/// The flip-from-elsewhere mechanism is [`KeyLogToggle`], obtained via
/// [`Self::toggle`]. It holds only the shared `AtomicBool`, so the
/// XPC route / config layer can flip without holding a reference to
/// the sink chain.
#[derive(Debug)]
pub struct ToggleableKeyLogSink<S> {
    inner: S,
    enabled: Arc<AtomicBool>,
}

impl<S> ToggleableKeyLogSink<S> {
    /// Build the wrapper. Initial state is **off** — TLS keylog is a
    /// developer-only feature, never enabled implicitly.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            enabled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cheap handle for flipping the switch from elsewhere.
    pub fn toggle(&self) -> KeyLogToggle {
        KeyLogToggle {
            enabled: Arc::clone(&self.enabled),
        }
    }

    /// Returns the current state.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Sets the state directly (callers that hold the wrapper).
    /// Prefer [`Self::toggle`] from external components.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Release);
    }

    /// Borrow the wrapped sink (useful for tests / introspection).
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: KeyLogSink> KeyLogSink for ToggleableKeyLogSink<S> {
    #[inline]
    fn write_line(&self, line: &str) {
        if self.enabled.load(Ordering::Acquire) {
            self.inner.write_line(line);
        }
    }
}

/// Cheap external handle for toggling a [`ToggleableKeyLogSink`].
/// Holds only the shared `AtomicBool`; does not retain the inner
/// sink, so it can be stashed in any state container without
/// pinning the sink's lifetime.
#[derive(Debug, Clone)]
pub struct KeyLogToggle {
    enabled: Arc<AtomicBool>,
}

impl KeyLogToggle {
    /// Flip on.
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Flip off.
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Set explicitly.
    pub fn set(&self, on: bool) {
        self.enabled.store(on, Ordering::Release);
    }

    /// Read the current state.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[derive(Debug, Default)]
    struct Capture(Mutex<Vec<String>>);
    impl KeyLogSink for Capture {
        fn write_line(&self, line: &str) {
            self.0.lock().push(line.to_owned());
        }
    }

    #[test]
    fn defaults_off_and_drops_lines() {
        let inner = Capture::default();
        let wrap = ToggleableKeyLogSink::new(inner);
        assert!(!wrap.is_enabled());
        wrap.write_line("a\n");
        wrap.write_line("b\n");
        assert!(wrap.inner().0.lock().is_empty());
    }

    #[test]
    fn enable_then_forwards() {
        let inner = Capture::default();
        let wrap = ToggleableKeyLogSink::new(inner);
        wrap.set_enabled(true);
        wrap.write_line("x\n");
        wrap.set_enabled(false);
        wrap.write_line("dropped\n");
        assert_eq!(wrap.inner().0.lock().as_slice(), &["x\n"]);
    }

    #[test]
    fn toggle_handle_flips_state() {
        let wrap = ToggleableKeyLogSink::new(Capture::default());
        let toggle = wrap.toggle();
        assert!(!toggle.is_enabled());
        toggle.enable();
        assert!(wrap.is_enabled());
        wrap.write_line("on\n");
        toggle.disable();
        wrap.write_line("off\n");
        assert_eq!(wrap.inner().0.lock().as_slice(), &["on\n"]);
    }

    #[test]
    fn toggle_handle_set_is_idempotent() {
        let wrap = ToggleableKeyLogSink::new(Capture::default());
        let toggle = wrap.toggle();
        toggle.set(true);
        toggle.set(true);
        assert!(toggle.is_enabled());
        toggle.set(false);
        toggle.set(false);
        assert!(!toggle.is_enabled());
    }
}
