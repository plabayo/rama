use std::ops::Deref;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default)]
pub enum Timeout {
    #[default]
    None,
    Duration(Duration),
}

impl Deref for Timeout {
    type Target = Duration;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::None => &Duration::ZERO,
            Self::Duration(t) => t,
        }
    }
}

const MAX_TIMEOUT: Duration = Duration::from_nanos(i64::MAX as u64);

impl From<Option<Duration>> for Timeout {
    fn from(value: Option<Duration>) -> Self {
        match value {
            Some(t) => t.into(),
            _ => Self::None,
        }
    }
}

impl From<Duration> for Timeout {
    fn from(t: Duration) -> Self {
        if t.is_zero() {
            return Self::None;
        }
        Self::Duration(t.min(MAX_TIMEOUT))
    }
}

impl Timeout {
    /// The absolute deadline for a call starting now, or `None` for no timeout.
    ///
    /// Computed at call invocation (rather than sleeping a duration once the request has been
    /// written) so the timeout also covers time the request spends queueing and in transmission.
    #[must_use]
    pub fn deadline(self) -> Option<tokio::time::Instant> {
        match self {
            Self::Duration(d) => Some(tokio::time::Instant::now() + d),
            Self::None => None,
        }
    }

    #[must_use]
    pub fn from_nanos(nanos: i64) -> Self {
        let nanos = u64::try_from(nanos).unwrap_or(0);
        Some(Duration::from_nanos(nanos)).into()
    }

    #[must_use]
    pub fn as_nanos(&self) -> i64 {
        let nanos = self.deref().as_nanos();
        i64::try_from(nanos).unwrap_or(i64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::Timeout;
    use std::time::Duration;

    /// `timeout_nano` semantics on the wire: 0 (or negative garbage) means "no timeout",
    /// matching the Go server (containerd/ttrpc server.go `getRequestContext`:
    /// `TimeoutNano == 0` → no deadline).
    #[test]
    fn nanos_wire_roundtrip() {
        assert!(matches!(Timeout::from_nanos(0), Timeout::None));
        assert!(matches!(Timeout::from_nanos(-5), Timeout::None));
        assert_eq!(Timeout::None.as_nanos(), 0);

        let t = Timeout::from_nanos(1_500_000_000);
        assert!(matches!(t, Timeout::Duration(d) if d == Duration::from_nanos(1_500_000_000)));
        assert_eq!(t.as_nanos(), 1_500_000_000);

        // From<Duration> clamps into the wire's i64 range
        assert_eq!(Timeout::from(Duration::MAX).as_nanos(), i64::MAX);
        assert!(matches!(Timeout::from(Duration::ZERO), Timeout::None));
        assert!(matches!(Option::<Duration>::None.into(), Timeout::None));
        assert!(matches!(
            Some(Duration::from_secs(1)).into(),
            Timeout::Duration(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_computed_from_now() {
        assert_eq!(Timeout::None.deadline(), None);

        let now = tokio::time::Instant::now();
        let deadline = Timeout::Duration(Duration::from_millis(150))
            .deadline()
            .expect("a duration yields a deadline");
        // Anchored at "now" (call invocation), not a duration slept later.
        assert_eq!(deadline, now + Duration::from_millis(150));
    }
}
