//! latency utilities and common types

/// The latency unit used to report latencies by various parts of the Rama codebase.
#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub enum LatencyUnit {
    /// Use seconds.
    Seconds,
    /// Use milliseconds.
    Millis,
    /// Use microseconds.
    Micros,
    /// Use nanoseconds.
    Nanos,
}
