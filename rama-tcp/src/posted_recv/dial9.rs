//! Pre-defined [dial9] events of [`PostedRecv`](super::PostedRecv).
//!
//! They are recorded on the completion threads, which carry the telemetry
//! handle of the thread that started them, falling back to the
//! process-global handle.
//!
//! [dial9]: https://github.com/dial9-rs/dial9

use dial9_trace_format::{EventEncoder, TraceEvent, TraceField, types::FieldType};

use super::{ThreadStartReason, ThreadStopReason};

impl TraceField for ThreadStartReason {
    fn field_type() -> FieldType {
        FieldType::U8
    }

    fn encode<W: std::io::Write>(&self, enc: &mut EventEncoder<'_, W>) -> std::io::Result<()> {
        enc.write_u8(self.dial9_code())
    }
}

impl TraceField for ThreadStopReason {
    fn field_type() -> FieldType {
        FieldType::U8
    }

    fn encode<W: std::io::Write>(&self, enc: &mut EventEncoder<'_, W>) -> std::io::Result<()> {
        enc.write_u8(self.dial9_code())
    }
}

/// A completion thread started.
#[derive(TraceEvent)]
pub struct PostedRecvThreadStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Threads running, including this one.
    pub threads: u64,
    pub reason: ThreadStartReason,
}

/// A completion thread stopped.
#[derive(TraceEvent)]
pub struct PostedRecvThreadStopped {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Threads still running.
    pub threads: u64,
    pub reason: ThreadStopReason,
}

/// Receives could not be posted for a stream, so its reads pass through.
#[derive(TraceEvent)]
pub struct PostedRecvPassThrough {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Encoded `std::io::ErrorKind` per
    /// [`io_error_kind_code`](rama_net::dial9::io_error_kind_code).
    pub error_kind: u32,
    /// Raw OS error code, if available.
    pub error_raw_os: Option<i64>,
}

/// The system ran out of buffers for a receive; reads of that stream pass
/// through until one can be posted again.
#[derive(TraceEvent)]
pub struct PostedRecvBlocked {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Raw OS error code of the failed receive.
    pub error_raw_os: i64,
}

#[cfg(target_os = "windows")]
pub(super) fn record_thread_started(threads: usize, reason: ThreadStartReason) {
    record(|timestamp_ns| PostedRecvThreadStarted {
        timestamp_ns,
        threads: threads as u64,
        reason,
    });
}

#[cfg(target_os = "windows")]
pub(super) fn record_thread_stopped(threads: usize, reason: ThreadStopReason) {
    record(|timestamp_ns| PostedRecvThreadStopped {
        timestamp_ns,
        threads: threads as u64,
        reason,
    });
}

#[cfg(target_os = "windows")]
pub(super) fn record_pass_through(error: &std::io::Error) {
    record(|timestamp_ns| PostedRecvPassThrough {
        timestamp_ns,
        error_kind: rama_net::dial9::io_error_kind_code(error.kind()),
        error_raw_os: rama_net::dial9::io_error_raw_os_code(error),
    });
}

#[cfg(target_os = "windows")]
pub(super) fn record_blocked(code: i32) {
    record(|timestamp_ns| PostedRecvBlocked {
        timestamp_ns,
        error_raw_os: i64::from(code),
    });
}

#[cfg(target_os = "windows")]
fn record<E: dial9::core::Encodable>(event: impl FnOnce(u64) -> E) {
    let handle = dial9::Dial9Handle::current();
    if handle.is_enabled() {
        handle.record_event(event(dial9::core::clock_monotonic_ns()));
    }
}
