//! Application-owned dial9 recording and correlation across Rama protocols.
//!
//! Configure the upstream recorder and writer directly. An [`Operation`] adds
//! a timed, cancellation-aware lifecycle to that recording. Its [`TraceContext`]
//! follows Rama task spawns and can also be carried explicitly across an FFI,
//! queue, or connection-pool boundary. It never changes network requests.

#[doc(inline)]
pub use ::dial9::*;
#[doc(inline)]
pub use ::dial9_trace_format as trace_format;

use ::dial9::core::{clock_monotonic_ns, encoder::Encodable};
use dial9_trace_format::TraceEvent;
use std::sync::atomic::{AtomicU64, Ordering};

mod export;
pub use export::{ExportReport, export_completed_segments};
mod health;
pub use health::{RecorderHealth, RecorderHealthSnapshot};
#[cfg(test)]
mod tests;

tokio::task_local! {
    static CONTEXT: TraceContext;
}

/// Correlation for a logical flow and the operation currently handling it.
///
/// IDs are process-local, nonzero, and independent of socket addresses. A
/// recording's process/session metadata supplies their scope. The default
/// context has no association. Applications may put this value in extensions
/// or messages; use [`scope`](Self::scope) when resuming the work elsewhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TraceContext {
    flow_id: u64,
    operation_id: u64,
}

impl crate::extensions::Extension for TraceContext {}

/// An association between independently lived operations, such as a request
/// and the pooled connection selected for it. No context is reassigned.
#[derive(TraceEvent)]
pub struct RamaOperationLink {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub related_flow_id: u64,
    pub related_operation_id: u64,
    pub relationship: &'static str,
}

impl TraceContext {
    /// Associate this operation with a transport or another logical flow.
    pub fn link(self, related: Self, relationship: &'static str) {
        if self.operation_id != 0 && related.operation_id != 0 {
            Dial9Handle::current().record_event_with(|| RamaOperationLink {
                timestamp_ns: clock_monotonic_ns(),
                flow_id: self.flow_id,
                operation_id: self.operation_id,
                related_flow_id: related.flow_id,
                related_operation_id: related.operation_id,
                relationship,
            });
        }
    }
    /// Context of the currently polled Rama operation, if any.
    #[must_use]
    pub fn current() -> Self {
        CONTEXT.try_with(|context| *context).unwrap_or_default()
    }

    /// Process-local logical flow identifier, or zero outside a recorded flow.
    #[must_use]
    pub const fn flow_id(self) -> u64 {
        self.flow_id
    }

    /// Process-local operation identifier, or zero outside a recorded operation.
    #[must_use]
    pub const fn operation_id(self) -> u64 {
        self.operation_id
    }

    /// Poll a future in this context, restoring the caller's context afterwards.
    /// This also works when the future migrates between runtime threads.
    pub fn scope<F: Future>(self, future: F) -> impl Future<Output = F::Output> {
        use crate::futures::future::Either;
        if self.operation_id == 0 {
            Either::Left(future)
        } else {
            Either::Right(CONTEXT.scope(self, future))
        }
    }

    /// Run a synchronous callback in this context, restoring it even on panic.
    pub fn scope_sync<T>(self, callback: impl FnOnce() -> T) -> T {
        if self.operation_id == 0 {
            callback()
        } else {
            CONTEXT.sync_scope(self, callback)
        }
    }
}

/// Capture the spawning task's context before its future is first polled.
pub(crate) fn inherit<F: Future>(future: F) -> impl Future<Output = F::Output> {
    TraceContext::current().scope(future)
}

/// Record a fallible operation, including an error or cancellation before it
/// completes. Construction is lazy: recording starts when this future is polled.
pub async fn record_result<T, E>(
    name: &'static str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let operation = Operation::new(name);
    let result = operation.context().scope(future).await;
    operation.finish(if result.is_ok() {
        Outcome::Success
    } else {
        Outcome::Error
    });
    result
}

/// Terminal outcome of an operation. The numeric values are part of the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Outcome {
    Success = 0,
    Error = 1,
    Cancelled = 2,
    Timeout = 3,
    Rejected = 4,
}

/// A recorded operation started. Parent IDs describe nesting within a flow.
#[derive(TraceEvent)]
pub struct RamaOperationStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub parent_operation_id: u64,
    pub name: &'static str,
}

/// A recorded operation ended, including cancellation by dropping its future.
#[derive(TraceEvent)]
pub struct RamaOperationFinished {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    #[traceevent(role = "span.name")]
    pub name: &'static str,
    #[traceevent(unit = "ns", role = "span.start")]
    pub started_ns: u64,
    #[traceevent(unit = "ns", role = "span.duration")]
    pub duration_ns: u64,
    /// Numeric [`Outcome`].
    pub outcome: u32,
    #[traceevent(unit = "bytes")]
    pub bytes_sent: u64,
    #[traceevent(unit = "bytes")]
    pub bytes_received: u64,
}

/// A lifecycle recorded only when the ambient recorder is enabled at creation.
///
/// Construct inside the future being observed so an unpolled future emits
/// nothing. Dropping an unfinished operation attempts a cancellation event once.
/// No clock read, ID allocation, or event construction occurs when disabled.
/// Pausing/stopping the recorder, dropped batches and segment eviction can leave
/// incomplete lifecycles in the retained recording.
///
/// Use [`record_event_with`](Self::record_event_with) for application details;
/// the closure receives IDs that also identify Rama's child operations. Avoid
/// recording payloads or high-cardinality strings unless they are needed.
#[derive(Debug)]
pub struct Operation {
    active: Option<ActiveOperation>,
}

#[derive(Debug)]
struct ActiveOperation {
    handle: Dial9Handle,
    context: TraceContext,
    name: &'static str,
    started: u64,
}

impl Operation {
    #[must_use]
    #[inline]
    pub fn new(name: &'static str) -> Self {
        let handle = Dial9Handle::current();
        if !handle.is_enabled() {
            return Self { active: None };
        }
        Self::start(handle, name)
    }

    fn start(handle: Dial9Handle, name: &'static str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let operation_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let parent = TraceContext::current();
        let context = TraceContext {
            flow_id: if parent.flow_id == 0 {
                operation_id
            } else {
                parent.flow_id
            },
            operation_id,
        };
        let started = clock_monotonic_ns();
        handle.record_event(RamaOperationStarted {
            timestamp_ns: started,
            flow_id: context.flow_id,
            operation_id,
            parent_operation_id: parent.operation_id,
            name,
        });
        Self {
            active: Some(ActiveOperation {
                handle,
                context,
                name,
                started,
            }),
        }
    }

    #[must_use]
    pub fn context(&self) -> TraceContext {
        self.active
            .as_ref()
            .map_or_else(TraceContext::default, |active| active.context)
    }

    /// Whether this operation was started in an enabled recording.
    #[must_use]
    pub fn is_recorded(&self) -> bool {
        self.active.is_some()
    }

    /// Elapsed time for an active operation; zero when recording was disabled.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.active
            .as_ref()
            .map_or(std::time::Duration::ZERO, |active| {
                std::time::Duration::from_nanos(clock_monotonic_ns().saturating_sub(active.started))
            })
    }

    /// Lazily add protocol or application information to this operation.
    pub fn record_event_with<E: Encodable>(&self, make: impl FnOnce(TraceContext) -> E) {
        if let Some(active) = &self.active {
            active.handle.record_event_with(|| make(active.context));
        }
    }

    /// End the operation without directional byte totals.
    #[inline]
    pub fn finish(self, outcome: Outcome) {
        self.finish_with_bytes(outcome, 0, 0);
    }

    /// End the operation with bytes sent and received at this protocol boundary.
    /// These are not necessarily wire bytes (for example, HTTP body bytes).
    #[inline]
    pub fn finish_with_bytes(mut self, outcome: Outcome, sent: u64, received: u64) {
        if self.active.is_some() {
            self.end(outcome, sent, received);
        }
    }

    fn end(&mut self, outcome: Outcome, bytes_sent: u64, bytes_received: u64) {
        if let Some(active) = self.active.take() {
            active.handle.record_event_with(|| {
                let timestamp_ns = clock_monotonic_ns();
                RamaOperationFinished {
                    timestamp_ns,
                    flow_id: active.context.flow_id,
                    operation_id: active.context.operation_id,
                    name: active.name,
                    started_ns: active.started,
                    duration_ns: timestamp_ns.saturating_sub(active.started),
                    outcome: outcome as u32,
                    bytes_sent,
                    bytes_received,
                }
            });
        }
    }
}

impl Drop for Operation {
    #[inline]
    fn drop(&mut self) {
        if self.active.is_some() {
            self.end(Outcome::Cancelled, 0, 0);
        }
    }
}
