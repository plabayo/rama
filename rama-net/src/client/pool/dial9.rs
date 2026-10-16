//! Pool selection events, paired with the `pool.checkout` operation duration.
use dial9_trace_format::TraceEvent;
use rama_core::telemetry::dial9::{Dial9Handle, TraceContext, core::clock_monotonic_ns};

#[derive(TraceEvent)]
pub struct PoolConnectionSelected {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    /// False means a permit to create a new connection was selected.
    pub reused: bool,
}

pub(super) fn selected(reused: bool) {
    Dial9Handle::current().record_event_with(|| {
        let context = TraceContext::current();
        PoolConnectionSelected {
            timestamp_ns: clock_monotonic_ns(),
            flow_id: context.flow_id(),
            operation_id: context.operation_id(),
            reused,
        }
    });
}
