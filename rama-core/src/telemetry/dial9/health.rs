//! An opt-in in-memory sink for dial9's operational metrics.

use metrique_writer_core::{
    Entry, EntryWriter, Observation, Unit, ValidationError, Value, ValueWriter,
    entry::{BoxEntry, EntryConfig},
    sink::{BoxEntrySink, EntrySink, FlushWait},
    value::MetricFlags,
};
use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

/// Recorder health for an application's metrics exporter or diagnostics bundle.
/// Pass [`sink`](Self::sink) to the upstream recorder builder's metrics sink.
/// Nothing is installed globally. Reading this handle performs no disk I/O.
/// Create a fresh health handle for each recorder session.
///
/// The flush/processing threads update atomics; application event recording
/// does no additional work. This consumes dial9 0.5's metric field names and
/// should be checked when upgrading dial9. It covers the counters listed here,
/// not every upstream metric or every possible write failure.
#[derive(Clone, Debug, Default)]
pub struct RecorderHealth(Arc<Counters>);

#[derive(Debug, Default)]
struct Counters {
    flushes: AtomicU64,
    events: AtomicU64,
    dropped_batches: AtomicU64,
    clean_segments: AtomicU64,
    undrained_segments: AtomicU64,
    metadata_failures: AtomicU64,
    finalize_failures: AtomicU64,
    processing_panics: AtomicU64,
    invalid_segments: AtomicU64,
}

/// Independently sampled counters; not a transactional snapshot.
/// A zero `flushes` count means no flush metrics have been observed yet.
/// Seal counts reflect the last upstream flush snapshot, which precedes
/// finalization of the last segment; they can undercount by that final seal.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
#[non_exhaustive]
pub struct RecorderHealthSnapshot {
    pub flushes: u64,
    pub events: u64,
    pub dropped_batches: u64,
    pub clean_segments: u64,
    pub undrained_segments: u64,
    pub metadata_failures: u64,
    pub finalize_failures: u64,
    pub processing_panics: u64,
    pub invalid_segments: u64,
}

impl RecorderHealth {
    pub fn sink(&self) -> BoxEntrySink {
        BoxEntrySink::new(self.clone())
    }

    #[must_use]
    pub fn snapshot(&self) -> RecorderHealthSnapshot {
        let c = &self.0;
        RecorderHealthSnapshot {
            flushes: c.flushes.load(Ordering::Relaxed),
            events: c.events.load(Ordering::Relaxed),
            dropped_batches: c.dropped_batches.load(Ordering::Relaxed),
            clean_segments: c.clean_segments.load(Ordering::Relaxed),
            undrained_segments: c.undrained_segments.load(Ordering::Relaxed),
            metadata_failures: c.metadata_failures.load(Ordering::Relaxed),
            finalize_failures: c.finalize_failures.load(Ordering::Relaxed),
            processing_panics: c.processing_panics.load(Ordering::Relaxed),
            invalid_segments: c.invalid_segments.load(Ordering::Relaxed),
        }
    }
}

impl EntrySink<BoxEntry> for RecorderHealth {
    fn append(&self, entry: BoxEntry) {
        entry.write(&mut HealthWriter(&self.0));
    }
    fn flush_async(&self) -> FlushWait {
        FlushWait::ready()
    }
}

struct HealthWriter<'a>(&'a Counters);

impl<'a> EntryWriter<'a> for HealthWriter<'_> {
    fn timestamp(&mut self, _: SystemTime) {}
    fn config(&mut self, _: &'a dyn EntryConfig) {}
    fn value(&mut self, name: impl Into<Cow<'a, str>>, value: &(impl Value + ?Sized)) {
        let name = name.into();
        let (counter, cumulative) = match name.as_ref() {
            "EventCount" => {
                self.0.flushes.fetch_add(1, Ordering::Relaxed);
                (&self.0.events, false)
            }
            "DroppedBatches" => (&self.0.dropped_batches, false),
            "SegmentsSealedClean" | "segments_sealed_clean" => (&self.0.clean_segments, true),
            "SegmentsSealedUndrained" | "segments_sealed_undrained" => {
                (&self.0.undrained_segments, true)
            }
            "WriteMetadataFailed" => (&self.0.metadata_failures, false),
            "FinalizeFailed" => (&self.0.finalize_failures, false),
            "Panicked" => (&self.0.processing_panics, false),
            "InvalidFileHeader" => (&self.0.invalid_segments, false),
            _ => return,
        };
        value.write(CounterWriter {
            counter,
            cumulative,
        });
    }
}

struct CounterWriter<'a> {
    counter: &'a AtomicU64,
    cumulative: bool,
}

impl ValueWriter for CounterWriter<'_> {
    fn string(self, _: &str) {}
    fn error(self, _: ValidationError) {}
    fn metric<'a>(
        self,
        distribution: impl IntoIterator<Item = Observation>,
        _: Unit,
        _: impl IntoIterator<Item = (&'a str, &'a str)>,
        _: MetricFlags<'_>,
    ) {
        for value in distribution {
            if let Observation::Unsigned(value) = value {
                if self.cumulative {
                    self.counter.fetch_max(value, Ordering::Relaxed);
                } else {
                    self.counter.fetch_add(value, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deltas_accumulate_and_seal_totals_do_not_double_count() {
        let health = RecorderHealth::default();
        let mut writer = HealthWriter(&health.0);
        writer.value("EventCount", &4_u64);
        writer.value("EventCount", &7_u64);
        writer.value("DroppedBatches", &2_u64);
        writer.value("DroppedBatches", &1_u64);
        writer.value("segments_sealed_clean", &2_u64);
        writer.value("segments_sealed_clean", &2_u64);
        writer.value("segments_sealed_clean", &3_u64);
        writer.value("segments_sealed_undrained", &1_u64);
        writer.value("WriteMetadataFailed", &true);
        writer.value("FinalizeFailed", &false);
        writer.value("Panicked", &true);
        writer.value("InvalidFileHeader", &true);
        let snapshot = health.snapshot();
        assert_eq!(snapshot.flushes, 2);
        assert_eq!(snapshot.events, 11);
        assert_eq!(snapshot.dropped_batches, 3);
        assert_eq!(snapshot.clean_segments, 3);
        assert_eq!(snapshot.undrained_segments, 1);
        assert_eq!(snapshot.metadata_failures, 1);
        assert_eq!(snapshot.finalize_failures, 0);
        assert_eq!(snapshot.processing_panics, 1);
        assert_eq!(snapshot.invalid_segments, 1);
    }
}
