//! Streaming qlog JSON Text Sequences (RFC 7464), using main schema draft 14.

use super::event::Event;
use serde::Serialize;
use std::{
    io::{self, Write},
    time::Instant,
};

/// Owns a single trace. The surrounding stream mutex serializes entire records.
/// No event history or intermediate JSON strings are retained.
pub(crate) struct QlogWriter {
    writer: Box<dyn Write + Send + Sync>,
    start_time: Instant,
    failed: bool,
}

impl QlogWriter {
    pub(crate) fn new(
        writer: Box<dyn Write + Send + Sync>,
        start_time: Instant,
        title: Option<&str>,
        description: Option<&str>,
    ) -> io::Result<Self> {
        let mut stream = Self {
            writer,
            start_time,
            failed: false,
        };
        stream.write_record(&Header {
            file_schema: "urn:ietf:params:qlog:file:sequential",
            serialization_format: "application/qlog+json-seq",
            title,
            description,
            trace: Trace {
                title,
                description,
                vantage_point: VantagePoint { r#type: "unknown" },
                event_schemas: ["urn:ietf:params:qlog:events:quic-13"],
                common_fields: CommonFields {
                    time_format: "relative_to_epoch",
                    reference_time: ReferenceTime {
                        clock_type: "monotonic",
                        epoch: "unknown",
                    },
                },
            },
        })?;
        Ok(stream)
    }

    pub(crate) fn emit(&mut self, group: &[u8], event: Event, now: Instant) -> io::Result<()> {
        self.write_record(&Record {
            time: now.saturating_duration_since(self.start_time).as_secs_f64() * 1000.0,
            group_id: group,
            event,
        })
    }

    fn write_record(&mut self, record: &impl Serialize) -> io::Result<()> {
        // A write error can leave half a JSON record behind. Stop this trace,
        // returning its first error to the caller for logging, without repeatedly
        // hitting a broken destination on the packet path.
        if self.failed {
            return Ok(());
        }
        let result = (|| {
            self.writer.write_all(b"\x1e")?;
            serde_json::to_writer(&mut self.writer, record).map_err(io::Error::from)?;
            self.writer.write_all(b"\n")
        })();
        self.failed = result.is_err();
        result
    }
}

impl Drop for QlogWriter {
    fn drop(&mut self) {
        if let Err(error) = self.writer.flush() {
            rama_core::telemetry::tracing::warn!(%error, "could not flush qlog trace");
        }
    }
}

#[derive(Serialize)]
struct Header<'a> {
    file_schema: &'static str,
    serialization_format: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    trace: Trace<'a>,
}

#[derive(Serialize)]
struct Trace<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    vantage_point: VantagePoint,
    event_schemas: [&'static str; 1],
    common_fields: CommonFields,
}

#[derive(Serialize)]
struct VantagePoint {
    r#type: &'static str,
}

#[derive(Serialize)]
struct CommonFields {
    time_format: &'static str,
    reference_time: ReferenceTime,
}

#[derive(Serialize)]
struct ReferenceTime {
    clock_type: &'static str,
    epoch: &'static str,
}

#[derive(Serialize)]
struct Record<'a> {
    time: f64,
    #[serde(serialize_with = "rama_utils::bytes::serde_hex::serialize")]
    group_id: &'a [u8],
    #[serde(flatten)]
    event: Event,
}
