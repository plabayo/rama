use super::*;
use serde_json::{Value, json};
use std::io;

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    remaining: Option<usize>,
    max_chunk: Option<usize>,
    interrupt_once: bool,
    calls: usize,
    flushes: usize,
}

#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Output>>);

impl Trace {
    fn records(&self) -> Vec<Value> {
        let output = self.0.lock();
        assert_eq!(output.bytes.first(), Some(&0x1e));
        output.bytes[1..]
            .split(|byte| *byte == 0x1e)
            .map(|record| {
                assert_eq!(record.last(), Some(&b'\n'));
                serde_json::from_slice(record).unwrap()
            })
            .collect()
    }
}

impl io::Write for Trace {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock();
        output.calls += 1;
        if std::mem::take(&mut output.interrupt_once) {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let len = output
            .remaining
            .unwrap_or(bytes.len())
            .min(output.max_chunk.unwrap_or(bytes.len()))
            .min(bytes.len());
        if len == 0 && !bytes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed trace"));
        }
        output.bytes.extend_from_slice(&bytes[..len]);
        if let Some(remaining) = &mut output.remaining {
            *remaining -= len;
        }
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().flushes += 1;
        Ok(())
    }
}

#[test]
fn qlog_header_escapes_metadata_and_declares_schema_and_clock() {
    let trace = Trace::default();
    let title = "a \"trace\"\nwith a record separator: \u{1e}";
    let writer = QlogWriter::new(
        Box::new(trace.clone()),
        Instant::now(),
        Some(title),
        Some("λ"),
    )
    .unwrap();
    let records = trace.records();
    assert_eq!(
        records,
        vec![json!({
            "file_schema": "urn:ietf:params:qlog:file:sequential",
            "serialization_format": "application/qlog+json-seq",
            "title": title,
            "description": "λ",
            "trace": {
                "title": title,
                "description": "λ",
                "vantage_point": {"type": "unknown"},
                "event_schemas": ["urn:ietf:params:qlog:events:quic-13"],
                "common_fields": {
                    "time_format": "relative_to_epoch",
                    "reference_time": {"clock_type": "monotonic", "epoch": "unknown"}
                }
            }
        })]
    );
    assert_eq!(trace.0.lock().flushes, 0);
    drop(writer);
    assert_eq!(trace.0.lock().flushes, 1);
}

#[test]
fn qlog_events_preserve_packet_types_time_group_and_loss_reason() {
    let trace = Trace::default();
    let start = Instant::now();
    let stream = crate::proto::QlogConfig::default()
        .with_writer(Box::new(trace.clone()))
        .with_start_time(start)
        .into_stream()
        .unwrap();
    let sink = QlogSink::from(Some(stream.clone()));
    assert!(sink.is_enabled());
    assert!(!QlogSink::default().is_enabled());
    let group = ConnectionId::new(&[0, 0xab]);
    for (space, early) in [
        (SpaceId::Initial, false),
        (SpaceId::Handshake, false),
        (SpaceId::Data, true),
        (SpaceId::Data, false),
    ] {
        sink.emit_packet_sent(
            7,
            1200,
            space,
            early,
            start + Duration::from_micros(1250),
            group,
        );
    }
    sink.emit_packet_received(
        8,
        SpaceId::Data,
        false,
        start.checked_sub(Duration::from_millis(1)).unwrap(),
        group,
    );
    let packet = SentPacket {
        path_generation: 0,
        time_sent: start,
        size: 1200,
        ack_eliciting: true,
        is_0rtt: false,
        largest_acked: None,
        retransmits: Default::default(),
        stream_frames: Default::default(),
    };
    let delay = Duration::from_micros(2500);
    for elapsed in [Duration::from_micros(1250), delay] {
        sink.emit_packet_lost(7, &packet, delay, SpaceId::Data, start + elapsed, group);
    }
    stream.emit_event(
        group,
        Event::RecoveryMetricsUpdated(event::RecoveryMetricsUpdated {
            latest_rtt: Some(1.25),
            bytes_in_flight: Some(u64::MAX),
            ..Default::default()
        }),
        start,
    );

    let records = trace.records();
    assert_eq!(records.len(), 9);
    assert!(records[0].get("title").is_none());
    for (record, kind) in records[1..5]
        .iter()
        .zip(["initial", "handshake", "0RTT", "1RTT"])
    {
        assert_eq!(
            *record,
            json!({
                "time": 1.25, "group_id": "00ab", "name": "quic:packet_sent",
                "data": {"header": {"packet_type": kind, "packet_number": 7}, "raw": {"length": 1200}}
            })
        );
    }
    assert_eq!(
        records[5],
        json!({
            "time": 0.0, "group_id": "00ab", "name": "quic:packet_received",
            "data": {"header": {"packet_type": "1RTT", "packet_number": 8}}
        })
    );
    for (record, (time, trigger)) in records[6..8]
        .iter()
        .zip([(1.25, "reordering_threshold"), (2.5, "time_threshold")])
    {
        assert_eq!(
            *record,
            json!({
                "time": time, "group_id": "00ab", "name": "quic:packet_lost",
                "data": {"header": {"packet_type": "1RTT", "packet_number": 7},
                    "trigger": trigger, "is_mtu_probe_packet": false}
            })
        );
    }
    assert_eq!(
        records[8],
        json!({
            "time": 0.0, "group_id": "00ab", "name": "quic:recovery_metrics_updated",
            "data": {"latest_rtt": 1.25, "bytes_in_flight": u64::MAX}
        })
    );
    let early_packet = SentPacket {
        is_0rtt: true,
        ..packet
    };
    sink.emit_packet_lost(9, &early_packet, delay, SpaceId::Data, start + delay, group);
    assert_eq!(trace.records()[9]["data"]["header"]["packet_type"], "0RTT");
    drop(sink);
    assert_eq!(
        trace.0.lock().flushes,
        0,
        "another stream handle still owns the writer"
    );
    drop(stream);
    assert_eq!(trace.0.lock().flushes, 1);
}

#[test]
fn qlog_writer_failure_disables_further_writes_and_preserves_first_error() {
    let trace = Trace::default();
    let start = Instant::now();
    let mut writer = QlogWriter::new(Box::new(trace.clone()), start, None, None).unwrap();
    trace.0.lock().remaining = Some(5);
    let event = || {
        Event::PacketReceived(Packet {
            header: PacketHeader {
                packet_type: PacketType::Initial,
                packet_number: 0,
            },
            raw: None,
        })
    };
    let error = writer.emit(&[], event(), start).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    let calls = trace.0.lock().calls;
    writer.emit(&[], event(), start).unwrap();
    assert_eq!(
        trace.0.lock().calls,
        calls,
        "a partial record ends the trace"
    );

    let trace = Trace::default();
    trace.0.lock().remaining = Some(0);
    assert!(
        crate::proto::QlogConfig::default()
            .with_writer(Box::new(trace))
            .into_stream()
            .is_none()
    );
    assert!(crate::proto::QlogConfig::default().into_stream().is_none());
}

#[test]
fn qlog_short_writes_and_interruptions_preserve_complete_records() {
    let trace = Trace::default();
    {
        let mut output = trace.0.lock();
        output.max_chunk = Some(1);
        output.interrupt_once = true;
    }
    let start = Instant::now();
    let stream = crate::proto::QlogConfig::default()
        .with_writer(Box::new(trace.clone()))
        .with_start_time(start)
        .into_stream()
        .unwrap();
    trace.0.lock().interrupt_once = true;
    QlogSink::from(Some(stream)).emit_packet_received(
        42,
        SpaceId::Handshake,
        false,
        start,
        ConnectionId::new(&[]),
    );
    let records = trace.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1],
        json!({"time": 0.0, "group_id": "", "name": "quic:packet_received", "data": {"header": {"packet_type": "handshake", "packet_number": 42}}})
    );
    assert_eq!(trace.0.lock().flushes, 1);
}

#[test]
fn qlog_cloned_streams_serialize_concurrent_records() {
    let trace = Trace::default();
    let start = Instant::now();
    let stream = crate::proto::QlogConfig::default()
        .with_writer(Box::new(trace.clone()))
        .into_stream()
        .unwrap();
    std::thread::scope(|scope| {
        for producer in 0..4 {
            let sink = QlogSink::from(Some(stream.clone()));
            scope.spawn(move || {
                for pn in 0..100 {
                    sink.emit_packet_sent(
                        pn,
                        1200,
                        SpaceId::Data,
                        false,
                        start,
                        ConnectionId::new(&[producer]),
                    );
                }
            });
        }
    });
    let records = trace.records();
    assert_eq!(records.len(), 401);
    let mut packets = std::collections::BTreeSet::new();
    for record in &records[1..] {
        assert_eq!(record["name"], "quic:packet_sent");
        assert!(packets.insert((
            record["group_id"].as_str().unwrap(),
            record["data"]["header"]["packet_number"].as_u64().unwrap()
        )));
    }
    for group in ["00", "01", "02", "03"] {
        for pn in 0..100 {
            assert!(packets.contains(&(group, pn)));
        }
    }
    drop(stream);
    assert_eq!(trace.0.lock().flushes, 1);
}

#[test]
fn qlog_recovery_metrics_emit_initial_snapshot_then_changes() {
    let trace = Trace::default();
    let start = Instant::now();
    let stream = crate::proto::QlogConfig::default()
        .with_writer(Box::new(trace.clone()))
        .with_start_time(start)
        .into_stream()
        .unwrap();
    let sink = QlogSink::from(Some(stream));
    let mut path = PathData::new(
        "127.0.0.1:443".parse().unwrap(),
        None,
        false,
        None,
        0,
        start,
        &crate::proto::TransportConfig::default(),
    );
    let group = ConnectionId::new(&[0xff]);
    QlogSink::default().emit_recovery_metrics(0, &mut path, start, group);
    sink.emit_recovery_metrics(0, &mut path, start, group);
    let records = trace.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1]["name"], "quic:recovery_metrics_updated");
    let data = &records[1]["data"];
    for field in [
        "min_rtt",
        "smoothed_rtt",
        "latest_rtt",
        "rtt_variance",
        "pto_count",
        "bytes_in_flight",
        "congestion_window",
    ] {
        assert!(data.get(field).is_some(), "missing {field}");
    }
    assert!(data.get("packets_in_flight").is_none());
    sink.emit_recovery_metrics(0, &mut path, start, group);
    assert_eq!(trace.records().len(), 2);
    sink.emit_recovery_metrics(1, &mut path, start + Duration::from_millis(5), group);
    assert_eq!(
        trace.records()[2],
        json!({"time": 5.0, "group_id": "ff", "name": "quic:recovery_metrics_updated", "data": {"pto_count": 1}})
    );
}
