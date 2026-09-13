use super::*;
use crate::qlog::QlogConfig;
use parking_lot::Mutex;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;

#[derive(Clone, Default)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl AsyncWrite for CaptureWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

pub(super) struct Capture {
    writer: CaptureWriter,
    recorder: Mutex<Option<crate::qlog::QlogRecorder>>,
    runtime: tokio::runtime::Runtime,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            writer: CaptureWriter::default(),
            recorder: Mutex::new(None),
            runtime: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        }
    }
}

impl Capture {
    pub(super) fn config(&self, start: Instant) -> crate::qlog::QlogRecorder {
        let _entered = self.runtime.enter();
        let recorder = QlogConfig::default()
            .with_writer(Box::new(self.writer.clone()))
            .with_start_time(start)
            .start()
            .unwrap();
        assert!(self.recorder.lock().replace(recorder.clone()).is_none());
        recorder
    }

    pub(super) fn transport(&self, start: Instant) -> Arc<TransportConfig> {
        Arc::new(TransportConfig::default().with_qlog_recorder(self.config(start)))
    }

    fn flush(&self) {
        let recorder = self.recorder.lock().clone().expect("configured capture");
        // Drive the same runtime that owns this synchronous simulator's recording task.
        self.runtime.block_on(recorder.flush()).unwrap();
    }

    pub(super) fn clear(&self) {
        self.flush();
        self.writer.0.lock().clear();
    }

    pub(super) fn records(&self) -> Vec<serde_json::Value> {
        self.flush();
        self.writer
            .0
            .lock()
            .split(|byte| *byte == 0x1e)
            .filter(|record| !record.is_empty())
            .map(|record| serde_json::from_slice(record).unwrap())
            .collect()
    }

    pub(super) fn events(&self, name: &str) -> Vec<serde_json::Value> {
        self.records()
            .into_iter()
            .filter(|record| record["name"] == name)
            .collect()
    }

    fn take_sent(&self) -> Vec<serde_json::Value> {
        let records = self.records();
        self.writer.0.lock().clear();
        records
            .into_iter()
            .filter(|record| record["name"] == "quic:packet_sent")
            .collect()
    }
}

/// Send a flight without delivering it, checking the logged packet lengths against the wire.
fn capture_flight(pair: &mut Pair, capture: &Capture) -> Vec<serde_json::Value> {
    assert!(pair.client.outbound.is_empty());
    capture.clear();
    for _ in 0..10 {
        pair.client.drive(pair.time, pair.server.addr);
        if !pair.client.outbound.is_empty() {
            break;
        }
        pair.time = pair
            .client
            .next_wakeup()
            .expect("a pending flight has a wakeup");
    }
    let sent = capture.take_sent();
    assert!(!sent.is_empty(), "the flight must actually send packets");
    let logged_bytes: u64 = sent
        .iter()
        .map(|record| record["data"]["raw"]["length"].as_u64().unwrap())
        .sum();
    let wire_bytes: usize = pair
        .client
        .outbound
        .iter()
        .map(|(_, bytes)| bytes.len())
        .sum();
    assert_eq!(logged_bytes, wire_bytes as u64);
    sent
}

#[test]
fn lost_packets_keep_their_original_encryption_level() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let mut config = client_config_with_deterministic_pns();

    // Populate the TLS session cache before enabling this connection's trace.
    let (client_ch, _) = pair.connect_with(config.clone());
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt(0), Bytes::new());
    pair.drive();
    pair.client
        .addr
        .set_port(CLIENT_PORTS.lock().next().unwrap());

    let capture = Capture::default();
    let mut transport = TransportConfig::default();
    transport.deterministic_packet_numbers(true);
    transport.set_qlog_recorder(capture.config(pair.time));
    config.transport = Arc::new(transport);
    let client_ch = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());

    // Deliver Initial separately, so dropping the next flight loses only early data.
    let initial = capture_flight(&mut pair, &capture);
    assert!(
        initial
            .iter()
            .all(|event| event["data"]["header"]["packet_type"] == "initial")
    );
    pair.drive_client();
    let stream = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, stream)
        .write(b"early data")
        .unwrap();
    let early = capture_flight(&mut pair, &capture);
    assert_eq!(early.len(), 1);
    assert_eq!(early[0]["data"]["header"]["packet_type"], "0RTT");
    let early_number = early[0]["data"]["header"]["packet_number"].clone();
    pair.client.outbound.clear();

    // Process the server's handshake before any data-space acknowledgement can declare loss.
    pair.drive_server();
    pair.drive_client();
    assert!(!pair.client_conn_mut(client_ch).is_handshaking());
    assert!(pair.client_conn_mut(client_ch).accepted_0rtt());
    assert!(
        capture
            .records()
            .iter()
            .all(|event| event["name"] != "quic:packet_lost")
    );
    pair.drive();
    pair.server.assert_accept();
    let losses: Vec<_> = capture
        .records()
        .into_iter()
        .filter(|event| event["name"] == "quic:packet_lost")
        .collect();
    assert!(
        losses.iter().any(|event| {
            event["data"]["header"]["packet_number"] == early_number
                && event["data"]["header"]["packet_type"] == "0RTT"
        }),
        "the lost early packet must retain its 0-RTT type after 1-RTT keys arrive: {losses:?}"
    );

    // A packet built with 1-RTT keys must not inherit the early packet's classification.
    pair.client_send(client_ch, stream)
        .write(b"established data")
        .unwrap();
    let established = capture_flight(&mut pair, &capture);
    assert_eq!(established.len(), 1);
    assert_eq!(established[0]["data"]["header"]["packet_type"], "1RTT");
    let established_number = established[0]["data"]["header"]["packet_number"].clone();
    pair.client.outbound.clear();
    pair.drive();
    let losses: Vec<_> = capture
        .records()
        .into_iter()
        .filter(|event| event["name"] == "quic:packet_lost")
        .collect();
    assert!(
        losses.iter().any(|event| {
            event["data"]["header"]["packet_number"] == established_number
                && event["data"]["header"]["packet_type"] == "1RTT"
        }),
        "the lost established packet must be classified as 1-RTT: {losses:?}"
    );
}
