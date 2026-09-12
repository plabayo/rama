use super::*;
use parking_lot::Mutex;
use std::io::{self, Write};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn records(&self) -> Vec<serde_json::Value> {
        self.0
            .lock()
            .split(|byte| *byte == 0x1e)
            .filter(|record| !record.is_empty())
            .map(|record| serde_json::from_slice(record).unwrap())
            .collect()
    }

    fn take_sent(&self) -> Vec<serde_json::Value> {
        let records = self.records();
        self.0.lock().clear();
        records
            .into_iter()
            .filter(|record| record["name"] == "quic:packet_sent")
            .collect()
    }
}

/// Send a flight without delivering it, checking the logged packet lengths against the wire.
fn capture_flight(pair: &mut Pair, capture: &Capture) -> Vec<serde_json::Value> {
    assert!(pair.client.outbound.is_empty());
    capture.0.lock().clear();
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
    transport.set_qlog(
        QlogConfig::default()
            .with_writer(Box::new(capture.clone()))
            .with_start_time(pair.time),
    );
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
