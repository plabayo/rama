//! The qlog trace a connection writes (draft-ietf-quic-qlog), configured and read back through
//! the public API only.

mod common;

use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use common::*;
use rama::{
    quic::{ClientConfig, Endpoint, QlogConfig, TransportConfig},
    utils::octets,
};

/// A writer a test can read back. qlog takes ownership of the writer, so what it wrote is read
/// through the shared buffer rather than the handle.
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<u8>>>);

impl Trace {
    fn written(&self) -> Vec<u8> {
        self.0.lock().expect("the buffer is not poisoned").clone()
    }
}

impl io::Write for Trace {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("the buffer is not poisoned")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A connection configured with a qlog writer records what it sends and receives, as qlog
/// records this test parses. A second connection on the same endpoint, configured without a
/// writer, adds nothing to that same writer while carrying its own payload.
#[tokio::test]
async fn a_configured_qlog_writer_receives_the_connection_s_trace() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = quinn::Endpoint::server(quinn_server_config(&auth), localhost())
        .expect("the quinn server binds");
    let server_addr = server.local_addr().expect("its address");
    let accepting = Peer::spawn({
        let server = server.clone();
        async move {
            for _ in 0..2 {
                let Some(incoming) = server.accept().await else {
                    return;
                };
                let Ok(conn) = incoming.await else { return };
                let mut uni = step("the stream arrives", conn.accept_uni())
                    .await
                    .expect("it opens");
                let _ = step("the payload", uni.read_to_end(octets::kib(64)))
                    .await
                    .expect("it is read whole");
                step("the connection closes", conn.closed()).await;
            }
        }
    });

    let client = step("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");

    // The traced connection.
    let trace = Trace::default();
    let traced = rama_client_config(anchor.clone()).with_transport_config(Arc::new(
        TransportConfig::default().with_qlog(QlogConfig::default().with_writer(Box::new(
            trace.clone(),
        ))),
    ));
    exchange(&client, server_addr, traced, &payload(0x4d, octets::kib(16))).await;

    let events = records(&trace.written());
    for name in ["packet_sent", "packet_received"] {
        assert!(
            events.iter().any(|event| event.contains(name)),
            "the writer received the connection's {name} records: {events:?}"
        );
    }
    let after_the_first = quiescent(&trace).await;

    // The second connection has no qlog, and the writer is the same one, so anything it
    // recorded would show as growth.
    let untraced =
        rama_client_config(anchor).with_transport_config(Arc::new(TransportConfig::default()));
    exchange(
        &client,
        server_addr,
        untraced,
        &payload(0x77, octets::kib(24)),
    )
    .await;
    assert_eq!(
        trace.written().len(),
        after_the_first,
        "a connection configured without a writer records nothing into it"
    );

    step("rama's shutdown", client.wait_idle()).await;
    server.close(0u32.into(), b"done");
    step("the quinn server goes idle", server.wait_idle()).await;
    accepting.join("the quinn peer").await;
}

/// The size the trace settles at: the connection writes its last records while it drains, so
/// the comparison has to start from a size that has stopped moving.
async fn quiescent(trace: &Trace) -> usize {
    let mut size = trace.written().len();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = trace.written().len();
        if now == size {
            return size;
        }
        size = now;
    }
    panic!("the trace never stopped growing");
}

/// The event names in a qlog stream, which is JSON text sequences: each record is preceded by
/// a record separator and holds one JSON object (RFC 7464).
fn records(written: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(written)
        .split('\u{1e}')
        .filter(|record| !record.trim().is_empty())
        .filter_map(|record| {
            let value: serde_json::Value = serde_json::from_str(record.trim()).ok()?;
            Some(value.get("name")?.as_str()?.to_owned())
        })
        .collect()
}

/// One connection carrying `payload` on a unidirectional stream, closed cleanly.
async fn exchange(
    client: &Endpoint,
    server_addr: std::net::SocketAddr,
    config: ClientConfig,
    payload: &[u8],
) {
    let conn = step(
        "the rama client connects",
        client
            .connect_with(config, server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");
    let mut stream = step("the stream opens", conn.open_uni())
        .await
        .expect("it opens");
    step("the payload is written", stream.write_all(payload))
        .await
        .expect("it is written");
    stream.finish().expect("the stream is finished");
    step("the peer has it", stream.stopped())
        .await
        .expect("the peer did not reset it");
    conn.close(0u32.into(), b"done");
    step("the connection ends", conn.closed()).await;
}
