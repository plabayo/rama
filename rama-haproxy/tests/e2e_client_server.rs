// Helpers below are not tagged `#[test]` themselves, so the workspace-wide
// `unwrap/expect-in-tests` allowance doesn't apply — opt them out explicitly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end integration tests that wire the rama-haproxy *client* layer
//! into the rama-haproxy *server* layer over rama's [`MockConnectorService`]
//! (which sets up an in-memory duplex pair under the hood), then assert that
//! PROXY protocol v2 features survive the round trip:
//!
//! - the source `SocketAddr` is exposed as a [`Forwarded`] extension,
//! - TLVs supplied to the client (`with_tlv(...)`) reappear on the server
//!   side as [`HaProxyTlvs`] entries (including AUTHORITY → typed `Domain`),
//! - the optional CRC32C TLV (`with_crc32c(true)`) is computed by the client
//!   and validated by the server's default (CRC-verifying) strictness.

use std::sync::Arc;

use parking_lot::Mutex;
use rama_core::{
    Layer, Service, ServiceInput, bytes::Bytes, error::BoxError, extensions::ExtensionsRef,
    service::service_fn,
};
use rama_haproxy::{
    client::{HaProxyLayer as ClientLayer, protocol as client_protocol, version as client_version},
    protocol::v2,
    server::{HaProxyCommand, HaProxyService as ServerService, HaProxyTlvs},
};
use rama_net::{
    address::{Domain, SocketAddress},
    forwarded::Forwarded,
    stream::SocketInfo,
    test_utils::client::MockConnectorService,
};

/// What the server-side inner service captured from the upstream extensions.
#[derive(Default)]
struct Captured {
    forwarded: Option<Forwarded>,
    command: Option<HaProxyCommand>,
    tlvs: Option<HaProxyTlvs>,
}

/// Source address the simulated upstream client lives at — embedded as `for=`
/// of the emitted PROXY header.
const SRC: SocketAddress = SocketAddress::local_ipv4(54321);

async fn run_e2e<F>(configure_client: F) -> Captured
where
    F: FnOnce(
        ClientLayer<client_protocol::Tcp, client_version::Two>,
    ) -> ClientLayer<client_protocol::Tcp, client_version::Two>,
{
    // Capture buffer for the server-side inner service.
    let captured: Arc<Mutex<Captured>> = Arc::new(Mutex::new(Captured::default()));
    let captured_clone = captured.clone();

    // `MockConnectorService::new` takes a Fn that produces the server-side
    // Service<MockSocket> each time a connection is "dialled". The mock
    // connector creates a duplex pair internally and spawns the server task.
    let connector = MockConnectorService::new(move || {
        let captured = captured_clone.clone();
        ServerService::new(service_fn(move |stream| {
            let captured = captured.clone();
            async move {
                let exts = <_ as ExtensionsRef>::extensions(&stream);
                let mut guard = captured.lock();
                guard.forwarded = exts.get_ref::<Forwarded>().cloned();
                guard.command = exts.get_ref::<HaProxyCommand>().copied();
                guard.tlvs = exts.get_ref::<HaProxyTlvs>().cloned();
                Ok::<_, BoxError>(())
            }
        }))
    });

    // Configure the haproxy client layer and stack it on the mock connector.
    let client_layer = configure_client(ClientLayer::tcp());
    let client_svc = client_layer.layer(connector);

    // Input carries the original source socket address via `SocketInfo`,
    // which is what the client layer reads to build the `for=` of the PROXY
    // header.
    let input: ServiceInput<()> = ServiceInput::new(());
    input.extensions().insert(SocketInfo::new(None, SRC));

    // Driving the client triggers the connector, which spawns the server,
    // which reads + parses the PROXY header and populates `captured`.
    let established = client_svc.serve(input).await.expect("client serve");
    // Drop the client side of the duplex so the server's read loop sees EOF
    // after the PROXY header bytes.
    drop(established);

    // Give the spawned server task a turn to finish before we read the
    // captured state.
    tokio::task::yield_now().await;

    let guard = captured.lock();
    Captured {
        forwarded: guard.forwarded.clone(),
        command: guard.command,
        tlvs: guard.tlvs.clone(),
    }
}

/// Variant of [`run_e2e`] that expects the client layer itself to refuse to
/// emit a header (e.g. because the test combined mutually-exclusive options),
/// and returns the resulting error.
async fn run_e2e_expect_client_error<F>(configure_client: F) -> BoxError
where
    F: FnOnce(
        ClientLayer<client_protocol::Tcp, client_version::Two>,
    ) -> ClientLayer<client_protocol::Tcp, client_version::Two>,
{
    // The server side never actually receives a header in this path, so we
    // can use a tiny no-op inner.
    let connector = MockConnectorService::new(|| {
        ServerService::new(service_fn(|_stream| async move { Ok::<_, BoxError>(()) }))
    });
    let client_svc = configure_client(ClientLayer::tcp()).layer(connector);
    let input: ServiceInput<()> = ServiceInput::new(());
    input.extensions().insert(SocketInfo::new(None, SRC));
    client_svc
        .serve(input)
        .await
        .expect_err("expected client error")
}

#[tokio::test]
async fn roundtrip_minimal_v2() {
    let out = run_e2e(|l| l).await;
    let fwd = out.forwarded.expect("Forwarded must be present");
    let socket = fwd.client_socket_addr().expect("client socket addr");
    assert_eq!(socket.ip_addr, SRC.ip_addr);
    assert_eq!(socket.port, SRC.port);
    assert_eq!(out.command, Some(HaProxyCommand::Proxy));
    assert!(
        out.tlvs.is_none() || out.tlvs.as_ref().unwrap().entries().is_empty(),
        "no TLVs configured: extension should be absent or empty",
    );
}

#[tokio::test]
async fn roundtrip_with_authority_tlv() {
    let out =
        run_e2e(|l| l.with_tlv(v2::Type::Authority, Bytes::from_static(b"example.com"))).await;
    let tlvs = out.tlvs.expect("TLV extension must be present");
    let authority = tlvs.authority().expect("authority TLV parsed as Domain");
    assert_eq!(authority, Domain::from_static("example.com"));
    // Raw access still works.
    let raw = tlvs.get(v2::Type::Authority).expect("authority raw");
    assert_eq!(raw.as_ref(), b"example.com");
}

#[tokio::test]
async fn roundtrip_with_unique_id_and_unknown_tlv() {
    let unique = b"req-abc-1234567890";
    let vendor_kind = v2::Type::Unknown(0xEA); // AWS-style vendor TLV
    let vendor_value = Bytes::from_static(b"\x01\x02\x03\x04");

    let out = run_e2e(|l| {
        l.with_tlv(v2::Type::UniqueId, Bytes::copy_from_slice(unique))
            .with_tlv(vendor_kind, vendor_value.clone())
    })
    .await;
    let tlvs = out.tlvs.expect("TLV extension must be present");
    assert_eq!(
        tlvs.unique_id().expect("unique id").as_ref(),
        unique.as_slice(),
    );
    let vendor = tlvs.get(vendor_kind).expect("vendor TLV must round-trip");
    assert_eq!(vendor.as_ref(), vendor_value.as_ref());
    // Iteration order matches insertion order.
    let kinds: Vec<_> = tlvs.entries().iter().map(|t| t.kind).collect();
    assert_eq!(kinds, vec![v2::Type::UniqueId, vendor_kind]);
}

/// Regression: combining `with_payload` with `with_crc32c(true)` is rejected
/// at send time — the raw payload would sit between the TLVs and the CRC
/// TLV, breaking the receiver's TLV parse.
#[tokio::test]
async fn rejects_payload_combined_with_crc32c() {
    let err = run_e2e_expect_client_error(|l| {
        l.with_payload(Bytes::from_static(b"garbage"))
            .with_crc32c(true)
    })
    .await;
    let msg = err.to_string();
    assert!(
        msg.contains("payload") && msg.contains("crc32c"),
        "unexpected error: {msg}",
    );
}

/// Regression: manually queuing a CRC32C TLV via `with_tlv` is rejected at
/// send time — CRC values must be computed by the builder over the final
/// header, not supplied by the caller.
#[tokio::test]
async fn rejects_manual_crc32c_tlv() {
    let err = run_e2e_expect_client_error(|l| {
        l.with_tlv(v2::Type::CRC32C, Bytes::from_static(&[0u8; 4]))
    })
    .await;
    let msg = err.to_string();
    assert!(
        msg.contains("CRC32C") && msg.contains("with_crc32c"),
        "unexpected error: {msg}",
    );
}

#[tokio::test]
async fn roundtrip_with_crc32c_is_accepted() {
    // The server uses default strictness, which verifies CRC32C when present.
    // If the client computed a wrong CRC, the server would reject the
    // connection and `MockConnectorService` panics, failing the test.
    let out = run_e2e(|l| {
        l.with_tlv(v2::Type::Authority, Bytes::from_static(b"svc.example"))
            .with_crc32c(true)
    })
    .await;
    let tlvs = out.tlvs.expect("TLV extension must be present");
    // Authority survives even when CRC32C is appended.
    assert_eq!(tlvs.authority(), Some(Domain::from_static("svc.example")));
    // The CRC32C TLV itself is also exposed.
    assert!(
        tlvs.get(v2::Type::CRC32C).is_some(),
        "CRC32C TLV should be present after roundtrip",
    );
}
