//! Native relay pairing against independent raw HTTP/2 peers, without UA.
//! This is an in-process wire fixture; external Go/tshark proof remains separate.

#![expect(clippy::unwrap_used, reason = "raw native peer test fixtures")]

use rama_core::{
    Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    io::BridgeIo,
    rt::Executor,
};
use rama_http_backend::proxy::mitm::{H2InitialCreditLimits, HttpMitmRelay};
use rama_http_core::h2::initial_credit::{
    Failure, PeerInitialCredit, ReceiveInitialCredit, Status,
};
use rama_http_types::{
    Version,
    conn::{H2ClientContextParams, H2ServerContextParams, H2SettingsLimits, TargetHttpVersion},
};
use rama_net::test_utils::client::MockSocket;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    task::JoinHandle,
};

async fn frame(io: &mut DuplexStream, kind: u8, flags: u8, stream: u32, body: &[u8]) {
    let length = (body.len() as u32).to_be_bytes();
    let mut head = [0; 9];
    head[..3].copy_from_slice(&length[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..].copy_from_slice(&stream.to_be_bytes());
    io.write_all(&head).await.unwrap();
    io.write_all(body).await.unwrap();
}

async fn next(io: &mut DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    let mut head = [0; 9];
    io.read_exact(&mut head).await.unwrap();
    let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let stream = u32::from_be_bytes(head[5..].try_into().unwrap()) & 0x7fff_ffff;
    let mut body = vec![0; length];
    io.read_exact(&mut body).await.unwrap();
    (head[3], head[4], stream, body)
}

async fn initial_client(io: &mut DuplexStream) {
    io.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    // Explicitly disabled push is required by the relay's existing SETTINGS contract.
    frame(io, 4, 0, 0, &[0, 2, 0, 0, 0, 0]).await;
}

async fn preface(io: &mut DuplexStream) {
    let mut bytes = [0; 24];
    io.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let first = next(io).await;
    assert_eq!((first.0, first.1, first.2), (4, 0, 0));
    assert_eq!(first.3, [0, 2, 0, 0, 0, 0]);
}

// The source ACK follows native credit publication. On this current-thread
// fixture the target subsequently checks that credit before acknowledging its
// own PING. This is a local protocol barrier, not cross-hop delivery ordering.
async fn credit_until_ping_ack(io: &mut DuplexStream, expected: u32, nonce: &[u8; 8]) {
    frame(io, 6, 0, 0, nonce).await;
    let mut received = 0;
    loop {
        let (kind, flags, stream, body) = next(io).await;
        if kind == 8 && stream == 0 {
            received += u32::from_be_bytes(body.try_into().unwrap());
        } else if kind == 6 && flags == 1 {
            assert_eq!(body, nonce);
            break;
        }
    }
    assert_eq!(
        received, expected,
        "mirrored connection credit at target ACK"
    );
}

async fn until(io: &mut DuplexStream, kind: u8, stream: u32) -> (u8, Vec<u8>) {
    loop {
        let (actual, flags, id, body) = next(io).await;
        if actual == kind && id == stream {
            return (flags, body);
        }
    }
}

async fn ping_without_credit(io: &mut DuplexStream, nonce: &[u8; 8]) {
    frame(io, 6, 0, 0, nonce).await;
    loop {
        let (kind, flags, stream, body) = next(io).await;
        assert!(
            kind != 8 || stream != 0,
            "unexpected mirrored connection credit"
        );
        if kind == 6 && flags == 1 {
            assert_eq!(body, nonce);
            break;
        }
    }
}

async fn request(io: &mut DuplexStream, post: bool) {
    // Static method/scheme/path and literal authority. Neither endpoint uses
    // Rama's encoder/decoder, so this exercises the actual native relay codecs.
    let mut fields = vec![if post { 0x83 } else { 0x82 }, 0x87, 0x84, 0x01, 12];
    fields.extend_from_slice(b"example.test");
    frame(io, 1, if post { 4 } else { 5 }, 1, &fields).await;
    if post {
        frame(io, 0, 1, 1, b"x").await;
    }
}

async fn eof(io: &mut DuplexStream) {
    let mut bytes = [0; 4096];
    while io.read(&mut bytes).await.unwrap() != 0 {}
}

fn compatible(ingress: &Extensions, egress: &Extensions) {
    let server = H2ServerContextParams {
        initial_connection_window_size: Some(65_535),
        adaptive_window: Some(false),
        ..Default::default()
    };
    ingress.insert(server);
    let client = H2ClientContextParams {
        init_connection_window_size: Some(65_535),
        adaptive_window: Some(false),
        ..Default::default()
    };
    egress.insert(client);
}

struct Fixture {
    client: DuplexStream,
    origin: DuplexStream,
    ingress: Extensions,
    egress: Extensions,
    relay: Option<JoinHandle<Result<(), BoxError>>>,
}

impl Fixture {
    fn new(mirror: bool, configure: impl FnOnce(&Extensions, &Extensions)) -> Self {
        Self::with_limits(
            if mirror {
                Some(H2InitialCreditLimits::try_new(65_540, 65_538).unwrap())
            } else {
                None
            },
            configure,
        )
    }

    fn with_limits(
        limits: Option<H2InitialCreditLimits>,
        configure: impl FnOnce(&Extensions, &Extensions),
    ) -> Self {
        let (client, ingress) = tokio::io::duplex(64 * 1024);
        let (egress, origin) = tokio::io::duplex(64 * 1024);
        let ingress = MockSocket::new(ingress);
        let egress = MockSocket::new(egress);
        let ingress_extensions = ingress.extensions().clone();
        let egress_extensions = egress.extensions().clone();
        egress_extensions.insert(TargetHttpVersion(Version::HTTP_2));
        configure(&ingress_extensions, &egress_extensions);
        let relay =
            HttpMitmRelay::new(Executor::default()).maybe_with_mirror_initial_h2_credit(limits);
        let relay = tokio::spawn(async move { relay.serve(BridgeIo(ingress, egress)).await });
        Self {
            client,
            origin,
            ingress: ingress_extensions,
            egress: egress_extensions,
            relay: Some(relay),
        }
    }

    async fn handshake(&mut self) {
        initial_client(&mut self.client).await;
        preface(&mut self.origin).await;
        frame(&mut self.origin, 4, 0, 0, &[]).await;
        frame(&mut self.origin, 4, 1, 0, &[]).await;
        let settings = next(&mut self.client).await;
        assert_eq!((settings.0, settings.1, settings.2), (4, 0, 0));
        assert!(settings.3.is_empty());
        frame(&mut self.client, 4, 1, 0, &[]).await;
    }

    fn downstream_credit(&self) -> PeerInitialCredit {
        self.ingress
            .self_get_ref::<PeerInitialCredit>()
            .unwrap()
            .clone()
    }

    fn upstream_credit(&self) -> PeerInitialCredit {
        self.egress
            .self_get_ref::<PeerInitialCredit>()
            .unwrap()
            .clone()
    }

    async fn cancel(&mut self) {
        let relay = self.relay.take().unwrap();
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
        eof(&mut self.origin).await;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(relay) = self.relay.take() {
            relay.abort();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_h2_relay_mirrors_initial_credit_and_freezes_both_boundaries() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(true, compatible);
        fixture.handshake().await;
        frame(&mut fixture.client, 8, 0, 0, &1_u32.to_be_bytes()).await;
        frame(&mut fixture.client, 8, 0, 0, &2_u32.to_be_bytes()).await;
        ping_without_credit(&mut fixture.client, b"source01").await;
        credit_until_ping_ack(&mut fixture.origin, 3, b"target01").await;
        frame(&mut fixture.origin, 8, 0, 0, &5_u32.to_be_bytes()).await;
        ping_without_credit(&mut fixture.origin, b"source02").await;
        credit_until_ping_ack(&mut fixture.client, 5, b"target02").await;
        request(&mut fixture.client, false).await;
        until(&mut fixture.origin, 1, 1).await;
        frame(&mut fixture.origin, 1, 5, 1, &[0x88]).await;
        until(&mut fixture.client, 1, 1).await;
        assert_eq!(fixture.downstream_credit().complete().await, Ok(65_538));
        assert_eq!(fixture.upstream_credit().complete().await, Ok(65_540));
        // Later WINDOW_UPDATE is ordinary independent per-hop flow control.
        frame(&mut fixture.client, 8, 0, 0, &7_u32.to_be_bytes()).await;
        ping_without_credit(&mut fixture.client, b"source03").await;
        credit_until_ping_ack(&mut fixture.origin, 0, b"target03").await;
        frame(&mut fixture.origin, 8, 0, 0, &9_u32.to_be_bytes()).await;
        ping_without_credit(&mut fixture.origin, b"source04").await;
        credit_until_ping_ack(&mut fixture.client, 0, b"target04").await;
        assert_eq!(
            fixture.downstream_credit().snapshot(),
            Status::Complete { target: 65_538 }
        );
        assert_eq!(
            fixture.upstream_credit().snapshot(),
            Status::Complete { target: 65_540 }
        );
        fixture.cancel().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_h2_relay_default_does_not_install_or_mirror_credit_cells() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(false, compatible);
        fixture.handshake().await;
        assert!(!fixture.ingress.contains::<PeerInitialCredit>());
        assert!(!fixture.egress.contains::<PeerInitialCredit>());
        assert!(!fixture.ingress.contains::<ReceiveInitialCredit>());
        assert!(!fixture.egress.contains::<ReceiveInitialCredit>());
        frame(&mut fixture.client, 8, 0, 0, &3_u32.to_be_bytes()).await;
        frame(&mut fixture.origin, 8, 0, 0, &5_u32.to_be_bytes()).await;
        ping_without_credit(&mut fixture.origin, b"default1").await;
        ping_without_credit(&mut fixture.client, b"default2").await;
        request(&mut fixture.client, false).await;
        until(&mut fixture.origin, 1, 1).await;
        frame(&mut fixture.origin, 1, 5, 1, &[0x88]).await;
        until(&mut fixture.client, 1, 1).await;
        // Unchanged default ownership: close both peers rather than claim the
        // new opt-in pair's cancellation contract for an unpaired relay.
        fixture.client.shutdown().await.unwrap();
        fixture.origin.shutdown().await.unwrap();
        let relay = fixture.relay.take().unwrap();
        relay.abort();
        let _result = relay.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_h2_relay_missing_or_conflicting_credit_options_fail_before_egress_output() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for case in 0..7 {
            let mut fixture = Fixture::new(true, |ingress, egress| {
                if case == 0 {
                    return;
                }
                compatible(ingress, egress);
                match case {
                    1 => {
                        let params = H2ServerContextParams {
                            adaptive_window: Some(false),
                            ..Default::default()
                        };
                        ingress.insert(params);
                    }
                    2 => {
                        let params = H2ClientContextParams {
                            adaptive_window: Some(false),
                            ..Default::default()
                        };
                        egress.insert(params);
                    }
                    3 => {
                        let mut params =
                            ingress.get_ref::<H2ServerContextParams>().unwrap().clone();
                        params.initial_connection_window_size = Some(65_536);
                        ingress.insert(params);
                    }
                    4 => {
                        let mut params = egress.get_ref::<H2ClientContextParams>().unwrap().clone();
                        params.init_connection_window_size = Some(65_536);
                        egress.insert(params);
                    }
                    5 => {
                        let mut params =
                            ingress.get_ref::<H2ServerContextParams>().unwrap().clone();
                        params.adaptive_window = Some(true);
                        ingress.insert(params);
                    }
                    6 => {
                        let mut params = egress.get_ref::<H2ClientContextParams>().unwrap().clone();
                        params.adaptive_window = Some(true);
                        egress.insert(params);
                    }
                    _ => panic!("fixture case"),
                }
            });
            initial_client(&mut fixture.client).await;
            let error = fixture.relay.take().unwrap().await.unwrap().unwrap_err();
            assert!(error.to_string().contains("explicit 65535/non-adaptive"));
            let mut byte = [0];
            assert_eq!(fixture.origin.read(&mut byte).await.unwrap(), 0);
            assert!(!fixture.ingress.contains::<PeerInitialCredit>());
            assert!(!fixture.egress.contains::<PeerInitialCredit>());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_h2_relay_existing_credit_handles_are_not_overwritten() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for case in 0..4 {
            let existing = PeerInitialCredit::new();
            let mut fixture = Fixture::new(true, |ingress, egress| {
                compatible(ingress, egress);
                match case {
                    0 => {
                        ingress.insert(existing.clone());
                    }
                    1 => {
                        egress.insert(existing.clone());
                    }
                    2 => {
                        ingress.insert(existing.try_receive_target(65_536).unwrap());
                    }
                    3 => {
                        egress.insert(existing.try_receive_target(65_536).unwrap());
                    }
                    _ => panic!("fixture case"),
                }
            });
            initial_client(&mut fixture.client).await;
            let error = fixture.relay.take().unwrap().await.unwrap().unwrap_err();
            assert!(error.to_string().contains("existing native handles"));
            assert_eq!(existing.snapshot(), Status::Unbound);
            let mut byte = [0];
            assert_eq!(fixture.origin.read(&mut byte).await.unwrap(), 0);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_h2_relay_option_ignores_actual_h1_ingress() {
    tokio::time::timeout(Duration::from_secs(5), async {
        // Deliberately absent H2 window/adaptive params: protocol inspection
        // must keep this ordinary H1 ingress outside the opt-in H2 contract.
        let mut fixture = Fixture::new(true, |_, _| {});
        fixture
            .client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .unwrap();
        let mut bytes = [0; 24];
        fixture.origin.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let settings = next(&mut fixture.origin).await;
        assert_eq!((settings.0, settings.1, settings.2), (4, 0, 0));
        assert!(!fixture.ingress.contains::<PeerInitialCredit>());
        assert!(!fixture.egress.contains::<PeerInitialCredit>());
        assert!(!fixture.ingress.contains::<ReceiveInitialCredit>());
        assert!(!fixture.egress.contains::<ReceiveInitialCredit>());
        fixture.origin.shutdown().await.unwrap();
        let relay = fixture.relay.take().unwrap();
        relay.abort();
        let _result = relay.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_h2_relay_setup_failure_cancels_started_egress_without_inventing_opposite_fact() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(true, |ingress, egress| {
            compatible(ingress, egress);
            let mut limits = H2SettingsLimits::default();
            limits.header_table_size = 0;
            ingress.insert(limits);
        });
        initial_client(&mut fixture.client).await;
        preface(&mut fixture.origin).await;
        let downstream = fixture.downstream_credit();
        let upstream = fixture.upstream_credit();
        // Valid upstream SETTINGS exceeds the caller's ingress resource ceiling.
        frame(&mut fixture.origin, 4, 0, 0, &[0, 1, 0, 0, 0, 1]).await;
        fixture.relay.take().unwrap().await.unwrap().unwrap_err();
        eof(&mut fixture.origin).await;
        assert_eq!(downstream.snapshot(), Status::Unbound);
        assert!(matches!(
            upstream.complete().await,
            Err(Failure::ClosedBeforeInitialHeaders | Failure::NativeError)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_h2_relay_future_cancellation_closes_started_egress() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(true, compatible);
        initial_client(&mut fixture.client).await;
        preface(&mut fixture.origin).await;
        let downstream = fixture.downstream_credit();
        let upstream = fixture.upstream_credit();
        // Origin deliberately withholds SETTINGS; relay setup is still pending.
        fixture.cancel().await;
        assert_eq!(downstream.snapshot(), Status::Unbound);
        assert!(matches!(
            upstream.complete().await,
            Err(Failure::ClosedBeforeInitialHeaders | Failure::NativeError)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_h2_relay_post_first_ambiguous_credit_fails_the_opt_in_pair() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(true, compatible);
        fixture.handshake().await;
        let upstream = fixture.upstream_credit();
        request(&mut fixture.client, true).await;
        assert_eq!(until(&mut fixture.origin, 0, 1).await.1, b"x");
        frame(&mut fixture.origin, 8, 0, 0, &1_u32.to_be_bytes()).await;
        assert_eq!(
            upstream.complete().await,
            Err(Failure::DataCreditBeforeInitialHeaders)
        );
        fixture.relay.take().unwrap().await.unwrap().unwrap_err();
        eof(&mut fixture.client).await;
        eof(&mut fixture.origin).await;
    })
    .await
    .unwrap();
}

#[test]
fn native_h2_relay_directional_limits_require_explicit_valid_budgets() {
    for (ingress, egress) in [
        (0, 65_535),
        (65_535, 65_534),
        (u32::MAX, 65_535),
        (65_535, u32::MAX),
    ] {
        H2InitialCreditLimits::try_new(ingress, egress).unwrap_err();
    }
    // The two directions may intentionally have different resource policies.
    let _limits = H2InitialCreditLimits::try_new(65_540, 65_538).unwrap();
}

async fn reject_credit_until_eof(io: &mut DuplexStream) {
    loop {
        let mut head = [0; 9];
        if io.read(&mut head[..1]).await.unwrap() == 0 {
            return;
        }
        io.read_exact(&mut head[1..]).await.unwrap();
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut body = vec![0; length];
        io.read_exact(&mut body).await.unwrap();
        assert!(
            head[3] != 8 || head[5..9] != [0, 0, 0, 0],
            "relay must not advertise over-budget or clamped connection credit"
        );
        // Existing graceful upstream-close handling may request a shutdown RTT.
        // Act as a conforming raw peer instead of causing an artificial stall.
        if head[3] == 6 && head[4] == 0 {
            frame(io, 6, 1, 0, &body).await;
        }
    }
}

#[tokio::test]
async fn native_h2_relay_directional_limit_closes_before_advertising_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for refuse_ingress in [false, true] {
            let limits = H2InitialCreditLimits::try_new(
                if refuse_ingress { 65_536 } else { 65_540 },
                if refuse_ingress { 65_538 } else { 65_536 },
            )
            .unwrap();
            let mut fixture = Fixture::with_limits(Some(limits), compatible);
            fixture.handshake().await;
            let source = if refuse_ingress {
                fixture.upstream_credit()
            } else {
                fixture.downstream_credit()
            };
            let source_peer = if refuse_ingress {
                &mut fixture.origin
            } else {
                &mut fixture.client
            };
            frame(source_peer, 8, 0, 0, &2_u32.to_be_bytes()).await;
            tokio::join!(
                reject_credit_until_eof(&mut fixture.client),
                reject_credit_until_eof(&mut fixture.origin),
            );
            // The egress health path can report an ordinary graceful close to
            // HttpMitmRelay::serve; do not pretend it retains the native cause.
            let _result = fixture.relay.take().unwrap().await.unwrap();
            assert!(matches!(
                source.snapshot(),
                Status::Failed { target: 65_537, .. } | Status::Observing { target: 65_537 }
            ));
        }
    })
    .await
    .unwrap();
}
