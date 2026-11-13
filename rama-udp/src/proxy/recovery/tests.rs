use super::*;
use crate::{
    DatagramSenderExt as _, SendDatagram, proxy::EcnPolicy, test_utils::MemoryDatagramSocket,
};
use rama_core::{
    extensions::{Extension, ExtensionsRef as _},
    service::service_fn,
};
use rama_net::{
    address::SocketAddress,
    client::{ConnectRequest, EstablishedClientConnection},
    stream::Socket as _,
};
use std::{
    io::ErrorKind,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Mutex, mpsc};

const LIMIT: Duration = Duration::from_secs(10);

fn pair(port: u16) -> (MemoryDatagramSocket, MemoryDatagramSocket) {
    MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(port),
        SocketAddress::local_ipv4(9000),
        NonZeroUsize::new(8).unwrap(),
    )
}

fn settings(signal: DatagramRecoverySignal) -> DatagramRecovery {
    DatagramRecovery::new(
        signal,
        DatagramRecoveryConfig {
            preparation_timeout: Duration::from_secs(2),
            unavailable_timeout: Duration::from_secs(5),
            failure_action: DatagramRecoveryFailureAction::Keep,
        },
    )
}

async fn send(socket: &MemoryDatagramSocket, bytes: &[u8]) {
    socket
        .create_sender()
        .send(SendDatagram::new(socket.peer_addr().unwrap(), bytes))
        .await
        .unwrap();
}

async fn receive(socket: &mut MemoryDatagramSocket, bytes: &[u8]) {
    let mut buffer = [0; 128];
    let meta = timeout(LIMIT, socket.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..meta.len], bytes);
}

struct Harness {
    client: MemoryDatagramSocket,
    origin: MemoryDatagramSocket,
    replacements: mpsc::UnboundedSender<Result<MemoryDatagramSocket, BoxError>>,
    requests: mpsc::UnboundedReceiver<()>,
    task: tokio::task::JoinHandle<Result<(), BoxError>>,
    signal: DatagramRecoverySignal,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Harness {
    async fn new(recovery: DatagramRecovery) -> Self {
        let (client, ingress) = pair(7000);
        let (egress, origin) = pair(8000);
        let (tx, rx) = mpsc::unbounded_channel();
        let rx = Arc::new(Mutex::new(rx));
        let (requests, notices) = mpsc::unbounded_channel();
        let factory = service_fn(move |()| {
            let rx = rx.clone();
            let requests = requests.clone();
            async move {
                requests.send(()).unwrap();
                rx.lock().await.recv().await.unwrap()
            }
        });
        let signal = recovery.signal.clone();
        let task = tokio::spawn(async move {
            DatagramForwardService::new(NonZeroUsize::new(128).unwrap(), EcnPolicy::Discard)
                .forward_with_recovery(
                    BridgeIo(
                        Peer::connected(ingress).unwrap(),
                        Peer::connected(egress).unwrap(),
                    ),
                    &recovery,
                    factory,
                )
                .await
        });
        let mut result = Self {
            client,
            origin,
            replacements: tx,
            requests: notices,
            task,
            signal,
        };
        result.exchange(b"initial").await;
        result
    }

    async fn exchange(&mut self, payload: &[u8]) {
        send(&self.client, payload).await;
        receive(&mut self.origin, payload).await;
        send(&self.origin, payload).await;
        receive(&mut self.client, payload).await;
    }

    async fn request(&mut self) {
        self.signal.request_recovery();
        timeout(LIMIT, self.requests.recv()).await.unwrap().unwrap();
    }

    async fn replace(&mut self, port: u16) {
        self.request().await;
        let (socket, origin) = pair(port);
        self.replacements.send(Ok(socket)).unwrap();
        // Receipt on the new path acknowledges adoption without sleeps or polling metrics.
        send(&origin, b"adopted").await;
        receive(&mut self.client, b"adopted").await;
        self.origin = origin;
    }
}

#[tokio::test]
async fn retains_ingress_across_multiple_replacements_and_empty_datagrams() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    for port in 8100..8120 {
        h.replace(port).await;
        h.exchange(b"").await;
        h.exchange(b"same application flow").await;
    }
}

#[tokio::test]
async fn preparation_does_not_pause_the_working_transport() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    h.request().await;
    h.exchange(b"old path during preparation").await;
    h.replacements
        .send(Err(BoxError::from_static_str("connector failed")))
        .unwrap();
    h.exchange(b"old path after failure").await;
    h.replace(8100).await;
}

#[tokio::test]
async fn a_new_signal_cancels_pending_preparation() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    h.request().await;
    h.request().await;
    let (socket, origin) = pair(8100);
    h.replacements.send(Ok(socket)).unwrap();
    send(&origin, b"latest").await;
    receive(&mut h.client, b"latest").await;
    h.origin = origin;
    h.exchange(b"still connected").await;
}

#[tokio::test]
async fn rejects_a_replacement_with_a_different_remote_peer() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    h.request().await;
    let (wrong, _remote) = MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(8100),
        SocketAddress::local_ipv4(9999),
        NonZeroUsize::new(8).unwrap(),
    );
    h.replacements.send(Ok(wrong)).unwrap();
    h.exchange(b"authorized old path").await;
    h.replace(8200).await;
}

#[tokio::test]
async fn recovers_after_egress_closes_without_closing_ingress() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    let (_, dummy) = pair(8999);
    drop(std::mem::replace(&mut h.origin, dummy));
    tokio::task::yield_now().await;
    h.replace(8100).await;
    h.exchange(b"recovered").await;
}

#[tokio::test(start_paused = true)]
async fn dead_egress_wait_is_bounded_without_retries() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    let (_, dummy) = pair(8999);
    drop(std::mem::replace(&mut h.origin, dummy));
    let error = (&mut h.task).await.unwrap().unwrap_err();
    assert!(error.to_string().contains("deadline"));
    assert!(h.requests.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn preparation_timeout_can_close_the_association() {
    let mut config = settings(DatagramRecoverySignal::new());
    config.config.failure_action = DatagramRecoveryFailureAction::Close;
    let mut h = Harness::new(config).await;
    h.request().await;
    let error = (&mut h.task).await.unwrap().unwrap_err();
    assert!(error.to_string().contains("timed out"));
}

#[tokio::test]
async fn cancellation_releases_the_shared_preparation_permit() {
    let gate = Arc::new(Semaphore::new(1));
    let mut h =
        Harness::new(settings(DatagramRecoverySignal::new()).with_preparation_gate(gate.clone()))
            .await;
    h.request().await;
    assert_eq!(gate.available_permits(), 0);
    h.task.abort();
    assert!((&mut h.task).await.unwrap_err().is_cancelled());
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_flows_recover_together_through_a_shared_gate() {
    timeout(LIMIT, async {
        let signal = DatagramRecoverySignal::new();
        let recovery = settings(signal.clone()).with_preparation_gate(Arc::new(Semaphore::new(4)));
        let mut flows = Vec::new();
        for _ in 0..64 {
            flows.push(Harness::new(recovery.clone()).await);
        }
        for _ in 0..4 {
            // Queue one owned replacement for each flow before broadcasting the routing change.
            let mut origins = Vec::new();
            for h in &flows {
                let (socket, origin) = pair(8100);
                h.replacements.send(Ok(socket)).unwrap();
                send(&origin, b"new path").await;
                origins.push(origin);
            }
            signal.request_recovery();
            for (h, origin) in flows.iter_mut().zip(origins) {
                receive(&mut h.client, b"new path").await;
                h.origin = origin;
                h.exchange(b"independent").await;
            }
        }
    })
    .await
    .unwrap();
}

#[derive(Debug, Clone, Extension)]
struct RouteMarker;

#[tokio::test]
async fn bridge_reuses_the_original_connector_target_and_extensions() {
    let signal = DatagramRecoverySignal::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let (sockets, mut origins) = mpsc::unbounded_channel();
    let connector = service_fn(move |request: ConnectRequest| {
        assert_eq!(
            request.authority,
            rama_net::address::HostWithPort::local_ipv4(9000)
        );
        assert!(request.extensions.contains::<RouteMarker>());
        seen.fetch_add(1, Ordering::Relaxed);
        let (conn, origin) = pair(8000);
        sockets.send(origin).unwrap();
        async move {
            Ok::<_, BoxError>(EstablishedClientConnection {
                conn,
                input: request,
            })
        }
    });
    let bridge = super::super::DatagramToProxyBridge::new(
        DatagramForwardService::new(NonZeroUsize::new(128).unwrap(), EcnPolicy::Discard),
        SocketAddress::local_ipv4(9000),
    )
    .with_connector(connector)
    .with_egress_recovery(settings(signal.clone()));
    let (mut client, ingress) = pair(7000);
    ingress.extensions().insert(RouteMarker);
    let task = tokio::spawn(async move { bridge.serve(ingress).await });
    let mut origin = origins.recv().await.unwrap();
    send(&client, b"first").await;
    receive(&mut origin, b"first").await;
    for _ in 0..4 {
        signal.request_recovery();
        let mut replacement = timeout(LIMIT, origins.recv()).await.unwrap().unwrap();
        send(&replacement, b"ready").await;
        receive(&mut client, b"ready").await;
        send(&client, b"same request").await;
        receive(&mut replacement, b"same request").await;
    }
    assert_eq!(calls.load(Ordering::Relaxed), 5);
    task.abort();
    let _cancelled = task.await;
}

#[test]
fn packet_wakes_do_not_repoll_the_shared_control_future() {
    let polls = AtomicUsize::new(0);
    let notified = parking_lot::Mutex::new(None::<Waker>);
    let inner = std::future::poll_fn(|cx| {
        polls.fetch_add(1, Ordering::Relaxed);
        *notified.lock() = Some(cx.waker().clone());
        Poll::<()>::Pending
    });
    let mut gated = std::pin::pin!(wake_gated(inner));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..10_000 {
        assert!(gated.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(polls.load(Ordering::Relaxed), 1);
    notified.lock().take().unwrap().wake();
    assert!(gated.as_mut().poll(&mut cx).is_pending());
    assert_eq!(polls.load(Ordering::Relaxed), 2);
}

#[test]
fn only_local_path_failures_are_recoverable() {
    for kind in [
        ErrorKind::NetworkDown,
        ErrorKind::NetworkUnreachable,
        ErrorKind::HostUnreachable,
        ErrorKind::AddrNotAvailable,
    ] {
        assert!(CopyError::Send(DatagramError::Io(kind.into())).is_recoverable_path_failure());
        assert!(CopyError::Receive(DatagramError::Io(kind.into())).is_recoverable_path_failure());
    }
    for kind in [
        ErrorKind::ConnectionRefused,
        ErrorKind::PermissionDenied,
        ErrorKind::InvalidInput,
        ErrorKind::Other,
    ] {
        assert!(!CopyError::Send(DatagramError::Io(kind.into())).is_recoverable_path_failure());
    }
    assert!(
        !CopyError::Policy(DatagramForwardError::InvalidMetadata).is_recoverable_path_failure()
    );
    assert!(
        !CopyError::Send(DatagramError::PayloadTooLarge { len: 100, max: 10 })
            .is_recoverable_path_failure()
    );
}

#[tokio::test]
async fn identical_routing_snapshots_do_not_reconnect() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    let state = DatagramRecoveryState {
        revision: 42,
        available: true,
    };
    h.signal.update(state);
    h.requests.recv().await.unwrap();
    let (socket, origin) = pair(8100);
    h.replacements.send(Ok(socket)).unwrap();
    send(&origin, b"ready").await;
    receive(&mut h.client, b"ready").await;
    h.origin = origin;
    for _ in 0..100 {
        h.signal.update(state);
    }
    h.exchange(b"unchanged").await;
    assert!(h.requests.try_recv().is_err());
}

#[tokio::test]
async fn unavailable_observation_cancels_preparation_without_replacing_working_path() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    h.request().await;
    h.signal.suspend_recovery();
    h.exchange(b"still working").await;
    assert!(h.requests.try_recv().is_err());
    h.replace(8100).await;
}

#[tokio::test(start_paused = true)]
async fn gate_wait_does_not_consume_preparation_timeout() {
    let gate = Arc::new(Semaphore::new(0));
    let mut h =
        Harness::new(settings(DatagramRecoverySignal::new()).with_preparation_gate(gate.clone()))
            .await;
    h.signal.request_recovery();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(30)).await;
    h.exchange(b"old path while queued").await;
    assert!(h.requests.try_recv().is_err());
    gate.add_permits(1);
    h.requests.recv().await.unwrap();
    let (socket, origin) = pair(8100);
    h.replacements.send(Ok(socket)).unwrap();
    send(&origin, b"prepared after gate").await;
    receive(&mut h.client, b"prepared after gate").await;
}

#[tokio::test]
async fn ingress_close_ends_recovery_during_an_egress_outage() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    let (_, dummy) = pair(8999);
    drop(std::mem::replace(&mut h.origin, dummy));
    h.request().await;
    let (dummy, _) = pair(6999);
    drop(std::mem::replace(&mut h.client, dummy));
    timeout(LIMIT, &mut h.task).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn egress_failure_during_preparation_uses_that_preparation() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    h.request().await;
    let (_, dummy) = pair(8999);
    drop(std::mem::replace(&mut h.origin, dummy));
    let (socket, origin) = pair(8100);
    h.replacements.send(Ok(socket)).unwrap();
    send(&origin, b"recovery already underway").await;
    receive(&mut h.client, b"recovery already underway").await;
    assert!(h.requests.try_recv().is_err());
}

#[derive(Debug)]
struct WithoutTruncation(MemoryDatagramSocket, bool);

impl rama_net::stream::Socket for WithoutTruncation {
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        self.0.local_addr()
    }
    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        self.0.peer_addr()
    }
}

impl DatagramSocket for WithoutTruncation {
    type Sender = <MemoryDatagramSocket as DatagramSocket>::Sender;
    fn create_sender(&self) -> Self::Sender {
        self.0.create_sender()
    }
    fn capabilities(&self) -> crate::DatagramCapabilities {
        let mut caps = self.0.capabilities();
        caps.receive_truncation = self.1;
        caps
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [std::io::IoSliceMut<'_>],
        metadata: &mut [crate::DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        self.0.poll_recv(cx, buffers, metadata)
    }
}

#[tokio::test]
async fn capability_downgrade_is_rejected_before_canceling_the_old_path() {
    for action in [
        DatagramRecoveryFailureAction::Keep,
        DatagramRecoveryFailureAction::Close,
    ] {
        let signal = DatagramRecoverySignal::new();
        let mut recovery = settings(signal.clone());
        recovery.config.failure_action = action;
        let (client, ingress) = pair(7000);
        let (egress, mut origin) = pair(8000);
        let (replacement, mut refused_origin) = pair(8100);
        let replacement = Arc::new(parking_lot::Mutex::new(Some(replacement)));
        let factory = service_fn(move |()| {
            let socket = replacement.lock().take().unwrap();
            async move { Ok::<_, BoxError>(WithoutTruncation(socket, false)) }
        });
        let mut task = tokio::spawn(async move {
            DatagramForwardService::new(NonZeroUsize::new(128).unwrap(), EcnPolicy::Discard)
                .forward_with_recovery(
                    BridgeIo(
                        Peer::connected(ingress).unwrap(),
                        Peer::connected(WithoutTruncation(egress, true)).unwrap(),
                    ),
                    &recovery,
                    factory,
                )
                .await
        });
        send(&client, b"first").await;
        receive(&mut origin, b"first").await;
        signal.request_recovery();
        let mut buffer = [0; 128];
        assert!(matches!(
            timeout(LIMIT, refused_origin.recv(&mut buffer))
                .await
                .unwrap(),
            Err(DatagramError::Closed)
        ));
        if action == DatagramRecoveryFailureAction::Keep {
            send(&client, b"old path preserved").await;
            receive(&mut origin, b"old path preserved").await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert!(timeout(LIMIT, &mut task).await.unwrap().unwrap().is_err());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn repeated_network_changes_do_not_extend_the_outage_deadline() {
    let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
    let (_, dummy) = pair(8999);
    drop(std::mem::replace(&mut h.origin, dummy));
    h.request().await;
    for _ in 0..4 {
        tokio::time::advance(Duration::from_secs(1)).await;
        h.request().await;
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(
        (&mut h.task)
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("deadline")
    );
}

#[tokio::test]
async fn blocked_old_send_is_cancelled_without_replaying_or_duplicating_packets() {
    timeout(LIMIT, async {
        let mut h = Harness::new(settings(DatagramRecoverySignal::new())).await;
        let sent = Arc::new(AtomicUsize::new(0));
        let progress = sent.clone();
        let mut sender = h.client.create_sender();
        let destination = h.client.peer_addr().unwrap();
        let producer = tokio::spawn(async move {
            for index in 0u8..64 {
                sender
                    .send(SendDatagram::new(destination, &[index]))
                    .await
                    .unwrap();
                progress.fetch_add(1, Ordering::Release);
            }
        });
        // Eight packets fill the old origin queue, one is blocked in send, and eight
        // fill ingress. There is no room for the producer to make further progress.
        while sent.load(Ordering::Acquire) < 17 {
            tokio::task::yield_now().await;
        }
        h.replace(8100).await;
        let mut received = Vec::new();
        loop {
            let mut bytes = [0; 128];
            let meta = h.origin.recv(&mut bytes).await.unwrap();
            assert_eq!(meta.len, 1);
            received.push(bytes[0]);
            if bytes[0] == 63 {
                break;
            }
        }
        producer.await.unwrap();
        assert_eq!(received, (9u8..64).collect::<Vec<_>>());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn superseding_a_factory_drops_its_prepared_transport_and_releases_permits() {
    let signal = DatagramRecoverySignal::new();
    let gate = Arc::new(Semaphore::new(1));
    let recovery = settings(signal.clone()).with_preparation_gate(gate.clone());
    let (client, ingress) = pair(7000);
    let (egress, mut origin) = pair(8000);
    let (prepared, mut observed) = mpsc::unbounded_channel();
    let factory = service_fn(move |()| {
        let (socket, origin) = pair(8100);
        prepared.send(origin).unwrap();
        async move {
            std::future::pending::<()>().await;
            Ok::<_, BoxError>(socket)
        }
    });
    let task = tokio::spawn(async move {
        DatagramForwardService::new(NonZeroUsize::new(128).unwrap(), EcnPolicy::Discard)
            .forward_with_recovery(
                BridgeIo(
                    Peer::connected(ingress).unwrap(),
                    Peer::connected(egress).unwrap(),
                ),
                &recovery,
                factory,
            )
            .await
    });
    send(&client, b"ready").await;
    receive(&mut origin, b"ready").await;
    signal.request_recovery();
    let mut first = timeout(LIMIT, observed.recv()).await.unwrap().unwrap();
    signal.request_recovery();
    let mut second = timeout(LIMIT, observed.recv()).await.unwrap().unwrap();
    let mut bytes = [0; 128];
    assert!(matches!(
        timeout(LIMIT, first.recv(&mut bytes)).await.unwrap(),
        Err(DatagramError::Closed)
    ));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(matches!(
        second.recv(&mut bytes).await,
        Err(DatagramError::Closed)
    ));
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test]
async fn bridge_retains_a_network_change_during_initial_connection_preparation() {
    let signal = DatagramRecoverySignal::new();
    let (started, mut starts) = mpsc::unbounded_channel();
    let (created, mut origins) = mpsc::unbounded_channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let allow = release.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let connector = service_fn(move |request: ConnectRequest| {
        let first = calls.fetch_add(1, Ordering::Relaxed) == 0;
        let release = allow.clone();
        let created = created.clone();
        let started = started.clone();
        async move {
            if first {
                started.send(()).unwrap();
                release.notified().await;
            }
            let (conn, origin) = pair(8000);
            created.send(origin).unwrap();
            Ok::<_, BoxError>(EstablishedClientConnection {
                conn,
                input: request,
            })
        }
    });
    let bridge = super::super::DatagramToProxyBridge::new(
        DatagramForwardService::new(NonZeroUsize::new(128).unwrap(), EcnPolicy::Discard),
        SocketAddress::local_ipv4(9000),
    )
    .with_connector(connector)
    .with_egress_recovery(settings(signal.clone()));
    let (mut client, ingress) = pair(7000);
    let task = tokio::spawn(async move { bridge.serve(ingress).await });
    timeout(LIMIT, starts.recv()).await.unwrap().unwrap();
    signal.request_recovery();
    release.notify_one();
    let mut initial = timeout(LIMIT, origins.recv()).await.unwrap().unwrap();
    let replacement = timeout(LIMIT, origins.recv()).await.unwrap().unwrap();
    send(&replacement, b"new route").await;
    receive(&mut client, b"new route").await;
    let mut buffer = [0; 128];
    assert!(matches!(
        initial.recv(&mut buffer).await,
        Err(DatagramError::Closed)
    ));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}
