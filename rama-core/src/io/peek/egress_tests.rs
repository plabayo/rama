use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf, duplex,
};

use super::*;
use crate::{
    ServiceInput,
    extensions::ExtensionsRef,
    graceful::{Cause, Scope, attach_scope},
    io::BridgeIo,
    service::service_fn,
};

const HOUR: Duration = Duration::from_hours(1);

type Ingress = ServiceInput<DuplexStream>;
type Peeked = BridgeIo<PeekPrefixedIo<Ingress>, PeekPrefixedIo<DuplexStream>>;

/// Client and server ends of a bridge whose ingress and egress are peeked.
struct Ends {
    client: DuplexStream,
    server: DuplexStream,
}

fn bridge() -> (BridgeIo<Ingress, DuplexStream>, Ends) {
    let (client, ingress) = duplex(1024);
    let (server, egress) = duplex(1024);
    (
        BridgeIo(ServiceInput::new(ingress), egress),
        Ends { client, server },
    )
}

fn magic(buffer: &[u8]) -> PeekVerdict<()> {
    prefix_peek_verdict(buffer, b"MAGIC")
}

/// Reads what the service sees once both peers closed: (side, ingress, egress).
async fn drain(
    side: &'static str,
    BridgeIo(mut ingress, mut egress): Peeked,
) -> Result<(&'static str, Vec<u8>, Vec<u8>), io::Error> {
    let mut i = Vec::new();
    let mut e = Vec::new();
    ingress.read_to_end(&mut i).await?;
    egress.read_to_end(&mut e).await?;
    Ok((side, i, e))
}

async fn accepted(io: Peeked) -> Result<(&'static str, Vec<u8>, Vec<u8>), io::Error> {
    drain("accepted", io).await
}

async fn fallback(io: Peeked) -> Result<(&'static str, Vec<u8>, Vec<u8>), io::Error> {
    drain("fallback", io).await
}

fn router<E: PeekEgressPredicate + Clone + 'static>(
    egress: E,
) -> impl Service<
    BridgeIo<Ingress, DuplexStream>,
    Output = (&'static str, Vec<u8>, Vec<u8>),
    Error = BoxError,
> {
    PeekRouter::new(magic, service_fn(accepted))
        .with_max_peek_size(NonZeroUsize::new(5).unwrap())
        .with_egress_predicate(egress)
        .with_fallback(service_fn(fallback))
}

/// Routes with services that only read the egress, so the client side stays
/// open and silent: any fallback must come from the egress verdict.
fn egress_only_router<E: PeekEgressPredicate + Clone + 'static>(
    egress: E,
    egress_len: usize,
) -> impl Service<BridgeIo<Ingress, DuplexStream>, Output = (&'static str, Vec<u8>), Error = BoxError>
{
    let read_egress = move |side: &'static str| {
        service_fn(move |BridgeIo(_ingress, mut egress): Peeked| async move {
            let mut bytes = vec![0; egress_len];
            egress.read_exact(&mut bytes).await?;
            Ok::<_, io::Error>((side, bytes))
        })
    };
    PeekRouter::new(magic, read_egress("accepted"))
        .with_egress_predicate(egress)
        .with_fallback(read_egress("fallback"))
}

#[tokio::test(start_paused = true)]
async fn server_first_mismatch_falls_back_at_once_and_replays_the_greeting() {
    const GREETING: &[u8] = b"220 smtp ready\r\n";
    let (input, mut ends) = bridge();
    ends.server.write_all(GREETING).await.unwrap();
    let start = tokio::time::Instant::now();
    let (side, egress) = tokio::time::timeout(
        HOUR,
        egress_only_router(PeekEgressPrefix::new(b"OK"), GREETING.len()).serve(input),
    )
    .await
    .expect("a mismatching greeting falls back while the client stays silent")
    .unwrap();
    assert_eq!("fallback", side);
    assert_eq!(GREETING, egress.as_slice());
    assert_eq!(start, tokio::time::Instant::now());
    drop(ends);
}

#[tokio::test(start_paused = true)]
async fn egress_eof_falls_back_and_replays_what_it_sent() {
    for sent in [&b""[..], b"O"] {
        let (input, mut ends) = bridge();
        ends.server.write_all(sent).await.unwrap();
        drop(ends.server);
        let (side, egress) = tokio::time::timeout(
            HOUR,
            egress_only_router(PeekEgressPrefix::new(b"OK"), sent.len()).serve(input),
        )
        .await
        .expect("egress EOF falls back while the client stays silent")
        .unwrap();
        assert_eq!("fallback", side);
        assert_eq!(sent, egress.as_slice());
        drop(ends.client);
    }
}

/// Egress that fails its first read.
struct FailingEgress;

impl AsyncRead for FailingEgress {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    }
}

impl AsyncWrite for FailingEgress {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn egress_read_error_counts_as_closed() {
    let side = |side: &'static str| {
        service_fn(
            move |_: BridgeIo<PeekPrefixedIo<Ingress>, PeekPrefixedIo<FailingEgress>>| async move {
                Ok::<_, io::Error>(side)
            },
        )
    };
    for (policy, expected) in [
        (PeekPolicy::FAIL_OPEN, Some("fallback")),
        (
            PeekPolicy::FAIL_OPEN.with_egress_closed_idle(PeekAction::Fail),
            None,
        ),
    ] {
        let (_client, ingress) = duplex(64);
        let input = BridgeIo(ServiceInput::new(ingress), FailingEgress);
        let result = PeekRouter::new(magic, side("accepted"))
            .with_egress_predicate(PeekEgressPrefix::new(b"OK"))
            .with_peek_policy(policy)
            .with_fallback(side("fallback"))
            .serve(input)
            .await;
        match expected {
            Some(expected) => assert_eq!(expected, result.unwrap()),
            None => assert_eq!(
                Some(PeekCutoff::EgressClosed),
                result
                    .unwrap_err()
                    .downcast_ref::<PeekCutoffError>()
                    .map(PeekCutoffError::cutoff)
            ),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn settled_egress_is_not_read_again_until_the_client_decides() {
    // a matching opening followed by FIN keeps waiting: once settled the egress
    // is not read, so its EOF reaches the service that follows the verdict
    let (input, mut ends) = bridge();
    ends.server.write_all(b"OK").await.unwrap();
    drop(ends.server);
    let mut serve =
        Box::pin(async move { router(PeekEgressPrefix::new(b"OK")).serve(input).await });
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"MAGIC").await.unwrap();
    drop(ends.client);
    let (side, _, egress) = serve.await.unwrap();
    assert_eq!("accepted", side);
    assert_eq!(b"OK".as_slice(), egress);
}

#[tokio::test(start_paused = true)]
async fn matching_egress_keeps_waiting_for_the_client_and_replays_both_sides() {
    let (input, mut ends) = bridge();
    ends.server.write_all(b"OK").await.unwrap();
    let mut serve =
        Box::pin(async move { router(PeekEgressPrefix::new(b"OK")).serve(input).await });

    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"MAGIC!").await.unwrap();
    ends.server.write_all(b" more").await.unwrap();
    drop(ends);
    let (side, ingress, egress) = serve.await.unwrap();
    assert_eq!("accepted", side);
    assert_eq!(b"MAGIC!".as_slice(), ingress);
    assert_eq!(b"OK more".as_slice(), egress);
}

#[tokio::test(start_paused = true)]
async fn consistent_byte_then_stall_keeps_waiting() {
    let (input, mut ends) = bridge();
    ends.server.write_all(b"O").await.unwrap();
    let mut serve =
        Box::pin(async move { router(PeekEgressPrefix::new(b"OK")).serve(input).await });
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"MAGIC").await.unwrap();
    drop(ends);
    let (side, _, egress) = serve.await.unwrap();
    assert_eq!("accepted", side);
    assert_eq!(b"O".as_slice(), egress);
}

fn undecided(_: &[u8]) -> PeekVerdict<()> {
    PeekVerdict::NeedMore
}

#[tokio::test(start_paused = true)]
async fn egress_undecided_at_its_limit_stops_reading_and_lets_the_client_decide() {
    let (input, mut ends) = bridge();
    ends.server.write_all(b"0123456789").await.unwrap();
    let router = PeekRouter::new(magic, service_fn(accepted))
        .with_egress_predicate(undecided)
        .with_max_egress_peek_size(NonZeroUsize::new(4).unwrap())
        .with_fallback(service_fn(fallback));
    let mut serve = Box::pin(async move { router.serve(input).await });

    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"MAGIC").await.unwrap();
    drop(ends);
    let (side, _, egress) = serve.await.unwrap();
    assert_eq!("accepted", side);
    assert_eq!(b"0123456789".as_slice(), egress);
}

#[tokio::test(start_paused = true)]
async fn egress_one_byte_below_its_limit_keeps_reading() {
    let (input, mut ends) = bridge();
    ends.server.write_all(b"012").await.unwrap();
    let read_egress = |side: &'static str| {
        service_fn(move |BridgeIo(_ingress, mut egress): Peeked| async move {
            let mut bytes = [0; 4];
            egress.read_exact(&mut bytes).await?;
            Ok::<_, io::Error>((side, bytes))
        })
    };
    let router = PeekRouter::new(magic, read_egress("accepted"))
        .with_egress_predicate(|b: &[u8]| {
            if b.len() > 3 {
                PeekVerdict::Reject
            } else {
                PeekVerdict::NeedMore
            }
        })
        .with_max_egress_peek_size(NonZeroUsize::new(4).unwrap())
        .with_fallback(read_egress("fallback"));
    let mut serve = Box::pin(async move { router.serve(input).await });
    // the client stays open: only the fourth egress byte can end the peek
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.server.write_all(b"3").await.unwrap();
    let (side, egress) = tokio::time::timeout(HOUR, serve).await.unwrap().unwrap();
    assert_eq!("fallback", side);
    assert_eq!(*b"0123", egress);
    drop(ends);
}

#[tokio::test(start_paused = true)]
async fn ingress_limit_is_not_lifted_by_a_matching_egress() {
    let (input, mut ends) = bridge();
    ends.server.write_all(b"OK").await.unwrap();
    let router = PeekRouter::new(undecided, service_fn(accepted))
        .with_max_peek_size(NonZeroUsize::new(5).unwrap())
        .with_egress_predicate(PeekEgressPrefix::new(b"OK"))
        .with_fallback(service_fn(fallback));
    let mut serve = Box::pin(async move { router.serve(input).await });
    // the egress matches first, then the client fills the ingress limit undecided
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"MAGI?").await.unwrap();
    drop(ends);
    let (side, ingress, _) = serve.await.unwrap();
    assert_eq!("fallback", side);
    assert_eq!(b"MAGI?".as_slice(), ingress);
}

#[tokio::test(start_paused = true)]
async fn mismatch_after_partial_client_input_waits_by_default() {
    let (input, mut ends) = bridge();
    ends.client.write_all(b"MA").await.unwrap();
    let mut serve =
        Box::pin(async move { router(PeekEgressPrefix::new(b"OK")).serve(input).await });
    tokio::time::timeout(Duration::from_secs(1), &mut serve)
        .await
        .unwrap_err();
    ends.server.write_all(b"NO").await.unwrap();
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"GIC").await.unwrap();
    drop(ends);
    let (side, ingress, egress) = serve.await.unwrap();
    assert_eq!("accepted", side);
    assert_eq!(b"MAGIC".as_slice(), ingress);
    assert_eq!(b"NO".as_slice(), egress);
}

#[tokio::test(start_paused = true)]
async fn complete_client_input_wins_over_a_mismatch_in_the_same_poll() {
    let (input, mut ends) = bridge();
    ends.client.write_all(b"MAGIC").await.unwrap();
    ends.server.write_all(b"NO").await.unwrap();
    drop(ends);
    let (side, _, egress) = router(PeekEgressPrefix::new(b"OK"))
        .serve(input)
        .await
        .unwrap();
    assert_eq!("accepted", side);
    assert_eq!(b"NO".as_slice(), egress);
}

#[tokio::test(start_paused = true)]
async fn no_egress_predicate_never_reads_the_egress() {
    let (input, mut ends) = bridge();
    ends.server.write_all(b"220 hi").await.unwrap();
    let mut serve = Box::pin(async move { router(NoEgressPeek).serve(input).await });
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"MAGIC").await.unwrap();
    drop(ends);
    let (side, _, egress) = serve.await.unwrap();
    assert_eq!("accepted", side);
    assert_eq!(b"220 hi".as_slice(), egress);
}

#[tokio::test(start_paused = true)]
async fn closure_ingress_predicate_on_a_bridge_does_not_read_the_egress() {
    let (input, mut ends) = bridge();
    ends.server.write_all(b"X").await.unwrap();
    let router = PeekRouter::new(magic, service_fn(accepted)).with_fallback(service_fn(fallback));
    let mut serve = Box::pin(async move { router.serve(input).await });
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    drop(ends);
    let (side, _, egress) = serve.await.unwrap();
    assert_eq!("fallback", side);
    assert_eq!(b"X".as_slice(), egress);
}

#[tokio::test(start_paused = true)]
async fn cancelled_peek_scope_applies_the_policy() {
    for (policy, expect_fallback) in [
        (PeekPolicy::FAIL_OPEN, true),
        (PeekPolicy::FAIL_CLOSED, false),
    ] {
        let (input, ends) = bridge();
        attach_scope(
            input.0.extensions(),
            &Scope::new().with_timeout(Duration::from_secs(30)),
        );
        let router = PeekRouter::new(
            magic,
            service_fn(async |_: Peeked| Ok::<_, io::Error>("accepted")),
        )
        .with_egress_predicate(PeekEgressPrefix::new(b"OK"))
        .with_peek_policy(policy)
        .with_fallback(service_fn(async |_: Peeked| Ok::<_, io::Error>("fallback")));
        let mut serve = Box::pin(async move { router.serve(input).await });
        tokio::time::timeout(Duration::from_secs(29), &mut serve)
            .await
            .unwrap_err();
        let result = tokio::time::timeout(Duration::from_secs(2), serve)
            .await
            .unwrap();
        drop(ends);
        if expect_fallback {
            assert_eq!("fallback", result.unwrap());
        } else {
            let err = result.unwrap_err();
            let err = err.downcast_ref::<PeekCutoffError>().unwrap();
            assert_eq!(PeekCutoff::Cancelled, err.cutoff());
            assert!(matches!(err.cause(), Some(Cause::Deadline)));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn aborted_peek_scope_fails_with_its_cause() {
    let (input, _ends) = bridge();
    let scope = Scope::new();
    attach_scope(input.0.extensions(), &scope);
    let serve = Box::pin(async move { router(PeekEgressPrefix::new(b"OK")).serve(input).await });
    tokio::task::yield_now().await;
    scope.abort(Cause::Reason("shutdown"));
    let err = serve.await.unwrap_err();
    let err = err.downcast_ref::<PeekCutoffError>().unwrap();
    assert_eq!(PeekCutoff::Aborted, err.cutoff());
    assert!(matches!(err.cause(), Some(Cause::Reason("shutdown"))));
}

#[tokio::test(start_paused = true)]
async fn chained_peekers_share_one_scope_and_replay_the_same_egress() {
    let (input, mut ends) = bridge();
    attach_scope(
        input.0.extensions(),
        &Scope::new().with_timeout(Duration::from_secs(30)),
    );
    const GREETING: &[u8] = b"220 smtp\r\n";
    ends.server.write_all(GREETING).await.unwrap();

    let inner = PeekRouter::new(
        |b: &[u8]| prefix_peek_verdict(b, b"PING"),
        service_fn(
            async |_: BridgeIo<PeekPrefixedIo<PeekPrefixedIo<Ingress>>, _>| {
                Ok::<_, io::Error>(("accepted", Vec::new()))
            },
        ),
    )
    .with_egress_predicate(PeekEgressPrefix::new(b"PONG"))
    .with_fallback(service_fn(
        async |BridgeIo(_ingress, mut e): BridgeIo<
            PeekPrefixedIo<PeekPrefixedIo<Ingress>>,
            PeekPrefixedIo<PeekPrefixedIo<DuplexStream>>,
        >| {
            let mut egress = vec![0; GREETING.len()];
            e.read_exact(&mut egress).await?;
            Ok::<_, io::Error>(("fallback", egress))
        },
    ));
    let outer = PeekRouter::new(
        magic,
        service_fn(async |_: Peeked| Ok::<_, io::Error>(("accepted", Vec::new()))),
    )
    .with_egress_predicate(PeekEgressPrefix::new(b"OK"))
    .with_fallback(inner);

    // the client stays open and silent: both peekers fall back on the egress verdict
    let (side, egress) = tokio::time::timeout(HOUR, outer.serve(input))
        .await
        .expect("the greeting falls through both peekers at once")
        .unwrap();
    assert_eq!("fallback", side);
    assert_eq!(GREETING, egress.as_slice());
    drop(ends);
}

#[tokio::test(start_paused = true)]
async fn abort_wins_over_a_pending_egress_cutoff() {
    let (input, mut ends) = bridge();
    let scope = Scope::new();
    attach_scope(input.0.extensions(), &scope);
    let router = PeekRouter::new(magic, service_fn(accepted))
        .with_egress_predicate(PeekEgressPrefix::new(b"OK"))
        .with_peek_policy(
            PeekPolicy::FAIL_OPEN
                .with_egress_mismatch_idle(PeekAction::Wait)
                .with_egress_mismatch_partial(PeekAction::Fallback),
        )
        .with_fallback(service_fn(fallback));
    let mut serve = Box::pin(async move { router.serve(input).await });

    ends.server.write_all(b"NO").await.unwrap();
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"MA").await.unwrap();
    scope.abort(Cause::Reason("shutdown"));
    let err = serve.await.unwrap_err();
    let err = err.downcast_ref::<PeekCutoffError>().unwrap();
    assert_eq!(PeekCutoff::Aborted, err.cutoff());
}

#[tokio::test(start_paused = true)]
async fn waived_mismatch_is_evaluated_again_once_the_client_starts() {
    let (input, mut ends) = bridge();
    let router = PeekRouter::new(
        magic,
        service_fn(async |_: Peeked| Ok::<_, io::Error>("accepted")),
    )
    .with_egress_predicate(PeekEgressPrefix::new(b"OK"))
    .with_peek_policy(
        PeekPolicy::FAIL_OPEN
            .with_egress_mismatch_idle(PeekAction::Wait)
            .with_egress_mismatch_partial(PeekAction::Fallback),
    )
    .with_fallback(service_fn(async |_: Peeked| Ok::<_, io::Error>("fallback")));
    let mut serve = Box::pin(async move { router.serve(input).await });

    ends.server.write_all(b"NO").await.unwrap();
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.client.write_all(b"MA").await.unwrap();
    let side = tokio::time::timeout(HOUR, serve).await.unwrap().unwrap();
    assert_eq!("fallback", side);
}

#[tokio::test(start_paused = true)]
async fn cancel_waived_at_partial_keeps_waiting_with_a_waived_mismatch_until_abort() {
    let (input, mut ends) = bridge();
    let scope = Scope::new();
    attach_scope(input.0.extensions(), &scope);
    let router = PeekRouter::new(magic, service_fn(accepted))
        .with_egress_predicate(PeekEgressPrefix::new(b"OK"))
        .with_peek_policy(PeekPolicy::FAIL_OPEN.with_cancelled_partial(PeekAction::Wait))
        .with_fallback(service_fn(fallback));
    let mut serve = Box::pin(async move { router.serve(input).await });

    ends.client.write_all(b"MA").await.unwrap();
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();
    ends.server.write_all(b"NO").await.unwrap();
    scope.cancel(Cause::Owner);
    tokio::time::timeout(HOUR, &mut serve).await.unwrap_err();

    scope.abort(Cause::Reason("shutdown"));
    let err = serve.await.unwrap_err();
    let err = err.downcast_ref::<PeekCutoffError>().unwrap();
    assert_eq!(PeekCutoff::Aborted, err.cutoff());
}

#[tokio::test(start_paused = true)]
async fn relay_after_the_verdict_is_not_cut_off_by_the_peek() {
    // the peek observes the scope the flow runs in; it never cancels it
    let (input, mut ends) = bridge();
    let scope = Scope::new();
    attach_scope(input.0.extensions(), &scope);
    ends.client.write_all(b"MAGIC").await.unwrap();
    let router = PeekRouter::new(
        magic,
        service_fn(async |_: Peeked| {
            tokio::time::sleep(HOUR).await;
            Ok::<_, io::Error>("relayed")
        }),
    )
    .with_fallback(service_fn(async |_: Peeked| Ok::<_, io::Error>("fallback")));
    assert_eq!("relayed", router.serve(input).await.unwrap());
    assert!(!scope.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn egress_writes_flush_and_shutdown_pass_through_while_a_prefix_is_pending() {
    let (input, mut ends) = bridge();
    ends.server.write_all(b"OK").await.unwrap();
    let router = PeekRouter::new(
        magic,
        service_fn(async |BridgeIo(_i, mut e): Peeked| {
            e.write_all(b"hello").await?;
            let written = e.write_vectored(&[io::IoSlice::new(b" world")]).await?;
            assert_eq!(6, written);
            e.flush().await?;
            e.shutdown().await?;
            let mut first = [0u8; 2];
            e.read_exact(&mut first).await?;
            Ok::<_, io::Error>(first)
        }),
    )
    .with_egress_predicate(PeekEgressPrefix::new(b"OK"))
    .with_fallback(service_fn(async |_: Peeked| Ok::<_, io::Error>([0u8; 2])));
    let mut serve = Box::pin(async move { router.serve(input).await });
    // the egress matches while the client is silent, so its prefix is pending replay
    tokio::time::timeout(Duration::from_secs(1), &mut serve)
        .await
        .unwrap_err();
    ends.client.write_all(b"MAGIC").await.unwrap();
    assert_eq!(*b"OK", serve.await.unwrap());
    let mut written = Vec::new();
    ends.server.read_to_end(&mut written).await.unwrap();
    assert_eq!(b"hello world".as_slice(), written);
}

#[tokio::test]
async fn replay_survives_byte_at_a_time_delivery_across_three_peekers() {
    for chunk in [1usize, 3, 64] {
        let (input, mut ends) = bridge();
        let greeting = b"220 example ESMTP\r\n";
        let request = b"EHLO me\r\n";
        let writer = tokio::spawn(async move {
            for piece in greeting.chunks(chunk) {
                ends.server.write_all(piece).await.unwrap();
                tokio::task::yield_now().await;
            }
            for piece in request.chunks(chunk) {
                ends.client.write_all(piece).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        type L1 = PeekPrefixedIo<Ingress>;
        type L2 = PeekPrefixedIo<L1>;
        type L3 = PeekPrefixedIo<L2>;
        type E3 = PeekPrefixedIo<PeekPrefixedIo<PeekPrefixedIo<DuplexStream>>>;
        let last = PeekRouter::new(
            |b: &[u8]| prefix_peek_verdict(b, b"C"),
            service_fn(async |_: BridgeIo<L3, E3>| Ok::<_, io::Error>((Vec::new(), Vec::new()))),
        )
        .with_egress_predicate(PeekEgressPrefix::new(b"3"))
        .with_fallback(service_fn(
            async |BridgeIo(mut i, mut e): BridgeIo<L3, E3>| {
                let mut ingress = vec![0u8; request.len()];
                let mut egress = vec![0u8; greeting.len()];
                e.read_exact(&mut egress).await?;
                i.read_exact(&mut ingress).await?;
                Ok::<_, io::Error>((ingress, egress))
            },
        ));
        let middle = PeekRouter::new(
            |b: &[u8]| prefix_peek_verdict(b, b"B"),
            service_fn(
                async |_: BridgeIo<L2, PeekPrefixedIo<PeekPrefixedIo<DuplexStream>>>| {
                    Ok::<_, io::Error>((Vec::new(), Vec::new()))
                },
            ),
        )
        .with_egress_predicate(PeekEgressPrefix::new(b"2"))
        .with_fallback(last);
        let first = PeekRouter::new(
            magic,
            service_fn(async |_: Peeked| Ok::<_, io::Error>((Vec::new(), Vec::new()))),
        )
        .with_egress_predicate(PeekEgressPrefix::new(b"1"))
        .with_fallback(middle);
        let (ingress, egress) = first.serve(input).await.unwrap();
        writer.await.unwrap();
        assert_eq!(request.as_slice(), ingress);
        assert_eq!(greeting.as_slice(), egress);
    }
}
