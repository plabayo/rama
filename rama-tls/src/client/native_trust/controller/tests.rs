use super::*;
use crate::client::ChannelReloadTrigger;
use rama_core::futures::Stream as _;
use rama_crypto::native_certs::bundled_root_certs;
use std::pin::Pin;

#[test]
fn a_user_stream_is_polled_only_after_its_waker_fires() {
    use rama_core::futures::{channel::mpsc, stream::poll_fn};
    use std::sync::atomic::AtomicUsize;

    let (mut send, mut events) = mpsc::channel(1);
    let polls = AtomicUsize::new(0);
    let polls = Arc::new(polls);
    let stream = poll_fn({
        let polls = polls.clone();
        move |cx| {
            polls.fetch_add(1, Ordering::Relaxed);
            Pin::new(&mut events).poll_next(cx)
        }
    });
    let reload = NativeTrustReload::new(NativeTrustScope::Full, Some(Box::pin(stream)));
    let anchors = bundled_root_certs();
    let original = reload
        .pin_with(None, |_| Ok((anchors[..1].to_vec(), false)))
        .unwrap();
    for _ in 0..32 {
        let PinAction::Ready(Ok(quiet)) = reload.prepare_pin(None) else {
            panic!("unexpected native trust refresh");
        };
        assert_eq!(original, quiet);
    }
    assert_eq!(polls.load(Ordering::Relaxed), 1);

    send.try_send(()).unwrap();
    let PinAction::Refresh(job) = reload.prepare_pin(None) else {
        panic!("expected native trust refresh");
    };
    let updated = job
        .run(None, |_| Ok((anchors[1..2].to_vec(), false)))
        .unwrap();
    assert_ne!(original, updated);
    assert_eq!(updated.native_roots().unwrap(), &anchors[1..2]);
}

#[test]
fn refresh_retries_without_another_request_and_preserves_equal_generations() {
    let (sender, trigger) = ChannelReloadTrigger::new();
    let reload = NativeTrustReload::new(NativeTrustScope::Full, Some(Box::pin(trigger)));
    let anchors = bundled_root_certs()[..1].to_vec();
    let load = |_| Ok((anchors.clone(), false));
    let original = reload.pin_with(None, load).unwrap();

    sender.request_reload().unwrap();
    let failed = reload
        .pin_with(None, |_| {
            Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into())
        })
        .unwrap();
    assert_eq!(original, failed);

    let stale = reload
        .pin_with(Some(Duration::ZERO), |_| panic!("failure backoff active"))
        .unwrap_err();
    assert!(stale.is::<NativeTrustRefreshError>());

    reload.0.reload.lock().failure.as_mut().unwrap().0 -= Duration::from_secs(2);
    let retried = reload.pin_with(None, load).unwrap();
    assert_eq!(original, retried);
}

#[test]
fn async_refresh_waiters_share_one_blocking_worker_after_leader_cancellation() {
    use rama_core::futures::future::join_all;
    use std::pin::pin;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(2)
        .build()
        .unwrap();
    runtime.block_on(async {
        let reload = NativeTrustReload::new(NativeTrustScope::Full, None);
        let max_age = Some(Duration::ZERO);
        let (entered, started) = flume::bounded(1);
        let (resume, paused) = flume::bounded(1);

        {
            let mut leader = pin!(reload.pin_async_with(max_age, move |_| {
                entered.send(()).unwrap();
                paused.recv().unwrap();
                Ok((bundled_root_certs()[..1].to_vec(), false))
            }));
            let cx = &mut Context::from_waker(Waker::noop());
            assert!(leader.as_mut().poll(cx).is_pending());
        }
        started.recv_async().await.unwrap();

        let mut waiters = pin!(join_all((0..16).map(|_| {
            reload.pin_async_with(max_age, |_| panic!("waiter started another refresh"))
        })));
        let cx = &mut Context::from_waker(Waker::noop());
        assert!(waiters.as_mut().poll(cx).is_pending());

        tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(|| {}))
            .await
            .expect("other blocking work must run while the native trust store is blocked")
            .unwrap();

        resume.send(()).unwrap();
        let snapshots = waiters.await;
        for snapshot in snapshots {
            assert_eq!(
                snapshot.unwrap().native_roots().unwrap(),
                &bundled_root_certs()[..1]
            );
        }

        let next = reload
            .pin_async_with(max_age, |_| {
                Ok((bundled_root_certs()[1..2].to_vec(), false))
            })
            .await
            .unwrap();
        assert_eq!(next.native_roots().unwrap(), &bundled_root_certs()[1..2]);
    });
}

#[test]
fn concurrent_handshakes_keep_a_fresh_pinned_snapshot_until_publication() {
    let (sender, trigger) = ChannelReloadTrigger::new();
    let reload = NativeTrustReload::new(NativeTrustScope::Full, Some(Box::pin(trigger)));
    let anchors = bundled_root_certs();
    let initial = reload
        .pin_with(None, |_| Ok((anchors[..1].to_vec(), false)))
        .unwrap();

    sender.request_reload().unwrap();
    std::thread::scope(|scope| {
        let (entered, waiting) = std::sync::mpsc::sync_channel(0);
        let (resume, paused) = std::sync::mpsc::sync_channel(0);
        let reload = &reload;
        let refreshing = scope.spawn(move || {
            reload
                .pin_with(None, |_| {
                    entered.send(()).unwrap();
                    paused.recv().unwrap();
                    Ok((anchors[1..2].to_vec(), false))
                })
                .unwrap()
        });
        waiting.recv().unwrap();
        let concurrent = reload.prepare_pin(None);
        let strict = reload.prepare_pin(Some(Duration::ZERO));
        resume.send(()).unwrap();

        let updated = refreshing.join().unwrap();
        let PinAction::Ready(Ok(concurrent)) = concurrent else {
            panic!("expected concurrent handshake to keep using fresh trust anchors");
        };
        assert!(matches!(strict, PinAction::Wait(..)));
        assert_eq!(initial, concurrent);
        assert_eq!(concurrent.native_roots().unwrap(), &anchors[..1]);
        assert_ne!(initial, updated);
        assert_eq!(updated.native_roots().unwrap(), &anchors[1..2]);
        let PinAction::Ready(Ok(next)) = reload.prepare_pin(None) else {
            panic!("expected newly published trust anchors");
        };
        assert_eq!(updated, next);
    });
}
