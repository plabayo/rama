use std::{
    cell::Cell,
    io,
    pin::{Pin, pin},
    sync::{atomic::AtomicUsize, mpsc::sync_channel},
    thread,
};

use rama_core::futures::{
    Stream as _, StreamExt as _, channel::mpsc, future::join_all, stream::poll_fn,
};
use rama_crypto::native_certs::bundled_root_certs;

use super::*;
use crate::client::{ChannelReloadTrigger, native_trust::warn_capture::WarnCapture};

#[test]
fn a_user_stream_is_polled_only_after_its_waker_fires() {
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
        assert!(Arc::ptr_eq(&original, &quiet));
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
    assert_eq!(updated.as_ref(), &anchors[1..2]);

    send.try_send(()).unwrap();
    let restored = reload
        .pin_with(None, |_| Ok((anchors[..1].to_vec(), false)))
        .unwrap();
    assert_eq!(original.as_ref(), restored.as_ref());
    assert!(!Arc::ptr_eq(&original, &restored));
}

#[test]
fn callers_joining_a_refresh_consume_queued_events_first() {
    let (sender, trigger) = ChannelReloadTrigger::new();
    let consumed = Arc::new(AtomicUsize::new(0));
    let counted = trigger.inspect({
        let consumed = consumed.clone();
        move |()| {
            consumed.fetch_add(1, Ordering::Relaxed);
        }
    });
    let reload = NativeTrustReload::new(NativeTrustScope::PlatformExtras, Some(Box::pin(counted)));
    let anchors = bundled_root_certs()[..1].to_vec();
    let current = reload
        .pin_with(None, |_| Ok((anchors.clone(), false)))
        .unwrap();

    sender.request_reload().unwrap();
    let PinAction::Refresh(leader) = reload.prepare_pin(None) else {
        panic!("expected native trust refresh");
    };
    assert_eq!(consumed.load(Ordering::Relaxed), 1);

    // An event queued during the refresh is consumed by whoever pins next,
    // whether it reuses the current snapshot or waits for the refresh.
    sender.request_reload().unwrap();
    let PinAction::Ready(Ok(reused)) = reload.prepare_pin(None) else {
        panic!("a fresh snapshot is served during a refresh");
    };
    assert!(Arc::ptr_eq(&current, &reused));
    assert_eq!(consumed.load(Ordering::Relaxed), 2);

    sender.request_reload().unwrap();
    let PinAction::Wait(..) = reload.prepare_pin(Some(Duration::ZERO)) else {
        panic!("a stale snapshot joins the refresh");
    };
    assert_eq!(consumed.load(Ordering::Relaxed), 3);

    leader.run(None, |_| Ok((anchors.clone(), false))).unwrap();
    let after_publication = reload.pin_with(None, |_| Ok((Vec::new(), false))).unwrap();
    assert!(after_publication.is_empty());
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
            Err(io::Error::from(io::ErrorKind::InvalidData).into())
        })
        .unwrap();
    assert!(Arc::ptr_eq(&original, &failed));

    let stale = reload
        .pin_with(Some(Duration::ZERO), |_| panic!("failure backoff active"))
        .unwrap_err();
    assert!(stale.is::<NativeTrustRefreshError>());

    set_retry_at(&reload, Instant::now());
    let retried = reload.pin_with(None, load).unwrap();
    assert!(Arc::ptr_eq(&original, &retried));
}

fn set_retry_at(reload: &NativeTrustReload, retry_at: Instant) {
    let published = reload.0.published.load();
    let failure = published.failure.as_ref().unwrap();
    reload.0.published.store(Arc::new(PublishedTrust {
        current: published.current.clone(),
        failure: Some(RefreshFailure {
            retry_at,
            error: failure.error.clone(),
        }),
    }));
}

#[test]
fn retry_backoff_grows_to_a_cap_and_resets_after_trigger_or_success() {
    let (sender, trigger) = ChannelReloadTrigger::new();
    let reload = NativeTrustReload::new(NativeTrustScope::Full, Some(Box::pin(trigger)));
    let reads = Cell::new(0);
    let fail = |_| {
        reads.set(reads.get() + 1);
        Err(io::Error::from(io::ErrorKind::InvalidData).into())
    };
    let assert_failed_read = |delay| {
        let started = Instant::now();
        assert!(
            reload
                .pin_with(None, fail)
                .unwrap_err()
                .is::<NativeTrustRefreshError>()
        );
        let published = reload.0.published.load();
        let retry_at = published.failure.as_ref().unwrap().retry_at;
        assert!(retry_at >= started + delay);
        assert!(retry_at <= Instant::now() + delay);
    };

    for (attempt, delay) in [1, 2, 4, 8, 16, 32, 60, 60].into_iter().enumerate() {
        assert_failed_read(Duration::from_secs(delay));
        // Simulate repeated handshakes before the scheduled retry.
        set_retry_at(&reload, Instant::now() + MAX_RETRY_DELAY);
        for _ in 0..8 {
            assert!(
                reload
                    .pin_with(None, fail)
                    .unwrap_err()
                    .is::<NativeTrustRefreshError>()
            );
        }
        assert_eq!(reads.get(), attempt + 1);

        if attempt < 7 {
            set_retry_at(&reload, Instant::now());
        }
    }

    // A real trigger bypasses the deadline and restarts the backoff sequence.
    sender.request_reload().unwrap();
    assert_failed_read(INITIAL_RETRY_DELAY);
    assert_eq!(reads.get(), 9);

    set_retry_at(&reload, Instant::now());
    reload
        .pin_with(None, |_| Ok((bundled_root_certs()[..1].to_vec(), false)))
        .unwrap();
    assert!(reload.0.published.load().failure.is_none());
    let started = Instant::now();
    let snapshot = reload.pin_with(Some(Duration::ZERO), fail).unwrap_err();
    assert!(snapshot.is::<NativeTrustRefreshError>());
    let retry_at = reload.0.published.load().failure.as_ref().unwrap().retry_at;
    assert!(retry_at >= started + INITIAL_RETRY_DELAY);
    assert!(retry_at <= Instant::now() + INITIAL_RETRY_DELAY);
    assert_eq!(reads.get(), 10);
}

#[test]
fn async_refresh_waiters_share_one_blocking_worker_after_leader_cancellation() {
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
            assert_eq!(snapshot.unwrap().as_ref(), &bundled_root_certs()[..1]);
        }

        let next = reload
            .pin_async_with(max_age, |_| {
                Ok((bundled_root_certs()[1..2].to_vec(), false))
            })
            .await
            .unwrap();
        assert_eq!(next.as_ref(), &bundled_root_certs()[1..2]);
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
    thread::scope(|scope| {
        let (entered, waiting) = sync_channel(0);
        let (resume, paused) = sync_channel(0);
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
        assert!(Arc::ptr_eq(&initial, &concurrent));
        assert_eq!(concurrent.as_ref(), &anchors[..1]);
        assert_ne!(initial, updated);
        assert_eq!(updated.as_ref(), &anchors[1..2]);
        let PinAction::Ready(Ok(next)) = reload.prepare_pin(None) else {
            panic!("expected newly published trust anchors");
        };
        assert!(Arc::ptr_eq(&updated, &next));
    });
}

#[test]
fn an_ended_trigger_warns_once_and_is_not_polled_again() {
    let polls = Arc::new(AtomicUsize::new(0));
    let stream = poll_fn({
        let polls = polls.clone();
        move |_| {
            polls.fetch_add(1, Ordering::Relaxed);
            Poll::<Option<()>>::Ready(None)
        }
    });
    let reload = NativeTrustReload::new(NativeTrustScope::Full, Some(Box::pin(stream)));
    let anchors = bundled_root_certs();
    let capture = WarnCapture::default();
    capture.record(|| {
        let first = reload
            .pin_with(None, |_| Ok((anchors[..1].to_vec(), false)))
            .unwrap();
        for _ in 0..8 {
            // A stray wake must not reach the finished stream.
            reload.0.wake.0.store(true, Ordering::Release);
            let PinAction::Ready(Ok(next)) = reload.prepare_pin(None) else {
                panic!("an ended trigger must keep the current snapshot");
            };
            assert!(Arc::ptr_eq(&first, &next));
        }
    });
    assert_eq!(polls.load(Ordering::Relaxed), 1);
    assert_eq!(capture.warnings(), 1);
}

#[test]
fn ready_pins_never_load_and_leave_events_for_the_next_pin() {
    let (sender, trigger) = ChannelReloadTrigger::new();
    let reload = NativeTrustReload::new(NativeTrustScope::Full, Some(Box::pin(trigger)));
    assert!(reload.pin_ready(None).is_none());

    let anchors = bundled_root_certs();
    let original = reload
        .pin_with(None, |_| Ok((anchors[..1].to_vec(), false)))
        .unwrap();
    assert!(Arc::ptr_eq(&original, &reload.pin_ready(None).unwrap()));
    assert!(reload.pin_ready(Some(Duration::ZERO)).is_none());

    sender.request_reload().unwrap();
    for _ in 0..2 {
        assert!(reload.pin_ready(None).is_none());
    }
    let PinAction::Refresh(job) = reload.prepare_pin(None) else {
        panic!("a consumed event refreshes on the next pin");
    };
    let updated = job
        .run(None, |_| Ok((anchors[1..2].to_vec(), false)))
        .unwrap();
    assert!(Arc::ptr_eq(&updated, &reload.pin_ready(None).unwrap()));
}
