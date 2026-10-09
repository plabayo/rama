//! Eviction of idle connections, slot waiters and fairness across ids.

use super::*;

#[tokio::test]
async fn an_idle_connection_its_waiters_leave_can_be_evicted() {
    let (pool, held) = saturated().await;
    let same = queue(&pool, &EMPTY_INPUT);
    let other_input = Extensions::new();
    let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &other_input, None));
    assert!(other.poll().is_pending(), "nothing to evict yet");
    drop(held);
    assert!(
        same.is_woken() && !other.is_woken(),
        "spoken for: no eviction chance"
    );
    drop(same);
    assert!(
        other.is_woken(),
        "nobody waits for it now: an eviction chance"
    );
    assert!(matches!(
        other.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn an_older_slot_waiter_evicts_a_spoken_for_idle_connection() {
    let (pool, held) = saturated().await;
    let other_input = Extensions::new();
    let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &other_input, None));
    assert!(other.poll().is_pending(), "nothing to evict yet");
    let mut same = queue(&pool, &EMPTY_INPUT);
    drop(held);
    assert!(
        same.is_woken() && other.is_woken(),
        "its own waiter and the older slot waiter both get the chance"
    );
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(evicted))) = other.poll() else {
        panic!("the older slot waiter evicts");
    };
    assert!(
        same.poll().is_pending(),
        "the connection went to the older one"
    );
    drop(evicted);
    assert!(matches!(
        same.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test(start_paused = true)]
async fn idle_eviction() {
    let pool = MultiplexPool::evicting(2, 5).with_idle_timeout(Duration::from_micros(1));
    let svc = connector(pool);

    let c = connect(&svc, 0).await;
    assert_eq!(created(&svc), 1);
    drop(c);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let _c = connect(&svc, 0).await;
    assert_eq!(created(&svc), 2, "idle connection should have been evicted");
}

#[tokio::test]
async fn lru_eviction_when_full() {
    let pool = MultiplexPool::evicting(1, 2);
    let svc = connector(pool);

    // A (id 0) and B (id 1), both idle. Then touch A again so A becomes more
    // recently used than B -> B is the LRU, even though A is first in storage.
    drop(connect(&svc, 0).await);
    drop(connect(&svc, 1).await);
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(connect(&svc, 0).await); // reuse A; A.last_idle now newer than B's
    assert_eq!(created(&svc), 2);

    // Pool is full (2 connections); a new id evicts the LRU idle connection (B).
    drop(connect(&svc, 2).await);
    assert_eq!(created(&svc), 3);

    // A survived (more recently used) -> reused, no new connection. This also
    // proves we evicted the LRU (B), not the first-in-storage connection (A).
    drop(connect(&svc, 0).await);
    assert_eq!(
        created(&svc),
        3,
        "A survived: LRU evicted B, not first-in-storage A"
    );

    // B was evicted -> a new connection is created for id 1.
    drop(connect(&svc, 1).await);
    assert_eq!(created(&svc), 4, "B (LRU) was evicted");
}

#[tokio::test]
async fn an_evicted_slot_goes_to_the_oldest_waiting_checkout() {
    let pool = MultiplexPool::evicting(1, 1);
    let svc = connector(pool.clone());

    // Keep the only connection active while another id waits for a slot.
    let active = connect(&svc, 0).await;
    let mut parked = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT, None));
    assert!(parked.poll().is_pending());

    // The idle connection is an eviction chance for the waiting checkout,
    // not for a newcomer that happens to look first.
    drop(active);
    assert!(parked.is_woken());
    let mut newcomer = tokio_test::task::spawn(pool.get_conn(&TestId(2), &EMPTY_INPUT, None));
    assert!(newcomer.poll().is_pending(), "the newcomer queues behind");
    let parked_permit = match parked.poll() {
        Poll::Ready(Ok(ConnectionResult::CreatePermit(permit))) => permit,
        other => panic!("the oldest waiter evicts: {other:?}"),
    };

    // Its slot then goes on through the semaphore, in arrival order.
    drop(parked_permit);
    assert!(newcomer.is_woken());
    match newcomer.poll() {
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) => {}
        other => panic!("the newcomer gets the released slot: {other:?}"),
    }
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn total_slot_waiters_are_fifo_and_cancellation_safe() {
    let pool = MultiplexPool::<Conn, TestId>::evicting(1, 1);
    let held = match pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap() {
        ConnectionResult::CreatePermit(permit) => permit,
        ConnectionResult::Connection(_) => panic!("empty pool unexpectedly reused a slot"),
    };

    let mut first = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT, None));
    assert!(first.poll().is_pending());
    let mut cancelled = tokio_test::task::spawn(pool.get_conn(&TestId(2), &EMPTY_INPUT, None));
    assert!(cancelled.poll().is_pending());
    let mut last = tokio_test::task::spawn(pool.get_conn(&TestId(3), &EMPTY_INPUT, None));
    assert!(last.poll().is_pending());
    drop(cancelled);

    // A connection-capacity notification must not cancel and requeue the
    // semaphore acquisitions. Poll newest-first to expose an accidental
    // loss of the original FIFO positions.
    pool.notify.notify_waiters();
    assert!(last.poll().is_pending());
    assert!(first.poll().is_pending());

    drop(held);
    assert!(first.is_woken());
    assert!(!last.is_woken());
    let first_permit = match first.poll() {
        Poll::Ready(Ok(ConnectionResult::CreatePermit(permit))) => permit,
        other => panic!("oldest waiter did not receive the slot first: {other:?}"),
    };
    assert!(last.poll().is_pending());

    drop(first_permit);
    assert!(last.is_woken());
    match last.poll() {
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) => {}
        other => panic!("remaining waiter did not progress after cancellation: {other:?}"),
    }
}

/// A create permit dropped by a failed connect must wake a parked waiter
/// through the total-slot semaphore instead of stranding it until the pool
/// timeout: nothing else notifies when a connect fails before creating.
#[tokio::test(start_paused = true)]
async fn failed_create_frees_slot_for_parked_waiter() {
    struct FailFirstConnector {
        attempts: AtomicUsize,
    }

    impl Service<ServiceInput<u32>> for FailFirstConnector {
        type Output = EstablishedClientConnection<Conn, ServiceInput<u32>>;
        type Error = ConnectionError;

        async fn serve(&self, input: ServiceInput<u32>) -> Result<Self::Output, Self::Error> {
            if self.attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                return Err(ConnectionError::transport(
                    BoxError::from_static_str("first connect fails"),
                    ConnectionErrorKind::Unavailable,
                ));
            }
            Ok(EstablishedClientConnection {
                input,
                conn: Conn {
                    serial: 1,
                    extensions: Extensions::new(),
                },
            })
        }
    }

    let pool = MultiplexPool::evicting(1, 1);
    let svc = Arc::new(
        PooledConnector::new(
            FailFirstConnector {
                attempts: AtomicUsize::new(0),
            },
            pool,
            id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
        )
        .with_wait_for_pool_timeout(Duration::from_secs(120)),
    );

    // Takes the only slot's create permit, then fails after 50ms.
    let failing = tokio::spawn({
        let svc = svc.clone();
        async move { svc.connect(ServiceInput::new(0u32)).await }
    });
    tokio::task::yield_now().await;
    // Parks: no connection to reuse and no free slot.
    let waiter = tokio::spawn({
        let svc = svc.clone();
        async move { svc.connect(ServiceInput::new(0u32)).await }
    });

    let (failed, waited) = tokio::join!(failing, waiter);
    let _error = failed.unwrap().expect_err("first connect must fail");
    waited
        .unwrap()
        .expect("the slot freed by the failed create must wake the parked waiter");
}

/// A waiter parked on a full pool is woken when the last handle of an
/// already-swept (broken) connection drops and its slot frees up.
#[tokio::test(start_paused = true)]
async fn slot_freed_by_swept_connection_teardown_wakes_waiter() {
    let pool = MultiplexPool::evicting(1, 1);
    let svc = Arc::new(connector(pool).with_wait_for_pool_timeout(Duration::from_secs(120)));

    let c1 = svc.connect(ServiceInput::new(0u32)).await.unwrap();
    c1.conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();

    // The waiter's own attempt sweeps the broken connection out of storage,
    // but the slot is still held by c1's live handle: it parks.
    let waiter = tokio::spawn({
        let svc = svc.clone();
        async move { svc.connect(ServiceInput::new(0u32)).await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    drop(c1);

    let waited = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("waiter must be woken by the freed slot");
    waited.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn cold_idle_connections_are_reaped_while_a_hot_one_serves() {
    let pool = MultiplexPool::evicting(1, 8).with_idle_timeout(Duration::from_secs(4));
    let svc = connector(pool.clone());
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(connect(&svc, 0).await);
    }
    drop(held);

    // Only the earliest connection is ever selected, so the others are
    // never looked at by a checkout. The bucket's own sweep reaps them.
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(600)).await;
        let handout = connect(&svc, 0).await;
        assert_eq!(serial_of(&handout.conn).await, 0);
    }
    assert_eq!(pool.storage.lock().by_id[&TestId(0)].conns().count(), 1);
    assert_eq!(pool.free_slots(), 7);
    assert_eq!(created(&svc), 4);
    assert_open_matches_capacity(&pool);
}

#[tokio::test]
async fn an_idle_connection_that_cannot_take_a_stream_is_evictable() {
    // Who waits: its own lane, another id, or both (the older one evicts).
    for (same_waits, other_waits) in [(true, false), (false, true), (true, true)] {
        let pool = MultiplexPool::evicting(usize::MAX, 1);
        let conn = Conn {
            serial: 0,
            extensions: Extensions::new(),
        };
        let max = Arc::new(MaxConcurrency::new(1));
        conn.extensions.insert_arc(max.clone());
        let held = pool
            .create(TestId(0), conn, pool.test_slot(), &EMPTY_INPUT)
            .await
            .unwrap();
        let mut same = same_waits.then(|| queue(&pool, &EMPTY_INPUT));
        let mut other = other_waits.then(|| {
            let mut other = checkout(&pool, 1);
            assert!(other.poll().is_pending());
            other
        });
        // The peer allows no streams any more, and the connection goes idle.
        max.set(0);
        drop(held);
        let evictor = same.as_mut().or(other.as_mut()).unwrap();
        assert!(
            evictor.is_woken()
                && matches!(
                    evictor.poll(),
                    Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
                ),
            "a connection nobody can use is nobody's ({same_waits}, {other_waits})"
        );
    }
}

#[tokio::test]
async fn a_checkout_whose_connections_cannot_take_a_stream_counts_as_cold() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    let max = Arc::new(MaxConcurrency::new(1));
    conn.extensions.insert_arc(max.clone());
    let held = pool
        .create(TestId(0), conn, pool.test_slot(), &EMPTY_INPUT)
        .await
        .unwrap();
    let mut waiter = queue(&pool, &EMPTY_INPUT);
    max.set(0);
    drop(held);
    assert!(matches!(
        waiter.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn a_younger_id_evicts_an_idle_connection_its_waiters_cannot_use() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    let max = Arc::new(MaxConcurrency::new(1));
    conn.extensions.insert_arc(max.clone());
    let held = pool
        .create(TestId(0), conn, pool.test_slot(), &EMPTY_INPUT)
        .await
        .unwrap();
    // The older waiter is warm and may not evict; the younger id is cold.
    let mut warm = queue(&pool, &EMPTY_INPUT);
    let mut cold = checkout(&pool, 1);
    assert!(cold.poll().is_pending());
    max.set(0);
    drop(held);
    assert!(cold.is_woken(), "nobody can use it: an eviction chance");
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(evicted))) = cold.poll() else {
        panic!("the cold id evicts");
    };
    assert!(warm.poll().is_pending(), "the slot went to the cold id");
    drop(evicted);
}

#[tokio::test]
async fn the_front_waiter_evicts_an_idle_connection_that_refuses_it() {
    let pool = MultiplexPool::evicting(32, 1);
    let (conn, state) = admission_connection(&pool, 1);
    let held = pool
        .create(TestId(0), conn, pool.test_slot(), &EMPTY_INPUT)
        .await
        .unwrap();
    let mut waiter = queue(&pool, &EMPTY_INPUT);
    // Credit stays exhausted although the connection goes idle.
    state.set_limit(0);
    drop(held);
    assert!(
        matches!(
            waiter.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "its own look found nothing usable there"
    );
}

#[tokio::test]
async fn an_eviction_chance_taken_by_a_waiter_served_elsewhere_passes_on() {
    let pool = MultiplexPool::evicting(1, 3);
    let a = add(&pool, 0, None).await;
    let c = add(&pool, 2, None).await;
    let _d = add(&pool, 3, None).await;
    let mut w = queue(&pool, &EMPTY_INPUT);
    let other_input = Extensions::new();
    let mut y = tokio_test::task::spawn(pool.get_conn(&TestId(1), &other_input, None));
    assert!(y.poll().is_pending());
    // At once: id 2's connection goes idle (an eviction chance) and id 0's
    // stream frees (w's own lane).
    drop(c);
    drop(a);
    drop(handout(&mut w));
    assert!(
        y.is_woken(),
        "the chance w did not use reaches the next one"
    );
    assert!(matches!(
        y.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn another_id_gets_its_turn_while_an_id_keeps_waiters() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let mut held = add(&pool, 0, None).await;
    let mut busy = queue(&pool, &EMPTY_INPUT);
    let other_input = Extensions::new();
    let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &other_input, None));
    assert!(other.poll().is_pending());
    // Id 0 keeps one more waiter queued at every idle moment.
    for round in 0.. {
        let mut next = queue(&pool, &EMPTY_INPUT);
        drop(held);
        if other.is_woken()
            && let Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) = other.poll()
        {
            assert!(round <= 1, "served in arrival order across ids");
            break;
        }
        held = handout(&mut busy);
        busy = std::mem::replace(&mut next, queue(&pool, &EMPTY_INPUT));
        drop(next);
        assert!(round < 8, "another id starves");
    }
}

#[tokio::test]
async fn an_older_slot_waiter_gets_the_idle_connection_whatever_runs_first() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let held = add(&pool, 0, None).await;
    let mut other = checkout(&pool, 1);
    assert!(other.poll().is_pending());
    let mut same = queue(&pool, &EMPTY_INPUT);
    drop(held);
    // Both may run: the younger lane waiter runs first and must leave it.
    assert!(
        same.poll().is_pending(),
        "kept for the older checkout of another id"
    );
    assert!(matches!(
        other.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn a_newcomer_leaves_an_idle_connection_to_an_older_slot_waiter() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let held = add(&pool, 0, None).await;
    let mut other = checkout(&pool, 1);
    assert!(other.poll().is_pending());
    drop(held);
    // A keep-alive loop's next request comes before the woken waiter runs.
    let mut next = checkout(&pool, 0);
    assert!(
        next.poll().is_pending(),
        "the idle connection is not the newcomer's"
    );
    assert!(matches!(
        other.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn leaving_a_lane_empty_announces_its_idle_connection() {
    let pool =
        MultiplexPool::evicting(1, 2).with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let one = add(&pool, 0, Some(keyed(0, 1))).await;
    let _two = add(&pool, 0, Some(keyed(0, 2))).await;
    let input = want(1);
    let mut moved = queue(&pool, &input);
    let mut other = checkout(&pool, 1);
    assert!(other.poll().is_pending());
    input.insert(Want(2));
    drop(one);
    // Its only waiter wants another key now: it leaves the lane empty.
    assert!(moved.poll().is_pending());
    assert!(
        other.is_woken(),
        "the idle connection nobody waits for is announced"
    );
    assert!(matches!(
        other.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn a_connection_breaking_lets_a_checkout_waiting_for_a_slot_take_it_out() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait);
    let held = add(&pool, 0, None).await;
    let health = held
        .extensions()
        .get_arc::<ConnectionHealthWatcher>()
        .unwrap();
    drop(held);
    let mut other = checkout(&pool, 1);
    assert!(other.poll().is_pending(), "it may not evict");
    health.mark_broken();
    assert!(
        other.is_woken(),
        "a broken connection is no one's: let it be taken out"
    );
    assert!(matches!(
        other.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn an_evictor_keeps_the_chance_it_used() {
    let pool = MultiplexPool::evicting(1, 1);
    let held = add(&pool, 0, None).await;
    let mut first = checkout(&pool, 1);
    assert!(first.poll().is_pending());
    let mut second = checkout(&pool, 2);
    assert!(second.poll().is_pending());
    drop(held);
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(evicted))) = first.poll() else {
        panic!("the first slot waiter evicts");
    };
    assert!(
        !second.is_woken(),
        "one idle connection, one chance: nothing left for the next"
    );
    drop((evicted, second));
}

#[tokio::test]
async fn a_lane_left_empty_announces_its_idle_connection_to_the_ids_evictors() {
    let pool = MultiplexPool::new()
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let held = fresh_keyed(&pool, 0, 1).await;
    let (own, other) = (want(1), want(2));
    let lane = queue_keyed(&pool, 0, &own);
    let mut evictor = queue_keyed(&pool, 0, &other);
    drop(held);
    assert!(!evictor.is_woken(), "the older lane waiter's");
    drop(lane);
    assert!(evictor.is_woken(), "its only waiter left");
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = evictor.poll() else {
        panic!("it replaces the idle connection");
    };
    drop(slot);
}

#[tokio::test]
async fn an_evictor_passes_the_chance_on_while_more_idle_connections_wait() {
    let pool = exclusive(3, SaturationPolicy::EvictIdleWhenCold);
    let held = [add(&pool, 0, None).await, add(&pool, 0, None).await];
    let busy = add(&pool, 3, None).await;
    let lane = queue(&pool, &EMPTY_INPUT);
    let mut first = checkout(&pool, 1);
    assert!(first.poll().is_pending());
    let mut second = checkout(&pool, 2);
    assert!(second.poll().is_pending());
    drop(held);
    assert!(!first.is_woken(), "the older lane waiter's");
    // One announcement for the lane's two idle connections.
    drop(lane);
    assert!(first.is_woken() && !second.is_woken());
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(evicted))) = first.poll() else {
        panic!("it evicts one");
    };
    assert!(second.is_woken(), "another one could go too");
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(next))) = second.poll() else {
        panic!("it evicts the other");
    };
    drop((evicted, next, busy));
}

#[tokio::test]
async fn a_checkout_leaving_only_chance_queues_announces_nothing() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(2).unwrap())
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let held = fresh_keyed(&pool, 0, 1).await;
    let busy = fresh(&pool, 2).await;
    let mut slot_waiter = checkout(&pool, 1);
    assert!(slot_waiter.poll().is_pending());
    let input = want(2);
    // At its id's limit, in no lane: only in the id's evictor queue.
    let replacing = queue_keyed(&pool, 0, &input);
    drop(replacing);
    assert!(!slot_waiter.is_woken(), "no lane was left empty");
    drop((slot_waiter, held, busy));
}

#[tokio::test]
async fn a_fruitless_look_spends_the_chances_it_answered() {
    let pool = exclusive(2, SaturationPolicy::EvictIdleWhenCold);
    let held = add(&pool, 0, None).await;
    let busy = add(&pool, 3, None).await;
    let mut first = checkout(&pool, 1);
    assert!(first.poll().is_pending());
    let mut second = checkout(&pool, 2);
    assert!(second.poll().is_pending());
    // Two chances, nothing idle: lanes of the busy connection left empty.
    for _ in 0..2 {
        drop(queue(&pool, &EMPTY_INPUT));
    }
    assert!(first.is_woken() && second.is_woken());
    assert!(second.poll().is_pending() && first.poll().is_pending());
    drop(held);
    // Both look, whoever was woken.
    pool.notify.notify_waiters();
    assert!(
        second.poll().is_pending(),
        "the younger evictor holds no chance any more"
    );
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = first.poll() else {
        panic!("the older one evicts it");
    };
    drop((slot, second, busy));
}

#[tokio::test]
async fn a_checkout_with_a_freed_slot_leaves_an_idle_connection_to_an_older_evictor() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(4).unwrap())
        .with_max_connections_per_id(NonZeroUsize::new(2).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let gone = fresh_keyed(&pool, 1, 1).await;
    let _other = fresh_keyed(&pool, 1, 1).await;
    let held = fresh(&pool, 0).await;
    let _busy = fresh(&pool, 3).await;
    // At id 1's limit first: it waits for an id slot, not yet for a total one.
    let input = want(2);
    let mut evictor = queue_keyed(&pool, 1, &input);
    let mut lane = checkout(&pool, 0);
    assert!(lane.poll().is_pending(), "warm: it waits for a total slot");
    // A connection of id 1 goes: its id slot to the evictor, its total slot
    // through the semaphore to the lane waiter, queued there first.
    gone.extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    drop(gone);
    assert!(evictor.poll().is_pending(), "nothing idle to evict yet");
    drop(held);
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = lane.poll() else {
        panic!("the idle connection is the older evictor's: dial with the slot");
    };
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(evicted))) = evictor.poll() else {
        panic!("the evictor takes it");
    };
    drop((slot, evicted));
}
