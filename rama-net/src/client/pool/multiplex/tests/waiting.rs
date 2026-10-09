//! The wait path: FIFO per lane, wakes and their hand-over.

use super::*;

#[tokio::test]
async fn waiters_are_served_in_arrival_order() {
    let (pool, held) = saturated().await;
    let mut first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    let mut third = queue(&pool, &EMPTY_INPUT);
    drop(held);
    assert!(first.is_woken());
    assert!(
        !second.is_woken() && !third.is_woken(),
        "one release, one wake"
    );
    let held = handout(&mut first);
    drop(held);
    assert!(second.is_woken() && !third.is_woken());
    let held = handout(&mut second);
    drop(held);
    let held = handout(&mut third);
    drop(held);
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn two_released_streams_wake_two_waiters() {
    let pool = MultiplexPool::evicting(2, 1);
    let a = add(&pool, 0, None).await;
    let ConnectionResult::Connection(b) = pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap()
    else {
        panic!("a free stream");
    };
    let mut first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    drop(a);
    drop(b);
    assert!(
        first.is_woken() && second.is_woken(),
        "each unit reaches its own waiter"
    );
    drop((handout(&mut first), handout(&mut second)));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn newcomers_queue_behind_waiters() {
    let (pool, held) = saturated().await;
    let mut waiter = queue(&pool, &EMPTY_INPUT);
    drop(held);
    // The released stream belongs to the waiter: a newcomer queues.
    let mut newcomer = queue(&pool, &EMPTY_INPUT);
    let held = handout(&mut waiter);
    assert!(newcomer.poll().is_pending());
    drop(held);
    drop(handout(&mut newcomer));
}

#[tokio::test]
async fn a_cancelled_waiter_passes_its_wake_on() {
    let (pool, held) = saturated().await;
    let first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    drop(held);
    assert!(first.is_woken() && !second.is_woken());
    drop(first);
    assert!(
        second.is_woken(),
        "the unused wake moves to the next waiter"
    );
    drop(handout(&mut second));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_waiter_woken_for_nothing_keeps_its_place() {
    let pool = MultiplexPool::evicting(4, 1);
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    let max = Arc::new(MaxConcurrency::new(1));
    conn.extensions.insert_arc(max.clone());
    let permit = pool.test_slot();
    let held = pool
        .create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    let mut first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    // A pushed change wakes the lane, but frees nothing.
    max.set(1);
    assert!(first.is_woken() && second.is_woken());
    assert!(first.poll().is_pending() && second.poll().is_pending());
    assert_eq!(
        pool.storage.lock().by_id[&TestId(0)]
            .unrestricted
            .waiters
            .len(),
        2,
        "a look queues once per lane"
    );
    drop(held);
    assert!(
        first.is_woken() && !second.is_woken(),
        "the first in line comes first"
    );
    // A look for another reason: a spent wake admits nobody.
    pool.notify.notify_waiters();
    assert!(second.poll().is_pending());
    drop(handout(&mut first));
    drop(handout(&mut second));
}

#[tokio::test]
async fn a_waiter_of_several_lanes_leaves_all_of_them() {
    let pool = MultiplexPool::evicting(1, 2);
    let unrestricted = add(&pool, 0, None).await;
    let keyed = add(&pool, 0, Some(keyed(0, 1))).await;
    let input = want(1);
    let mut waiter = queue(&pool, &input);
    drop(keyed);
    let served = handout(&mut waiter);
    for lane in pool.storage.lock().by_id[&TestId(0)].lanes() {
        assert!(lane.waiters.is_empty(), "the served waiter left every lane");
    }
    drop((served, unrestricted));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

/// Many checkouts on few exclusive connections, with pushed changes in
/// between: every one completes, and nothing stays queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiters_never_stall_under_churn() {
    for selection in [
        MuxSelection::FirstAvailable,
        MuxSelection::LeastLoaded,
        MuxSelection::RoundRobin,
    ] {
        let pool = MultiplexPool::evicting(1, 4).with_selection(selection);
        let max = Arc::new(MaxConcurrency::new(1));
        let mut tasks = Vec::new();
        for task in 0..32_u32 {
            let pool = pool.clone();
            let max = max.clone();
            tasks.push(tokio::spawn(async move {
                for round in 0..64_u32 {
                    let handout = match pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap() {
                        ConnectionResult::Connection(handout) => handout,
                        ConnectionResult::CreatePermit(permit) => {
                            let conn = Conn {
                                serial: 0,
                                extensions: Extensions::new(),
                            };
                            conn.extensions.insert_arc(max.clone());
                            pool.create(TestId(0), conn, permit, &EMPTY_INPUT)
                                .await
                                .unwrap()
                        }
                    };
                    if (task + round) % 7 == 0 {
                        max.set(1);
                    }
                    tokio::task::yield_now().await;
                    drop(handout);
                }
            }));
        }
        tokio::time::timeout(Duration::from_secs(30), async {
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await
        .expect("no checkout stalls");
        assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
        assert_open_matches_capacity(&pool);
    }
}

#[tokio::test]
async fn a_cancellation_wave_across_lanes_passes_each_wake_once() {
    let pool = MultiplexPool::evicting(1, 2);
    let unrestricted = add(&pool, 0, None).await;
    let keyed_conn = add(&pool, 0, Some(keyed(0, 1))).await;
    let input = want(1);
    let mut waiters: Vec<_> = (0..32).map(|_| queue(&pool, &input)).collect();
    let mut last = waiters.pop().unwrap();
    drop(keyed_conn);
    // The others leave in arrival order, without a look: one wake moves on.
    drop(waiters);
    let unspent: usize = pool.storage.lock().by_id[&TestId(0)]
        .lanes()
        .map(|lane| lane.waiters.unspent())
        .sum();
    assert_eq!(unspent, 1, "one release, one wake");
    assert!(last.is_woken());
    drop((handout(&mut last), unrestricted));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_waiter_served_in_another_lane_passes_its_wake_on() {
    let pool = MultiplexPool::evicting(2, 2).with_selection(MuxSelection::FirstAvailable);
    let unrestricted = add(&pool, 0, None).await;
    let keyed_conn = add(&pool, 0, Some(keyed(0, 1))).await;
    let ConnectionResult::Connection(full_unrestricted) =
        pool.get_conn(&TestId(0), &want(2)).await.unwrap()
    else {
        panic!("a free stream");
    };
    let ConnectionResult::Connection(full_keyed) =
        pool.get_conn(&TestId(0), &want(1)).await.unwrap()
    else {
        panic!("a free stream");
    };
    let (both, unrestricted_only, both_again) = (want(1), want(2), want(1));
    let mut first = queue(&pool, &both);
    let mut second = queue(&pool, &unrestricted_only);
    let mut third = queue(&pool, &both_again);
    // A keyed stream frees (waking `first`), then an unrestricted one
    // (waking `second`): `first` prefers the older unrestricted one.
    drop(full_keyed);
    drop(full_unrestricted);
    let served = handout(&mut first);
    assert!(Arc::ptr_eq(&served.inner, &unrestricted.inner));
    if second.is_woken() {
        assert!(second.poll().is_pending(), "it cannot use the keyed one");
    }
    assert!(
        third.is_woken(),
        "the keyed stream `first` left is announced to the next who can use it"
    );
    drop(handout(&mut third));
    drop((served, second, unrestricted, keyed_conn));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_capacity_raise_wakes_every_waiter() {
    let pool = MultiplexPool::evicting(10, 1);
    let permit = new_slot(&pool).await;
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    let max = Arc::new(MaxConcurrency::new(1));
    conn.extensions.insert_arc(max.clone());
    let first = pool
        .create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    let mut a = queue(&pool, &EMPTY_INPUT);
    let mut b = queue(&pool, &EMPTY_INPUT);
    max.set(3);
    assert!(a.is_woken() && b.is_woken());
    drop((handout(&mut a), handout(&mut b), first));
}

#[tokio::test(start_paused = true)]
async fn maxconcurrency_increase_wakes_waiters() {
    let pool = MultiplexPool::evicting(10, 1);
    let svc = Arc::new(connector_with(pool, Some(1)));

    let c1 = svc.connect(ServiceInput::new(0)).await.unwrap();

    let woke = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = {
        let svc = svc.clone();
        let woke = woke.clone();
        tokio::spawn(async move {
            let _h = svc.connect(ServiceInput::new(0)).await.unwrap();
            woke.store(true, Ordering::Relaxed);
        })
    };

    // The waiter parks: connection 0 is at capacity and the pool is full.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!woke.load(Ordering::Relaxed), "waiter should be parked");

    // Raise the connection's advertised capacity (as an h2 SETTINGS bump would):
    // the parked waiter must wake and admit on the now-available stream slot.
    c1.conn
        .extensions()
        .get_ref::<MaxConcurrency>()
        .unwrap()
        .set(2);

    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("a MaxConcurrency increase should wake the parked waiter")
        .unwrap();
    assert!(woke.load(Ordering::Relaxed));
    // c1 is still held; the waiter admitted on the same connection, not a new one.
    assert_eq!(svc.inner.created.load(Ordering::Relaxed), 1);
}

/// A `MaxConcurrency` raise right after the parking poll wakes the waiter
/// without another wake source: it queued before its check.
#[tokio::test]
async fn maxconcurrency_increase_wakes_manually_driven_waiter() {
    let pool = MultiplexPool::evicting(10, 1);
    let svc = connector_with(pool.clone(), Some(1));

    // Connection A: at its advertised capacity of 1, holding the only slot.
    let c1 = svc.connect(ServiceInput::new(0u32)).await.unwrap();

    let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
    assert!(
        waiter.poll().is_pending(),
        "waiter must park: A is at capacity"
    );

    // Raise A's capacity: the connection wakes its lane's waiters.
    c1.conn
        .extensions()
        .get_ref::<MaxConcurrency>()
        .unwrap()
        .set(2);
    assert!(
        waiter.is_woken(),
        "a capacity raise must wake the parked waiter"
    );
    match waiter.poll() {
        Poll::Ready(Ok(ConnectionResult::Connection(_))) => {}
        other => panic!("waiter must admit on the raised capacity, got: {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn new_multiplexed_connection_wakes_waiters() {
    let pool = MultiplexPool::evicting(2, 1);
    let svc = PooledConnector::new(
        SlowConnector {
            created: AtomicUsize::new(0),
            delay: Duration::from_millis(100),
        },
        pool,
        id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
    )
    .with_wait_for_pool_timeout(Duration::from_millis(500));

    let c1 = svc.connect(ServiceInput::new(1u32)).await.unwrap();

    let waiter1 = svc.connect(ServiceInput::new(2u32));
    let waiter2 = svc.connect(ServiceInput::new(2u32));

    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(c1);

    let (r1, r2) = tokio::join!(waiter1, waiter2);
    assert!(r1.is_ok(), "first waiter should create a new connection");
    assert!(
        r2.is_ok(),
        "second waiter should reuse the spare stream slot"
    );
}

#[tokio::test]
async fn stream_release_wakes_a_waiter_for_the_matching_id() {
    let pool = MultiplexPool::evicting(2, 2);
    let svc = connector(pool.clone());

    let a1 = connect(&svc, 0).await;
    let a2 = connect(&svc, 0).await;
    let b1 = connect(&svc, 1).await;
    let b2 = connect(&svc, 1).await;
    assert_eq!(created(&svc), 2);

    // Register B first. A pool-global `notify_one` would wake this
    // incompatible waiter and strand A even though A gains capacity.
    let mut b_waiter = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT));
    assert!(b_waiter.poll().is_pending());
    let mut a_waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
    assert!(a_waiter.poll().is_pending());

    // A remains active, so only an A waiter can use the released stream;
    // the connection is not globally evictable.
    drop(a2);
    assert!(a_waiter.is_woken(), "the matching-ID waiter must wake");
    match a_waiter.poll() {
        Poll::Ready(Ok(ConnectionResult::Connection(_))) => {}
        other => panic!("matching-ID waiter did not reuse A: {other:?}"),
    }
    assert!(b_waiter.poll().is_pending());

    drop((a1, b1, b2));
}

#[tokio::test(start_paused = true)]
async fn saturation_waits_and_times_out() {
    let pool = MultiplexPool::evicting(1, 1);
    let svc = connector(pool).with_wait_for_pool_timeout(Duration::from_millis(50));

    let c1 = connect(&svc, 0).await;
    // connection full, no room to create -> get_conn waits, then times out
    let error = svc
        .connect(ServiceInput::new(0u32))
        .await
        .expect_err("saturated pool should time out");
    assert_eq!(error.domain(), ConnectionErrorDomain::Local);
    assert_eq!(error.kind(), ConnectionErrorKind::Timeout);

    drop(c1);
    // now a slot is free again
    let _c2 = connect(&svc, 0).await;
}

#[tokio::test]
async fn a_waiter_whose_request_changed_leaves_its_old_lane() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(2).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait);
    let one = add(&pool, 0, Some(keyed(0, 1))).await;
    let _two = add(&pool, 0, Some(keyed(0, 2))).await;
    let changing = want(1);
    let mut moved = queue(&pool, &changing);
    let staying = want(1);
    let mut behind = queue(&pool, &staying);
    changing.insert(Want(2));
    drop(one);
    // The front waiter of key 1 now wants key 2: it hands its wake on.
    assert!(moved.poll().is_pending(), "key 2's connection is busy");
    assert!(
        behind.is_woken(),
        "key 1's freed stream reaches its next waiter"
    );
    drop(handout(&mut behind));
    for lane in pool.storage.lock().by_id[&TestId(0)].lanes() {
        if !lane.waiters.is_empty() {
            assert_eq!(lane.waiters.unspent(), 0);
        }
    }
}

#[tokio::test]
async fn newcomers_queue_behind_waiters_of_several_lanes() {
    let pool = MultiplexPool::evicting(1, 2);
    let unrestricted = add(&pool, 0, None).await;
    let keyed_conn = add(&pool, 0, Some(keyed(0, 1))).await;
    let input = want(1);
    let mut waiter = queue(&pool, &input);
    drop(keyed_conn);
    let newcomer_input = want(1);
    let newcomer = queue(&pool, &newcomer_input);
    assert!(waiter.is_woken() && !newcomer.is_woken());
    drop((handout(&mut waiter), newcomer, unrestricted));
    assert_open_matches_capacity(&pool);
}

#[test]
fn a_wake_landing_during_a_look_is_passed_on_by_the_served_waiter() {
    let count = Arc::new(AtomicUsize::new(0));
    let slot_waiters = Arc::new(WaitQueue::new());
    let lane = Arc::new(WaitQueue::new());
    let mut waiting = Waiting::new(&count, &slot_waiters, None, 0);
    waiting.register(&lane);
    let behind = Party::new(1).waiter();
    lane.push(&behind);
    waiting.begin_look();
    // A unit frees in the lane while the look runs: the look began unwoken,
    // so serving it spends no wake of the lane.
    assert!(lane.wake_one());
    waiting.served(Some(lane.clone()));
    drop(waiting);
    assert!(
        behind.is_woken(),
        "the unit is still there for the next one"
    );
}

/// Notifies the pool from the request key derivation of look `at`.
#[derive(Debug, Clone)]
struct NotifyOnLook {
    notify: Arc<Notify>,
    looks: Arc<AtomicUsize>,
    at: Arc<AtomicUsize>,
}

impl ConnectionReusePolicy for NotifyOnLook {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<Self>(1))
    }

    fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
        if self.looks.fetch_add(1, Ordering::SeqCst) + 1 == self.at.load(Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
        Some(ReuseKey::from_bits::<Self>(1))
    }
}

#[tokio::test]
async fn a_notification_during_a_look_leads_to_another_look() {
    let pool = MultiplexPool::evicting(1, 1);
    let policy = NotifyOnLook {
        notify: pool.notify.clone(),
        looks: Arc::default(),
        at: Arc::new(AtomicUsize::new(usize::MAX)),
    };
    let held = add(&pool, 0, Some(ConnectionReuse::new(policy.clone()))).await;
    let before = policy.looks.load(Ordering::SeqCst);
    // A new connection or rekey announced while the waiting look runs: the
    // look before it waits (the fast one, then the first queued one).
    policy.at.store(before + 2, Ordering::SeqCst);
    let mut waiter = queue(&pool, &EMPTY_INPUT);
    assert_eq!(
        policy.looks.load(Ordering::SeqCst),
        before + 3,
        "the announcement was not lost between the look and the wait"
    );
    drop((held, waiter.poll()));
}

#[test]
fn a_cancellation_wave_through_the_slot_queue_stays_linear() {
    let count = Arc::new(AtomicUsize::new(0));
    let slot_waiters = Arc::new(WaitQueue::new());
    let lanes: Vec<_> = (0..256).map(|_| Arc::new(WaitQueue::new())).collect();
    // Each waits in its own lane and for a slot; each leave empties its lane.
    let waitings: Vec<_> = lanes
        .iter()
        .enumerate()
        .map(|(order, lane)| {
            let mut waiting = Waiting::new(&count, &slot_waiters, None, order as u64);
            waiting.register(lane);
            waiting.register_for_chances(&slot_waiters);
            waiting
        })
        .collect();
    let parties: Vec<_> = waitings
        .iter()
        .map(|waiting| waiting.party.clone())
        .collect();
    drop(waitings);
    let wakes: usize = parties.iter().map(|party| party.wakes()).sum();
    assert!(
        wakes <= 3 * lanes.len(),
        "{wakes} wakes for {} leaves",
        lanes.len()
    );
}
