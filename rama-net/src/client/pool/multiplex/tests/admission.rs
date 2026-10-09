//! Transport admission, pushed changes and work outliving its handouts.

use super::*;

#[tokio::test]
async fn a_freed_unit_wakes_one_waiter_and_other_changes_all() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 1);
    let held = pool
        .create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    let mut waiters = [(); 3].map(|()| queue(&pool, &EMPTY_INPUT));
    state.changed.notify(Change::Freed);
    assert!(
        waiters[0].is_woken() && !waiters[1].is_woken() && !waiters[2].is_woken(),
        "one unit, one wake"
    );
    assert!(waiters[0].poll().is_pending(), "nothing came free");
    state.changed.notify(Change::Other);
    assert!(
        waiters.iter().all(|waiter| waiter.is_woken()),
        "an uncounted change wakes the lane"
    );
    drop((waiters, held));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn admission_reserves_before_publication_and_releases_unused_handouts() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 0);
    let input = Extensions::new();
    let mut create = tokio_test::task::spawn(pool.create(TestId(0), conn, permit, &input));
    assert!(create.poll().is_pending());
    assert!(pool.storage.lock().by_id.is_empty());
    state.set_limit(1);
    assert!(create.is_woken());
    let Poll::Ready(Ok(first)) = create.poll() else {
        panic!("first credit must admit establishment")
    };
    assert_eq!(state.reserved.load(Ordering::SeqCst), 1);
    assert!(!input.contains::<ReservationToken>());
    let mut bound = input.clone();
    first.admission.as_ref().unwrap().bind(&mut bound);
    let token = bound.get_ref::<ReservationToken>().unwrap();
    assert!(token.0.upgrade().is_some());
    drop(first);
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    assert!(token.0.upgrade().is_none());
}

#[tokio::test]
async fn cloned_request_metadata_cannot_exchange_or_retain_handout_reservations() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 2);
    let shared = Extensions::new();
    let first = pool.create(TestId(0), conn, permit, &shared).await.unwrap();
    let ConnectionResult::Connection(second) =
        pool.get_conn(&TestId(0), &shared, None).await.unwrap()
    else {
        panic!("second reserved checkout")
    };
    assert_eq!(state.reserved.load(Ordering::SeqCst), 2);
    // Dispatch in reverse checkout order against clones of the same store.
    let second_metadata = second.serve(shared.clone()).await.unwrap();
    let first_metadata = first.serve(shared.clone()).await.unwrap();
    assert!(!shared.contains::<ReservationToken>());
    let a = &first_metadata.get_ref::<ReservationToken>().unwrap().0;
    let b = &second_metadata.get_ref::<ReservationToken>().unwrap().0;
    assert!(!Weak::ptr_eq(a, b));
    drop(first);
    assert!(
        a.upgrade().is_none(),
        "saved metadata must not own unused credit"
    );
    assert!(
        b.upgrade().is_some(),
        "other handout keeps its own reservation"
    );
    let second_again = second.serve(shared.clone()).await.unwrap();
    assert!(Weak::ptr_eq(
        b,
        &second_again.get_ref::<ReservationToken>().unwrap().0
    ));
    drop(second);
    assert!(b.upgrade().is_none());
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn admission_wakes_on_transport_credit_without_releasing_pool_handout() {
    for selection in [
        MuxSelection::FirstAvailable,
        MuxSelection::LeastLoaded,
        MuxSelection::RoundRobin,
    ] {
        let pool = MultiplexPool::evicting(32, 1).with_selection(selection);
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 1);
        let input = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
        let next_input = Extensions::new();
        let mut next = tokio_test::task::spawn(pool.get_conn(&TestId(0), &next_input, None));
        assert!(next.poll().is_pending());
        state.set_limit(2);
        assert!(next.is_woken());
        let Poll::Ready(Ok(ConnectionResult::Connection(second))) = next.poll() else {
            panic!("transport credit must wake saturated pool")
        };
        assert_eq!(state.reserved.load(Ordering::SeqCst), 2);
        drop((first, second));
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn work_outliving_its_handouts_keeps_a_connection_from_eviction() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    let input = Extensions::new();
    let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
    // An upgraded tunnel, say: the handout is gone, the connection is not idle.
    state.set_in_use(true);
    drop(first);

    let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT, None));
    assert!(other.poll().is_pending(), "a busy connection was evicted");
    assert!(pool.storage.lock().by_id.contains_key(&TestId(0)));

    state.set_in_use(false);
    assert!(
        other.is_woken(),
        "the end of that work must wake the waiter"
    );
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) = other.poll() else {
        panic!("the now idle connection must be evicted for the waiter")
    };
    assert!(pool.storage.lock().by_id.is_empty());
}

#[tokio::test]
async fn the_end_of_work_outliving_the_last_handout_is_an_eviction_chance() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    let input = Extensions::new();
    let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
    let mut leaving = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT, None));
    let mut staying = tokio_test::task::spawn(pool.get_conn(&TestId(2), &EMPTY_INPUT, None));
    assert!(leaving.poll().is_pending());
    assert!(staying.poll().is_pending());

    state.set_in_use(true);
    drop(first);
    assert!(
        !leaving.is_woken() && !staying.is_woken(),
        "still busy: nothing to evict"
    );
    drop(leaving);

    state.set_in_use(false);
    assert!(
        staying.is_woken(),
        "the connection announces the end of its work"
    );
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) = staying.poll() else {
        panic!("the now idle connection must be evicted for the remaining waiter")
    };
}

#[tokio::test]
async fn a_busy_connection_is_asked_again_only_after_a_change() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    let first = pool
        .create(TestId(0), conn, permit, &Extensions::new())
        .await
        .unwrap();
    state.set_in_use(true);
    drop(first);
    let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT, None));
    assert!(other.poll().is_pending(), "a busy connection was evicted");
    let asked = state.asked.load(Ordering::SeqCst);
    assert!(asked > 0);
    // Looks without a change of the connection do not ask again.
    for _ in 0..3 {
        pool.notify.notify_waiters();
        assert!(other.poll().is_pending());
    }
    assert_eq!(state.asked.load(Ordering::SeqCst), asked);
    state.set_in_use(false);
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) = other.poll() else {
        panic!("asked again after its change, the idle connection is evicted")
    };
    assert!(state.asked.load(Ordering::SeqCst) > asked);
}

#[tokio::test(start_paused = true)]
async fn work_outliving_its_handouts_keeps_a_connection_from_expiring() {
    let pool = MultiplexPool::evicting(32, 1).with_idle_timeout(Duration::from_micros(1));
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    let input = Extensions::new();
    let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
    state.set_in_use(true);
    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let Ok(ConnectionResult::Connection(reused)) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await
    else {
        panic!("a busy connection expired as idle")
    };
    drop(reused);
    state.set_in_use(false);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_matches!(
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await,
        Ok(ConnectionResult::CreatePermit(_))
    );
}

#[tokio::test(start_paused = true)]
async fn an_expired_connection_asked_outside_the_lock_frees_its_slot() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait)
        .with_idle_timeout(Duration::from_millis(30));
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    drop(
        pool.create(TestId(0), conn, permit, &Extensions::new())
            .await
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    // Only a sweep of all ids comes across it, and asks once it let go.
    let Ok(ConnectionResult::CreatePermit(_)) = pool.get_conn(&TestId(1), &EMPTY_INPUT, None).await
    else {
        panic!("its slot is free once it expired")
    };
    assert!(state.asked.load(Ordering::SeqCst) > 0);
    assert!(pool.storage.lock().by_id.is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_idle_clock_restarts_when_the_pool_sees_outliving_work() {
    let pool = MultiplexPool::evicting(32, 1).with_idle_timeout(Duration::from_millis(30));
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    let input = Extensions::new();
    let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
    state.set_in_use(true);
    drop(first);
    tokio::time::sleep(Duration::from_millis(40)).await;
    // A full pool sweeps every connection for another destination's request.
    let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT, None));
    assert!(other.poll().is_pending());
    drop(other);

    state.set_in_use(false);
    assert_matches!(
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await,
        Ok(ConnectionResult::Connection(_)),
        "work that just ended does not count as idle time"
    );
}

#[tokio::test(start_paused = true)]
async fn a_lookup_during_outliving_work_restarts_the_idle_clock() {
    let pool = MultiplexPool::evicting(32, 2).with_idle_timeout(Duration::from_millis(30));
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    let input = Extensions::new();
    let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
    state.set_in_use(true);
    drop(first);
    // Before the timeout, a lookup that cannot use the connection still sees its work.
    state.set_limit(0);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_matches!(
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await,
        Ok(ConnectionResult::CreatePermit(_))
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    state.set_in_use(false);
    state.set_limit(4);
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_matches!(
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await,
        Ok(ConnectionResult::Connection(_)),
        "idle for 5ms of a 30ms timeout"
    );
}

/// A connection forked from another one's metadata, a tunnel through it say, is admitted
/// by its own policy only, never the outer connection's.
#[tokio::test]
async fn admission_is_the_connections_own_not_an_ancestors() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (outer, state) = admission_connection(&pool, 0);
    let inner = Conn {
        serial: 2,
        extensions: outer.extensions.fork(),
    };
    let input = Extensions::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        pool.create(TestId(0), inner, permit, &input),
    )
    .await
    .expect("the outer connection's admission does not apply")
    .unwrap();
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
}

/// A saturated candidate that goes broken wakes its waiters, so they look again rather
/// than wait for its handouts.
#[tokio::test]
async fn a_saturated_candidate_going_broken_wakes_its_waiters() {
    let pool = MultiplexPool::evicting(1, 1);
    let svc = connector(pool);
    let held = connect(&svc, 0).await;
    let mut waiter = tokio_test::task::spawn(connect(&svc, 0));
    assert!(waiter.poll().is_pending());
    // Settle until it waits on nothing but the pool.
    for _ in 0..16 {
        if !waiter.is_woken() {
            break;
        }
        assert!(waiter.poll().is_pending());
    }
    assert!(!waiter.is_woken());
    held.conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    assert!(waiter.is_woken(), "a broken candidate woke nobody");
    assert!(
        waiter.poll().is_pending(),
        "its handout still holds the slot"
    );
    drop(held);
    assert!(waiter.is_woken());
    assert!(waiter.poll().is_ready());
}

#[tokio::test]
async fn admission_failure_does_not_publish_or_leak_new_connection_slot() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 1);
    state.failed.store(true, Ordering::SeqCst);
    let error = pool
        .create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "admission failed");
    assert!(pool.storage.lock().by_id.is_empty());
    assert_eq!(pool.free_slots(), 1);
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn admission_cancellation_before_publication_releases_create_permit() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 0);
    let mut create = tokio_test::task::spawn(pool.create(TestId(0), conn, permit, &EMPTY_INPUT));
    assert!(create.poll().is_pending());
    drop(create);
    assert!(pool.storage.lock().by_id.is_empty());
    assert_eq!(pool.free_slots(), 1);
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn pool_timeout_also_bounds_fresh_transport_admission() {
    let pool = MultiplexPool::evicting(32, 1);
    let (_, state) = admission_connection(&pool, 0);
    let connector_state = state.clone();
    let inner = service_fn(move |input: ServiceInput<u32>| {
        let state = connector_state.clone();
        async move {
            let conn = Conn {
                serial: 1,
                extensions: Extensions::new(),
            };
            conn.extensions
                .insert(ConnectionAdmission::new(FakeAdmission(state)));
            Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
        }
    });
    let client = PooledConnector::new(
        inner,
        pool.clone(),
        id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
    )
    .with_wait_for_pool_timeout(Duration::from_secs(1));
    let error = client.connect(ServiceInput::new(0)).await.unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::Timeout);
    assert!(pool.storage.lock().by_id.is_empty());
    assert_eq!(pool.free_slots(), 1);
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn admission_failure_on_cached_connection_tries_another_candidate() {
    for selection in [
        MuxSelection::FirstAvailable,
        MuxSelection::LeastLoaded,
        MuxSelection::RoundRobin,
    ] {
        let pool = MultiplexPool::evicting(32, 2).with_selection(selection);
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 1);
        let first = pool
            .create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap();
        let permit = new_slot(&pool).await;
        let second = pool
            .create(
                TestId(0),
                Conn {
                    serial: 2,
                    extensions: Extensions::new(),
                },
                permit,
                &EMPTY_INPUT,
            )
            .await
            .unwrap();
        drop((first, second));
        state.failed.store(true, Ordering::SeqCst);
        let ConnectionResult::Connection(next) =
            pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
        else {
            panic!("healthy candidate must be reused")
        };
        assert_eq!(next.serve(ServiceInput::new(())).await.unwrap(), 2);
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn admission_returns_reserved_credit_when_connection_closes_during_reservation() {
    #[derive(Debug)]
    struct CloseDuringAdmission {
        inner: FakeAdmission,
        enabled: Arc<AtomicBool>,
        health: Arc<ConnectionHealthWatcher>,
    }

    impl ConnectionAdmissionPolicy for CloseDuringAdmission {
        fn try_acquire(
            &self,
            input: &Extensions,
        ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
            let reservation = self.inner.try_acquire(input)?;
            if self.enabled.load(Ordering::SeqCst) {
                self.health.mark_broken();
            }
            Ok(reservation)
        }

        fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
            self.inner.subscribe(listener);
        }

        fn in_use(&self) -> bool {
            self.inner.in_use()
        }
    }

    let pool = MultiplexPool::evicting(32, 2);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 2);
    let health = Arc::new(ConnectionHealthWatcher::default());
    let enabled = Arc::new(AtomicBool::new(false));
    conn.extensions.insert_arc(health.clone());
    conn.extensions
        .insert(ConnectionAdmission::new(CloseDuringAdmission {
            inner: FakeAdmission(state.clone()),
            enabled: enabled.clone(),
            health,
        }));
    let first = pool
        .create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    enabled.store(true, Ordering::SeqCst);
    let permit = new_slot(&pool).await;
    assert_eq!(
        state.reserved.load(Ordering::SeqCst),
        1,
        "rejected reservation must be returned"
    );
    drop((permit, first));
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn admission_failure_on_only_cached_connection_returns_fresh_slot() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 1);
    drop(
        pool.create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap(),
    );
    state.failed.store(true, Ordering::SeqCst);
    let permit = new_slot(&pool).await;
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    drop(permit);
    assert_eq!(pool.free_slots(), 1);
}

#[tokio::test]
async fn concurrent_pool_checkouts_cannot_oversubscribe_transport_credit() {
    let pool = MultiplexPool::evicting(32, 1);
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    let first = pool
        .create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    let inputs: Vec<_> = (0..16).map(|_| Extensions::new()).collect();
    let mut pending: Vec<_> = inputs
        .iter()
        .map(|input| tokio_test::task::spawn(pool.get_conn(&TestId(0), input, None)))
        .collect();
    let mut admitted = vec![first];
    for waiter in &mut pending {
        if let Poll::Ready(Ok(ConnectionResult::Connection(conn))) = waiter.poll() {
            admitted.push(conn);
        }
    }
    assert_eq!(admitted.len(), 4);
    assert_eq!(state.reserved.load(Ordering::SeqCst), 4);
    drop(pending);
    drop(admitted);
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn exclusive_pool_replaces_connection_with_exhausted_transport_credit() {
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let state = Arc::new(AdmissionState {
        limit: AtomicUsize::new(1),
        reserved: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        in_use: AtomicBool::new(false),
        asked: AtomicUsize::new(0),
        changed: ChangeSignal::new(),
        storage: Weak::new(),
    });
    let conn = Conn {
        serial: 1,
        extensions: Extensions::new(),
    };
    conn.extensions
        .insert(ConnectionAdmission::new(FakeAdmission(state.clone())));
    let ConnectionResult::CreatePermit(permit) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("new connection required")
    };
    let input = Extensions::new();
    let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
    assert_eq!(state.reserved.load(Ordering::SeqCst), 1);
    drop(first);
    assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    state.set_limit(0);
    assert_matches!(
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap(),
        ConnectionResult::CreatePermit(_),
    );
}

#[derive(Debug, Extension)]
struct Binding;

/// Credit that a dispatch already moved into the protocol's own count:
/// dropping a handout returns nothing, so nothing is pushed for it.
#[derive(Debug, Default)]
struct Busy {
    in_use: AtomicBool,
    changed: ChangeSignal,
}

#[derive(Debug)]
struct BusyAdmission(Arc<Busy>);

impl ConnectionAdmissionPolicy for BusyAdmission {
    fn try_acquire(&self, _: &Extensions) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        Ok(Some(ConnectionAdmissionLease::new(Arc::new(()), Binding)))
    }

    fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        self.0.changed.subscribe(listener);
    }

    fn in_use(&self) -> bool {
        self.0.in_use.load(Ordering::SeqCst)
    }
}

/// An admission source that records being called while it notifies.
#[derive(Debug, Default)]
struct Probe {
    in_use: AtomicBool,
    notifying: AtomicBool,
    reentered: AtomicBool,
    changed: ChangeSignal,
}

impl Probe {
    fn notify(&self) {
        self.notifying.store(true, Ordering::SeqCst);
        self.changed.notify(Change::Other);
        self.notifying.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct ProbeAdmission(Arc<Probe>);

impl ConnectionAdmissionPolicy for ProbeAdmission {
    fn try_acquire(&self, _: &Extensions) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        Ok(Some(ConnectionAdmissionLease::new(Arc::new(()), Binding)))
    }

    fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        self.0.changed.subscribe(listener);
    }

    fn in_use(&self) -> bool {
        if self.0.notifying.load(Ordering::SeqCst) {
            self.0.reentered.store(true, Ordering::SeqCst);
        }
        self.0.in_use.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn a_source_notification_never_calls_back_into_the_source() {
    let pool = MultiplexPool::evicting(2, 1);
    let permit = new_slot(&pool).await;
    let probe = Arc::new(Probe::default());
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions
        .insert(ConnectionAdmission::new(ProbeAdmission(probe.clone())));
    let first = pool
        .create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    probe.in_use.store(true, Ordering::SeqCst);
    drop(first);
    let other_input = Extensions::new();
    let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &other_input, None));
    assert!(other.poll().is_pending(), "busy: nothing to evict");
    probe.in_use.store(false, Ordering::SeqCst);
    probe.notify();
    assert!(
        !probe.reentered.load(Ordering::SeqCst),
        "a listener only wakes"
    );
    assert!(
        other.is_woken(),
        "the end of the work is an eviction chance"
    );
    assert!(matches!(
        other.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn a_release_wakes_its_lane_and_not_an_eviction_waiter() {
    let pool = MultiplexPool::evicting(2, 1);
    let permit = new_slot(&pool).await;
    let busy = Arc::new(Busy::default());
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions
        .insert(ConnectionAdmission::new(BusyAdmission(busy.clone())));
    let first = pool
        .create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    // Work outlives the handout: the connection is not idle, so not
    // evictable, and a waiter of another id waits for it to become so.
    busy.in_use.store(true, Ordering::SeqCst);
    drop(first);
    let other_input = Extensions::new();
    let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &other_input, None));
    assert!(other.poll().is_pending());
    let ConnectionResult::Connection(a) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("a free stream");
    };
    let ConnectionResult::Connection(b) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("a free stream");
    };
    let mut same = queue(&pool, &EMPTY_INPUT);
    if other.is_woken() {
        assert!(other.poll().is_pending());
    }
    drop(b);
    assert!(
        same.is_woken(),
        "the freed stream wakes the waiter of its lane"
    );
    drop(handout(&mut same));
    drop((a, other));
}

#[tokio::test(start_paused = true)]
async fn idle_limits_never_close_a_connection_with_outliving_work() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(4).unwrap())
        .with_max_idle_per_id(NonZeroUsize::new(1).unwrap());
    let permit = pool.test_slot();
    let (conn, state) = admission_connection(&pool, 4);
    let tunnel = pool
        .create(TestId(0), conn, permit, &Extensions::new())
        .await
        .unwrap();
    state.set_in_use(true);
    drop(tunnel);
    for slot in [pool.test_slot(), pool.test_slot()] {
        let conn = Conn {
            serial: 2,
            extensions: Extensions::new(),
        };
        drop(
            pool.create(TestId(0), conn, slot, &Extensions::new())
                .await
                .unwrap(),
        );
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    let storage = pool.storage.lock();
    let serials: Vec<_> = storage.by_id[&TestId(0)]
        .conns()
        .map(|conn| conn.conn.serial)
        .collect();
    assert_eq!(
        serials,
        [1, 2],
        "the busy one stays, the extra idle one goes"
    );
}

#[tokio::test(start_paused = true)]
async fn outliving_work_seen_uncounts_a_connection_from_the_idle_limits() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(4).unwrap())
        .with_max_idle_total(NonZeroUsize::new(1).unwrap());
    let (conn, state) = admission_connection(&pool, 4);
    let tunnel = pool
        .create(TestId(0), conn, pool.test_slot(), &Extensions::new())
        .await
        .unwrap();
    state.set_in_use(true);
    drop(tunnel);
    // A change of its source counts it idle until it is asked.
    state.set_limit(4);
    tokio::time::advance(Duration::from_millis(1)).await;
    let other = Conn {
        serial: 2,
        extensions: Extensions::new(),
    };
    drop(
        pool.create(TestId(1), other, pool.test_slot(), &Extensions::new())
            .await
            .unwrap(),
    );
    assert_eq!(
        pool.storage.lock().by_id.len(),
        2,
        "the busy one is not idle, so one idle connection is within the limit"
    );
}

#[tokio::test(start_paused = true)]
async fn the_exact_path_hands_out_no_connection_past_the_idle_timeout() {
    let pool = MultiplexPool::evicting(32, 1).with_idle_timeout(Duration::from_millis(30));
    let permit = new_slot(&pool).await;
    let (conn, state) = admission_connection(&pool, 4);
    drop(
        pool.create(TestId(0), conn, permit, &Extensions::new())
            .await
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    let lanes = pool.request_lanes(&TestId(0), &EMPTY_INPUT);
    let mut swept = Swept::default();
    let snapshot = pool.snapshot(
        &mut pool.storage.lock(),
        &TestId(0),
        &lanes,
        &mut swept,
        &mut Look::New,
    );
    assert!(
        snapshot.is_empty(),
        "its admission is asked first, without the lock"
    );
    pool.settle(swept);
    assert!(state.asked.load(Ordering::SeqCst) > 0);
    assert!(pool.storage.lock().by_id.is_empty());
}

#[tokio::test(start_paused = true)]
async fn outliving_work_ending_trims_over_the_idle_limits() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(8).unwrap())
        .with_max_idle_total(NonZeroUsize::new(1).unwrap());
    let mut states = Vec::new();
    for id in 0..4 {
        let (conn, state) = admission_connection(&pool, 4);
        let tunnel = pool
            .create(TestId(id), conn, pool.test_slot(), &Extensions::new())
            .await
            .unwrap();
        state.set_in_use(true);
        drop(tunnel);
        states.push(state);
    }
    assert_eq!(pool.storage.lock().by_id.len(), 4, "all busy");
    for state in &states {
        state.set_in_use(false);
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    // The listener trims from a task of its own.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let storage = pool.storage.lock();
    assert_eq!(storage.by_id.len(), 1, "one idle connection is the limit");
    assert!(
        storage.by_id.contains_key(&TestId(3)),
        "the most recently used"
    );
}
