//! A burst on a multiplexed lane waits for the connects in flight: it opens
//! the connections it needs, in one handshake, not one each.

use super::*;
use rama_core::futures::future::join_all;

const HANDSHAKE: Duration = Duration::from_millis(100);

/// Establishes a connection per call after a handshake (`step` longer for
/// each dial), each taking `streams` streams if set, kept by none if
/// `kept_by_none`, filed under the `key` it says; or fails as `fail` says.
struct Dialer {
    dials: AtomicUsize,
    streams: Option<usize>,
    kept_by_none: bool,
    fail: fn(&Extensions) -> Option<ConnectionError>,
    key: fn(&Extensions) -> Option<u8>,
    handshake: Duration,
    step: Duration,
}

impl Dialer {
    fn new(streams: Option<usize>) -> Self {
        Self {
            dials: AtomicUsize::new(0),
            streams,
            kept_by_none: false,
            fail: |_| None,
            key: |_| None,
            handshake: HANDSHAKE,
            step: Duration::ZERO,
        }
    }
}

impl Service<ServiceInput<u32>> for Dialer {
    type Output = EstablishedClientConnection<Conn, ServiceInput<u32>>;
    type Error = ConnectionError;

    async fn serve(&self, input: ServiceInput<u32>) -> Result<Self::Output, Self::Error> {
        let serial = self.dials.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(self.handshake + self.step * serial as u32).await;
        if let Some(error) = (self.fail)(&input.extensions) {
            return Err(error);
        }
        let conn = Conn {
            serial,
            extensions: Extensions::new(),
        };
        conn.extensions.insert(ConnectionHealthWatcher::default());
        if let Some(streams) = self.streams {
            conn.extensions.insert(MaxConcurrency::new(streams));
        }
        if self.kept_by_none {
            conn.extensions.insert(kept_by_none());
        }
        if let Some(key) = (self.key)(&input.extensions) {
            conn.extensions.insert(keyed(0, key));
        }
        Ok(EstablishedClientConnection { input, conn })
    }
}

type Dialing = PooledConnector<
    Dialer,
    MultiplexPool<Conn, TestId>,
    fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
>;

type Handout = EstablishedClientConnection<MultiplexedConnection<Conn, TestId>, ServiceInput<u32>>;

fn dialing(pool: MultiplexPool<Conn, TestId>, dialer: Dialer) -> Dialing {
    PooledConnector::new(
        dialer,
        pool,
        id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
    )
}

fn dials(svc: &Dialing) -> usize {
    svc.inner.dials.load(Ordering::Relaxed)
}

/// `n` handouts of `id`, held, one after the other.
async fn hold(svc: &Dialing, id: u32, n: usize) -> Vec<Handout> {
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        held.push(svc.connect(ServiceInput::new(id)).await.unwrap());
    }
    held
}

/// `n` checkouts of `id` at once, all served.
async fn burst(svc: &Dialing, id: u32, n: usize) -> Vec<Handout> {
    join_all((0..n).map(|_| svc.connect(ServiceInput::new(id))))
        .await
        .into_iter()
        .map(|result| result.expect("every checkout of the burst is served"))
        .collect()
}

/// Any request of the pool expects connections of `STREAMS`.
fn expect_ten(_: &TestId, _: &Extensions) -> Option<NonZeroUsize> {
    NonZeroUsize::new(10)
}

/// Requirements of a connection that must not be retained.
fn kept_by_none() -> ConnectionReuse {
    ConnectionReuse::new(KeyPolicy {
        key: None,
        class: 1,
    })
}

/// The create permit of a checkout of `id` that dials at once.
async fn permit(pool: &MultiplexPool<Conn, TestId>, id: u32, input: &Extensions) -> MultiplexSlot {
    match pool.get_conn(&TestId(id), input, None).await.unwrap() {
        ConnectionResult::CreatePermit(slot) => slot,
        ConnectionResult::Connection(_) => panic!("expected a create permit"),
    }
}

/// A connection of `id` taking `streams`, published with `reuse`, created with `slot`.
async fn land(
    pool: &MultiplexPool<Conn, TestId>,
    id: u32,
    slot: MultiplexSlot,
    streams: usize,
    reuse: Option<ConnectionReuse>,
    input: &Extensions,
) -> MultiplexedConnection<Conn, TestId> {
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(streams));
    if let Some(reuse) = reuse {
        conn.extensions.insert(reuse);
    }
    pool.create(TestId(id), conn, slot, input).await.unwrap()
}

/// Break `conn` and hand it back: the pool lets it go.
fn close(conn: MultiplexedConnection<Conn, TestId>) {
    conn.inner
        .conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    drop(conn);
}

fn refused() -> ConnectionError {
    ConnectionError::transport(
        BoxError::from_static_str("refused"),
        ConnectionErrorKind::Unavailable,
    )
}

#[tokio::test(start_paused = true)]
async fn a_burst_on_a_full_connection_waits_for_one_new_connection() {
    let svc = dialing(MultiplexPool::new(), Dialer::new(Some(10)));
    let _held = hold(&svc, 0, 10).await;
    assert_eq!(dials(&svc), 1);
    let _burst = burst(&svc, 0, 8).await;
    assert_eq!(dials(&svc), 2, "one new connection takes the burst");
}

#[tokio::test(start_paused = true)]
async fn a_burst_opens_the_connections_it_needs_in_one_handshake() {
    let svc = dialing(MultiplexPool::new(), Dialer::new(Some(3)));
    let _held = hold(&svc, 0, 3).await;
    let start = tokio::time::Instant::now();
    let _burst = burst(&svc, 0, 8).await;
    assert!(start.elapsed() < HANDSHAKE * 2, "all dialed at once");
    assert_eq!(dials(&svc) - 1, 3, "8 checkouts of 3 streams each");
}

#[tokio::test(start_paused = true)]
async fn connections_of_one_stream_are_dialed_per_checkout() {
    let svc = dialing(MultiplexPool::new(), Dialer::new(Some(1)));
    let _held = hold(&svc, 0, 1).await;
    let _burst = burst(&svc, 0, 8).await;
    assert_eq!(dials(&svc), 9, "nothing to share");
}

#[tokio::test(start_paused = true)]
async fn a_burst_on_a_new_id_dials_per_checkout_without_a_hint() {
    let svc = dialing(MultiplexPool::new(), Dialer::new(Some(10)));
    let _burst = burst(&svc, 0, 8).await;
    assert_eq!(dials(&svc), 8, "the protocol may not multiplex");
}

#[tokio::test(start_paused = true)]
async fn a_cap_on_connecting_dials_a_cold_http1_burst_a_few_at_a_time() {
    for patience in [None, Some(Duration::from_millis(10))] {
        let pool = MultiplexPool::new()
            .with_max_connecting_per_id(NonZeroUsize::new(2).unwrap())
            .maybe_with_max_wait_before_dial(patience);
        let svc = dialing(pool, Dialer::new(Some(1)));
        let start = tokio::time::Instant::now();
        let _burst = burst(&svc, 0, 8).await;
        assert_eq!(dials(&svc), 8, "one connection per checkout");
        assert!(
            start.elapsed() >= HANDSHAKE * 4 && start.elapsed() < HANDSHAKE * 5,
            "two at a time, also once done waiting: {:?}",
            start.elapsed()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn an_http1_burst_within_the_cap_on_connecting_dials_at_once() {
    let pool = MultiplexPool::new()
        .with_max_connecting_per_id(NonZeroUsize::new(6).unwrap())
        .with_idle_timeout(Duration::from_secs(1));
    let svc = dialing(pool, Dialer::new(Some(1)));
    let start = tokio::time::Instant::now();
    drop(burst(&svc, 0, 6).await);
    assert!(
        start.elapsed() < HANDSHAKE * 2,
        "a cold id: one handshake, {:?}",
        start.elapsed()
    );
    // Gone, its one stream each learned.
    tokio::time::advance(Duration::from_secs(2)).await;
    drop(svc.connect(ServiceInput::new(1)).await.unwrap());
    assert!(!svc.pool.storage.lock().by_id.contains_key(&TestId(0)));
    let start = tokio::time::Instant::now();
    drop(burst(&svc, 0, 6).await);
    assert!(
        start.elapsed() < HANDSHAKE * 2,
        "a learned id: one handshake, {:?}",
        start.elapsed()
    );
    assert_eq!(dials(&svc), 13);
}

#[tokio::test(start_paused = true)]
async fn a_cap_on_connecting_binds_connects_whose_landings_serve_nobody_else() {
    // One stream each, and many, of which a landing serves only its dialer.
    for streams in [1, 10] {
        let pool = MultiplexPool::new()
            .with_streams_hint(expect_ten)
            .with_max_connecting_per_id(NonZeroUsize::new(2).unwrap());
        let mut dialer = Dialer::new(Some(streams));
        dialer.kept_by_none = true;
        let svc = dialing(pool, dialer);
        drop(svc.connect(ServiceInput::new(0)).await.unwrap());
        let start = tokio::time::Instant::now();
        let _burst = burst(&svc, 0, 8).await;
        assert_eq!(dials(&svc), 9);
        assert!(
            start.elapsed() >= HANDSHAKE * 4 && start.elapsed() < HANDSHAKE * 5,
            "{streams} streams: still two at a time, {:?}",
            start.elapsed()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_checkout_held_by_the_cap_past_its_dial_deadline_sleeps() {
    let pool = MultiplexPool::<Conn, TestId>::new()
        .with_max_connecting_per_id(NonZeroUsize::new(1).unwrap());
    let ConnectionResult::CreatePermit(dialing) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("the first dials");
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1);
    let mut capped = tokio_test::task::spawn(Box::pin(pool.get_conn(
        &TestId(0),
        &EMPTY_INPUT,
        Some(deadline),
    )));
    assert!(capped.poll().is_pending(), "held by the cap");
    tokio::time::advance(Duration::from_millis(5)).await;
    for _ in 0..4 {
        assert!(capped.poll().is_pending(), "still capped");
        tokio::task::yield_now().await;
    }
    assert!(
        !capped.is_woken(),
        "its spent patience does not keep it looking"
    );
    drop((capped, dialing));
}

#[tokio::test(start_paused = true)]
async fn a_cap_on_connecting_binds_a_hinted_cold_burst() {
    let pool = MultiplexPool::new()
        .with_streams_hint(expect_ten)
        .with_max_connecting_per_id(NonZeroUsize::new(1).unwrap());
    let svc = dialing(pool, Dialer::new(Some(1)));
    let start = tokio::time::Instant::now();
    let _burst = burst(&svc, 0, 3).await;
    assert_eq!(dials(&svc), 3);
    assert!(start.elapsed() >= HANDSHAKE * 3, "one at a time");
}

#[tokio::test(start_paused = true)]
async fn a_burst_on_a_new_id_waits_for_a_hinted_connection() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let svc = dialing(pool, Dialer::new(Some(10)));
    let _burst = burst(&svc, 0, 8).await;
    assert_eq!(dials(&svc), 1);
}

#[tokio::test(start_paused = true)]
async fn the_first_connection_corrects_a_hint_that_was_too_high() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let svc = dialing(pool, Dialer::new(Some(3)));
    let start = tokio::time::Instant::now();
    let _burst = burst(&svc, 0, 8).await;
    assert_eq!(dials(&svc), 3, "8 checkouts of 3 streams each");
    assert!(
        start.elapsed() < HANDSHAKE * 3,
        "the rest dialed at once, once the first showed its streams"
    );
}

#[tokio::test(start_paused = true)]
async fn a_connection_taking_no_stream_is_not_waited_for() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let svc = dialing(pool, Dialer::new(Some(0)));
    let first = svc.connect(ServiceInput::new(0)).await.unwrap();
    let second = svc.connect(ServiceInput::new(0)).await.unwrap();
    drop((first, second));
    assert_eq!(dials(&svc), 2);
}

#[tokio::test(start_paused = true)]
async fn an_id_dials_as_its_last_connection_took_once_it_has_none() {
    let pool = MultiplexPool::new().with_idle_timeout(Duration::from_secs(1));
    let svc = dialing(pool, Dialer::new(Some(10)));
    drop(hold(&svc, 0, 1).await);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _burst = burst(&svc, 0, 8).await;
    assert_eq!(
        dials(&svc),
        2,
        "the expired connection's streams are the guess"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failed_connect_fails_the_checkouts_that_waited_for_it() {
    let pool = MultiplexPool::new();
    let seed = dialing(pool.clone(), Dialer::new(Some(4)));
    let _held = hold(&seed, 0, 4).await;
    let mut dialer = Dialer::new(Some(4));
    dialer.fail = |_| Some(refused());
    let svc = dialing(pool, dialer);
    let results = join_all((0..4).map(|_| svc.connect(ServiceInput::new(0)))).await;
    for result in &results {
        let error = result
            .as_ref()
            .expect_err("the connect they waited for failed");
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }
    assert_eq!(dials(&svc), 1, "they fail with it, without dialing again");
}

#[tokio::test(start_paused = true)]
async fn a_checkout_waits_for_a_slow_connect_no_longer_than_its_patience() {
    let pool = MultiplexPool::new().with_max_wait_before_dial(HANDSHAKE / 2);
    let seed = dialing(pool.clone(), Dialer::new(Some(4)));
    let _held = hold(&seed, 0, 4).await;
    let mut slow = Dialer::new(Some(4));
    slow.handshake = HANDSHAKE * 10;
    let slow = dialing(pool.clone(), slow);
    let mut stuck = tokio_test::task::spawn(slow.connect(ServiceInput::new(0)));
    assert!(stuck.poll().is_pending(), "dialing");
    let start = tokio::time::Instant::now();
    let served = seed.connect(ServiceInput::new(0)).await.unwrap();
    assert!(start.elapsed() < HANDSHAKE * 2, "it dialed its own");
    drop((served, stuck));
}

#[tokio::test]
async fn a_cancelled_checkout_leaves_nothing_in_flight_or_waiting() {
    let pool = MultiplexPool::new();
    let svc = dialing(pool.clone(), Dialer::new(Some(4)));
    let held = hold(&svc, 0, 4).await;
    let mut dialing = tokio_test::task::spawn(Box::pin(svc.connect(ServiceInput::new(0))));
    assert!(dialing.poll().is_pending());
    let mut waiting = tokio_test::task::spawn(Box::pin(svc.connect(ServiceInput::new(0))));
    assert!(waiting.poll().is_pending());
    drop(waiting);
    drop(dialing);
    let storage = pool.storage.lock();
    let connects = &storage.connects[&TestId(0)];
    assert!(connects.iter().all(|connects| connects.is_unused()));
    drop((storage, held));
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_connect_hands_the_checkouts_that_waited_for_it_a_dial_of_their_own() {
    let svc = dialing(MultiplexPool::new(), Dialer::new(Some(4)));
    let _held = hold(&svc, 0, 4).await;
    let before = dials(&svc);
    let mut dialing = tokio_test::task::spawn(Box::pin(svc.connect(ServiceInput::new(0))));
    assert!(dialing.poll().is_pending(), "dialing");
    let mut waiting = tokio_test::task::spawn(Box::pin(svc.connect(ServiceInput::new(0))));
    assert!(
        waiting.poll().is_pending(),
        "waits for the connect in flight"
    );
    assert_eq!(dials(&svc), before + 1, "one connect in flight for both");
    drop(dialing);
    let served = tokio::time::timeout(HANDSHAKE * 2, waiting)
        .await
        .expect("no checkout is left waiting on a cancelled connect")
        .unwrap();
    assert_eq!(dials(&svc), before + 2, "the waiter dialed its own");
    drop(served);
}

#[tokio::test(start_paused = true)]
async fn checkouts_of_a_connection_kept_by_none_never_wait() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let svc = dialing(pool, Dialer::new(Some(10)));
    let _burst = burst(&svc, u32::MAX, 4).await;
    assert_eq!(
        dials(&svc),
        4,
        "an id not reused leaves nothing to wait for"
    );
}

#[tokio::test(start_paused = true)]
async fn a_lowered_limit_sizes_the_next_burst() {
    let svc = dialing(MultiplexPool::new(), Dialer::new(Some(3)));
    let first = svc.connect(ServiceInput::new(0)).await.unwrap();
    first
        .conn
        .extensions()
        .get_arc::<MaxConcurrency>()
        .unwrap()
        .set(100);
    let _held = (first, hold(&svc, 0, 99).await);
    // The peer allows 3 streams per connection now.
    let newest = svc.connect(ServiceInput::new(0)).await.unwrap();
    let before = dials(&svc);
    let start = tokio::time::Instant::now();
    let _burst = burst(&svc, 0, 8).await;
    assert!(
        start.elapsed() < HANDSHAKE * 2,
        "sized by the newest connection"
    );
    assert_eq!(
        dials(&svc) - before,
        2,
        "2 spare streams on the newest, 6 more on 2 new"
    );
    drop(newest);
}

#[tokio::test(start_paused = true)]
async fn a_guess_dials_a_few_connects_before_a_connection_shows_its_streams() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let svc = dialing(pool, Dialer::new(Some(10)));
    let early = async {
        tokio::time::sleep(HANDSHAKE / 2).await;
        dials(&svc)
    };
    let (served, early) = tokio::join!(burst(&svc, 0, 30), early);
    assert_eq!(early, 2, "a guess opens no burst of connects");
    assert_eq!(served.len(), 30);
    assert_eq!(dials(&svc), 3, "30 checkouts of 10 streams each");
}

#[tokio::test(start_paused = true)]
async fn checkouts_that_waited_for_a_guess_dial_their_own_once_it_takes_one_stream() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let svc = dialing(pool, Dialer::new(Some(1)));
    let _burst = burst(&svc, 0, 4).await;
    assert_eq!(dials(&svc), 4, "the guess was wrong: one connection each");
}

#[tokio::test(start_paused = true)]
async fn checkouts_that_waited_dial_their_own_once_a_connection_lands_with_one_stream() {
    let pool = MultiplexPool::new();
    let seed = dialing(pool.clone(), Dialer::new(Some(4)));
    let _held = hold(&seed, 0, 4).await;
    // The next connection negotiates a protocol that does not multiplex.
    let svc = dialing(pool, Dialer::new(Some(1)));
    let _burst = burst(&svc, 0, 4).await;
    assert_eq!(
        dials(&svc),
        4,
        "one connection each, once the first shows it"
    );
}

#[tokio::test(start_paused = true)]
async fn a_new_id_expecting_to_multiplex_takes_what_other_ids_took() {
    // The hint expects 10, the pool's connections take 4.
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let svc = dialing(pool, Dialer::new(Some(4)));
    drop(hold(&svc, 0, 1).await);
    let before = dials(&svc);
    let start = tokio::time::Instant::now();
    let _burst = burst(&svc, 1, 8).await;
    assert_eq!(dials(&svc) - before, 2, "8 checkouts of 4 streams each");
    assert!(start.elapsed() < HANDSHAKE * 2, "dialed at once");
}

#[tokio::test]
async fn a_connection_kept_by_none_wakes_the_checkouts_that_waited_for_it() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    let held = land(&pool, 0, slot, 10, Some(kept_by_none()), &EMPTY_INPUT).await;
    assert!(!held.inner.filed.load(Ordering::Relaxed), "kept by none");
    assert!(first.is_woken(), "its streams reach none of them");
    assert!(matches!(
        first.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
    assert!(second.is_woken(), "the wake is passed on");
    assert!(
        matches!(
            second.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "dials without waiting for the first"
    );
}

#[tokio::test]
async fn a_connection_filed_for_other_keys_wakes_the_checkouts_that_waited_for_it() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let slot = permit(&pool, 0, &want(2)).await;
    let mut full = vec![land(&pool, 0, slot, 10, Some(keyed(0, 2)), &want(2)).await];
    for _ in 1..10 {
        let ConnectionResult::Connection(conn) =
            pool.get_conn(&TestId(0), &want(2), None).await.unwrap()
        else {
            panic!("a stream of the first connection");
        };
        full.push(conn);
    }
    let input = want(1);
    let slot = permit(&pool, 0, &input).await;
    let mut waiter = queue(&pool, &input);
    // The connector files the connection under a key the request did not ask for.
    full.push(land(&pool, 0, slot, 10, Some(keyed(0, 2)), &input).await);
    assert!(waiter.is_woken(), "its streams reach none of them");
    assert!(
        matches!(
            waiter.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "it dials its own"
    );
}

#[tokio::test(start_paused = true)]
async fn a_burst_on_connections_kept_by_none_dials_at_once_once_one_shows_it() {
    let mut dialer = Dialer::new(Some(10));
    dialer.kept_by_none = true;
    let svc = dialing(MultiplexPool::new().with_streams_hint(expect_ten), dialer);
    let start = tokio::time::Instant::now();
    let _burst = tokio::time::timeout(HANDSHAKE * 10, burst(&svc, 0, 8))
        .await
        .expect("no checkout is left waiting");
    assert_eq!(dials(&svc), 8, "one connection each");
    assert!(start.elapsed() < HANDSHAKE * 3, "the rest dialed at once");
}

#[tokio::test]
async fn checkouts_left_by_a_connection_kept_by_none_all_wait_for_slots() {
    let pool = MultiplexPool::new()
        .with_streams_hint(expect_ten)
        .with_max_connections_total(NonZeroUsize::new(2).unwrap());
    let other = fresh(&pool, 1).await;
    let slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    let kept = land(&pool, 0, slot, 10, Some(kept_by_none()), &EMPTY_INPUT).await;
    assert!(first.poll().is_pending(), "at the total limit");
    assert!(
        second.is_woken(),
        "the wake it left for a slot is passed on"
    );
    assert!(second.poll().is_pending(), "at the total limit");
    drop(kept);
    assert!(matches!(
        first.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
    close(other);
    assert!(
        matches!(
            second.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "each got a slot"
    );
}

#[tokio::test]
async fn a_claim_moves_with_its_checkout_to_other_keys() {
    let pool = MultiplexPool::new()
        .with_streams_hint(expect_ten)
        .with_max_connections_total(NonZeroUsize::new(2).unwrap());
    let slot = permit(&pool, 0, &want(0)).await;
    let _seed = land(&pool, 0, slot, 10, Some(keyed(0, 0)), &want(0)).await;
    let other = fresh(&pool, 1).await;
    let moving = want(1);
    let mut claimant = queue(&pool, &moving);
    let staying = want(1);
    let mut waiter = queue(&pool, &staying);
    moving.insert(Want(2));
    close(other);
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = claimant.poll() else {
        panic!("the freed slot is the claimant's");
    };
    assert!(waiter.is_woken(), "nothing is dialed for its keys anymore");
    pool.abandon(slot, &refused());
    assert!(
        matches!(
            waiter.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "another key's connect failing is not its failure: it dials"
    );
}

#[tokio::test]
async fn connects_of_keys_no_checkout_uses_are_forgotten() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let slot = permit(&pool, 0, &want(0)).await;
    let _seed = land(&pool, 0, slot, 10, Some(keyed(0, 0)), &want(0)).await;
    for key in 1..=u8::MAX {
        drop(permit(&pool, 0, &want(key)).await);
    }
    let storage = pool.storage.lock();
    let kept = storage.connects[&TestId(0)].len();
    assert!(kept <= 2, "{kept} connects of unused keys kept");
}

/// The pool whose checkout the request is, for a streams hint to use.
#[derive(Debug, Clone, Extension)]
struct HintPool(MultiplexPool<Conn, TestId>);

fn hint_using_the_pool(_: &TestId, input: &Extensions) -> Option<NonZeroUsize> {
    if let Some(HintPool(pool)) = input.get_ref::<HintPool>() {
        assert!(
            pool.storage.try_lock_for(Duration::from_secs(1)).is_some(),
            "the hint runs outside the pool's lock"
        );
        let mut nested = std::pin::pin!(pool.get_conn(&TestId(1), &EMPTY_INPUT, None));
        let polled = nested
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
        assert!(polled.is_ready(), "a checkout of the hint is served");
    }
    NonZeroUsize::new(10)
}

#[tokio::test]
async fn the_streams_hint_may_use_the_pool() {
    let pool = MultiplexPool::new().with_streams_hint(hint_using_the_pool);
    let input = Extensions::new();
    input.insert(HintPool(pool.clone()));
    drop(permit(&pool, 0, &input).await);
}

/// A request of id 0 wanting `key`.
fn wanting(key: u8) -> ServiceInput<u32> {
    let input = ServiceInput::new(0);
    input.extensions.insert(Want(key));
    input
}

fn want_key(input: &Extensions) -> Option<u8> {
    input.get_ref::<Want>().map(|want| want.0)
}

#[tokio::test(start_paused = true)]
async fn a_down_endpoint_fails_a_burst_in_one_handshake() {
    let pool = MultiplexPool::new();
    let seed = dialing(pool.clone(), Dialer::new(Some(4)));
    let _held = hold(&seed, 0, 4).await;
    let mut down = Dialer::new(Some(4));
    down.fail = |_| Some(refused());
    down.step = Duration::from_millis(1);
    let svc = dialing(pool, down);
    let start = tokio::time::Instant::now();
    let results = join_all((0..12).map(|_| svc.connect(ServiceInput::new(0)))).await;
    assert!(results.iter().all(Result::is_err));
    assert!(
        start.elapsed() < HANDSHAKE * 2,
        "no waiter waits for another dial to fail"
    );
}

#[tokio::test(start_paused = true)]
async fn steady_load_on_a_down_endpoint_fails_with_its_error() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let mut down = Dialer::new(Some(10));
    down.fail = |_| Some(refused());
    down.step = Duration::from_micros(50);
    let svc = dialing(pool, down).with_wait_for_pool_timeout(Duration::from_secs(1));
    let results = join_all((0..400u32).map(|at| {
        let svc = &svc;
        async move {
            tokio::time::sleep(Duration::from_millis(5) * at).await;
            let start = tokio::time::Instant::now();
            let kind = svc
                .connect(ServiceInput::new(0))
                .await
                .err()
                .map(|error| error.kind());
            (kind, start.elapsed())
        }
    }))
    .await;
    for (kind, took) in results {
        assert_eq!(
            kind,
            Some(ConnectionErrorKind::Unavailable),
            "the endpoint's error"
        );
        assert!(took < HANDSHAKE * 3, "failed after {took:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_request_scoped_failure_fails_no_other_request() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let mut dialer = Dialer::new(Some(10));
    // A request-specific policy the peer rejects: only requests wanting key 1.
    dialer.fail = |input| {
        (want_key(input) == Some(1)).then(|| {
            ConnectionError::application(
                BoxError::from_static_str("request pin rejected"),
                ConnectionErrorKind::Authentication,
            )
            .with_policy_scope(ConnectionPolicyScope::Request)
        })
    };
    dialer.key = want_key;
    let svc = dialing(pool, dialer);
    let (rejected, other) = tokio::join!(svc.connect(wanting(1)), svc.connect(wanting(2)));
    assert_eq!(
        rejected.map(drop).map_err(|error| error.kind()),
        Err(ConnectionErrorKind::Authentication),
        "its own policy failed"
    );
    assert!(other.is_ok(), "it dials its own");
}

#[tokio::test(start_paused = true)]
async fn a_cold_id_groups_its_requests_by_the_keys_it_had() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let mut dialer = Dialer::new(Some(10));
    dialer.key = want_key;
    let svc = dialing(pool.clone(), dialer);
    close(svc.connect(wanting(1)).await.unwrap().conn);
    // A look takes the closed connection out, and the id's bucket with it.
    drop(pool.get_conn(&TestId(0), &want(1), None).await.unwrap());
    assert!(pool.storage.lock().by_id.is_empty(), "the id is cold");
    let start = tokio::time::Instant::now();
    let (one, two) = tokio::join!(svc.connect(wanting(1)), svc.connect(wanting(2)));
    assert!(one.is_ok() && two.is_ok());
    assert!(
        start.elapsed() < HANDSHAKE * 2,
        "neither waited for the other's connection"
    );
}

#[tokio::test(start_paused = true)]
async fn a_burst_of_each_key_dials_its_own_connects_at_once() {
    let pool = MultiplexPool::new();
    let mut dialer = Dialer::new(Some(10));
    dialer.key = want_key;
    let svc = dialing(pool, dialer);
    let _seed = svc.connect(wanting(0)).await.unwrap();
    let start = tokio::time::Instant::now();
    let served = join_all((0..6).map(|n| svc.connect(wanting(1 + n % 2)))).await;
    assert!(served.iter().all(Result::is_ok));
    assert_eq!(dials(&svc), 3, "one connection per key");
    assert!(start.elapsed() < HANDSHAKE * 2, "both keys dialed at once");
}

#[tokio::test(start_paused = true)]
async fn a_checkout_waiting_for_a_connect_dials_its_own_before_the_pool_timeout() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let svc = dialing(pool, Dialer::new(Some(10))).with_wait_for_pool_timeout(HANDSHAKE / 2);
    let results = join_all((0..4).map(|_| svc.connect(ServiceInput::new(0)))).await;
    assert!(
        results.iter().all(Result::is_ok),
        "waiting for another's handshake is no wait for the pool"
    );
}

#[tokio::test(start_paused = true)]
async fn a_checkout_waiting_for_connects_leaves_its_ids_slot_to_them() {
    let pool = MultiplexPool::new().with_max_connections_per_id(NonZeroUsize::new(1).unwrap());
    let ConnectionResult::CreatePermit(slot) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("an empty pool");
    };
    let (conn, _admission) = admission_connection(&pool, 1);
    let max = Arc::new(MaxConcurrency::new(1));
    conn.extensions.insert_arc(max.clone());
    conn.extensions.insert(ConnectionHealthWatcher::default());
    let only = pool
        .create(TestId(0), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap();
    let mut first = checkout(&pool, 0);
    assert!(
        first.poll().is_pending(),
        "at the id's limit, dialing uncounted"
    );
    // The peer allows two streams, its admission still one.
    max.set(2);
    let mut second = checkout(&pool, 0);
    assert!(
        second.poll().is_pending(),
        "counts a connect, at the id's limit"
    );
    assert!(first.poll().is_pending(), "waits for that connect");
    close(only);
    let either = [first.poll(), second.poll()];
    assert!(
        either
            .iter()
            .any(|polled| matches!(polled, Poll::Ready(Ok(ConnectionResult::CreatePermit(_))))),
        "the freed slot dials the connect they wait for"
    );
}

#[tokio::test]
async fn a_checkout_is_not_failed_by_a_failure_from_before_it_waited() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut failed = queue(&pool, &EMPTY_INPUT);
    pool.abandon(slot, &refused());
    assert!(matches!(failed.poll(), Poll::Ready(Err(_))));
    let _slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut later = queue(&pool, &EMPTY_INPUT);
    assert!(
        later.poll().is_pending(),
        "it waits for the new connect, not failed by the old"
    );
}

#[tokio::test]
async fn a_checkout_that_saw_a_connect_land_is_not_failed_by_the_next() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let first = permit(&pool, 0, &EMPTY_INPUT).await;
    let second = pool
        .count_connect(&TestId(0), &EMPTY_INPUT, None)
        .expect("counted");
    let mut served = queue(&pool, &EMPTY_INPUT);
    let mut waiting = queue(&pool, &EMPTY_INPUT);
    let _held = land(&pool, 0, first, 2, None, &EMPTY_INPUT).await;
    let Poll::Ready(Ok(ConnectionResult::Connection(_served))) = served.poll() else {
        panic!("the spare stream");
    };
    assert!(waiting.poll().is_pending(), "the second connect is for it");
    second.failed(&refused());
    assert!(
        matches!(
            waiting.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "the endpoint is up: it dials"
    );
}

#[tokio::test]
async fn a_new_connection_wakes_no_checkout_of_other_ids() {
    let pool = MultiplexPool::new()
        .with_streams_hint(expect_ten)
        .with_max_connections_total(NonZeroUsize::new(4).unwrap());
    let _first = add(&pool, 0, None).await;
    let _slot = permit(&pool, 1, &EMPTY_INPUT).await;
    let other = queue_keyed(&pool, 1, &EMPTY_INPUT);
    let _second = add(&pool, 0, None).await;
    assert!(!other.is_woken(), "nothing for it");
}

/// Tasks through coalescing on a multi-thread runtime, with dials that fail or
/// are dropped, cancelled checkouts, a peer changing its streams and
/// connections going away: nothing stalls, nothing is left behind.
async fn churn(pool: MultiplexPool<Conn, TestId>, keyed: bool) {
    const IDS: u32 = 3;
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }
    let max: Arc<[Arc<MaxConcurrency>]> =
        (0..IDS).map(|_| Arc::new(MaxConcurrency::new(4))).collect();
    let tasks: Vec<_> = (0..32_u64)
        .map(|task| {
            let (pool, max) = (pool.clone(), max.clone());
            tokio::spawn(async move {
                let mut rng =
                    0x9e37_79b9_7f4a_7c15 ^ (task + 1).wrapping_mul(0x2545_f491_4f6c_dd1d);
                for _ in 0..64 {
                    let roll = next(&mut rng);
                    let id = (roll % u64::from(IDS)) as u32;
                    let key = keyed.then(|| 1 + ((roll >> 4) % 2) as u8);
                    let input = key.map_or_else(Extensions::new, want);
                    let max = &max[id as usize];
                    if (roll >> 32).is_multiple_of(13) {
                        max.set(1 + ((roll >> 40) % 3) as usize);
                    }
                    let handout = churn_one(&pool, id, &input, key, next(&mut rng), max).await;
                    for _ in 0..(roll >> 48) % 8 {
                        tokio::task::yield_now().await;
                    }
                    if let Some(handout) = handout
                        && (roll >> 52).is_multiple_of(6)
                    {
                        close(handout);
                    }
                }
            })
        })
        .collect();
    tokio::time::timeout(Duration::from_secs(10), async {
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .expect("no checkout stalls");
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
    let storage = pool.storage.lock();
    for connects in storage.connects.values().flatten() {
        assert!(connects.is_unused(), "nothing left in flight or queued");
    }
    drop(storage);
    assert_open_matches_capacity(&pool);
}

/// One checkout as a connector drives it: cancelled after a few polls, or its
/// create permit abandoned, dropped or created with.
async fn churn_one(
    pool: &MultiplexPool<Conn, TestId>,
    id: u32,
    input: &Extensions,
    key: Option<u8>,
    roll: u64,
    max: &Arc<MaxConcurrency>,
) -> Option<MultiplexedConnection<Conn, TestId>> {
    let test_id = TestId(id);
    let mut checkout = std::pin::pin!(pool.get_conn(&test_id, input, None));
    let result = if roll.is_multiple_of(8) {
        let mut polls = (roll >> 8) % 4;
        loop {
            match rama_core::futures::poll!(checkout.as_mut()) {
                Poll::Ready(result) => break result,
                Poll::Pending if polls == 0 => return None,
                Poll::Pending => {
                    polls -= 1;
                    tokio::task::yield_now().await;
                }
            }
        }
    } else {
        checkout.await
    };
    let slot = match result.ok()? {
        ConnectionResult::Connection(conn) => return Some(conn),
        ConnectionResult::CreatePermit(slot) => slot,
    };
    for _ in 0..(roll >> 16) % 3 {
        tokio::task::yield_now().await;
    }
    match (roll >> 24) % 9 {
        0 | 1 => {
            pool.abandon(slot, &refused());
            return None;
        }
        2 => return None,
        _ => {}
    }
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    if (roll >> 28).is_multiple_of(2) {
        conn.extensions.insert_arc(max.clone());
    } else {
        conn.extensions.insert(MaxConcurrency::new(max.get()));
    }
    if let Some(key) = key {
        conn.extensions.insert(keyed(0, key));
    }
    pool.create(TestId(id), conn, slot, input).await.ok()
}

fn hint_four(_: &TestId, _: &Extensions) -> Option<NonZeroUsize> {
    NonZeroUsize::new(4)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn churn_coalescing_unlimited() {
    churn(MultiplexPool::new().with_streams_hint(hint_four), false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn churn_coalescing_at_limits() {
    let pool = MultiplexPool::new()
        .with_streams_hint(hint_four)
        .with_max_connections_total(NonZeroUsize::new(5).unwrap())
        .with_max_connections_per_id(NonZeroUsize::new(2).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdle);
    churn(pool, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn churn_coalescing_keyed_with_expiry() {
    let pool = MultiplexPool::new()
        .with_streams_hint(hint_four)
        .with_max_connections_total(NonZeroUsize::new(8).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdle)
        .with_idle_timeout(Duration::from_micros(200));
    churn(pool, true).await;
}

#[tokio::test]
async fn a_connection_refusing_its_first_stream_ends_its_connect_as_a_failure() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    let (conn, state) = admission_connection(&pool, 10);
    state.failed.store(true, Ordering::SeqCst);
    let _refused = pool
        .create(TestId(0), conn, slot, &EMPTY_INPUT)
        .await
        .expect_err("its admission refused the stream");
    // Not a failure their requests share: each dials its own, none waits for another.
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(_dialing))) = first.poll() else {
        panic!("it dials");
    };
    assert!(second.is_woken(), "told as well");
    assert!(matches!(
        second.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

/// A connection of `id` admitting one stream however many its peer allows,
/// held: its peer's allowance is `max`.
async fn admitting_one(
    pool: &MultiplexPool<Conn, TestId>,
    id: u32,
) -> (MultiplexedConnection<Conn, TestId>, Arc<MaxConcurrency>) {
    let slot = permit(pool, id, &EMPTY_INPUT).await;
    let (conn, _admission) = admission_connection(pool, 1);
    let max = Arc::new(MaxConcurrency::new(1));
    conn.extensions.insert_arc(max.clone());
    conn.extensions.insert(ConnectionHealthWatcher::default());
    let held = pool
        .create(TestId(id), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap();
    (held, max)
}

#[tokio::test]
async fn a_checkout_behind_woken_waiters_leaves_them_the_free_streams() {
    let pool = MultiplexPool::new();
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(4));
    let slot = new_slot(&pool).await;
    let mut held = vec![
        pool.create(TestId(0), conn, slot, &EMPTY_INPUT)
            .await
            .unwrap(),
    ];
    for _ in 0..3 {
        let Ok(ConnectionResult::Connection(handout)) =
            pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await
        else {
            panic!("a stream of the connection");
        };
        held.push(handout);
    }
    let ConnectionResult::CreatePermit(dialing) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("every stream is held: a connect");
    };
    let mut first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    held.truncate(1);
    drop(dialing);
    assert!(first.is_woken() && second.is_woken());
    // Nothing in flight: what the woken ones leave serves the newcomer.
    let mut third = checkout(&pool, 0);
    assert!(
        third.poll().is_pending(),
        "three streams free for three: no connect"
    );
    for waiter in [&mut first, &mut second, &mut third] {
        assert_eq!(serial_of(&handout(waiter)).await, 0);
    }
}

#[tokio::test]
async fn refused_room_costs_the_waiters_behind_a_round_not_a_stall() {
    let pool = MultiplexPool::new();
    // Room for three streams, as far as its peer goes, but it admits one.
    let slot = new_slot(&pool).await;
    let (conn, _admission) = admission_connection(&pool, 1);
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(3));
    let _held = pool
        .create(TestId(0), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap();
    let ConnectionResult::CreatePermit(dialing) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("refused: a connect");
    };
    let mut front = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    // Three waiting, one connect for two of them in flight, and the room the
    // front was refused counted for the third.
    let mut third = checkout(&pool, 0);
    assert!(third.poll().is_pending());
    let _landed = land(&pool, 0, dialing, 3, None, &EMPTY_INPUT).await;
    let _served = [handout(&mut front), handout(&mut second)];
    assert!(third.is_woken(), "the room left is its to try");
    assert!(
        matches!(
            third.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "refused, nothing in flight: it dials"
    );
}

/// Id 0 with a full connection of four streams, a connect in flight and a
/// waiter for it: as the connect lands with four streams, its dialer takes one
/// and the waiter is woken for one.
async fn landing_for_a_waiter<'a>(
    pool: &'a MultiplexPool<Conn, TestId>,
    held: &mut Vec<MultiplexedConnection<Conn, TestId>>,
) -> Checkout<'a> {
    let slot = permit(pool, 0, &EMPTY_INPUT).await;
    held.push(land(pool, 0, slot, 4, None, &EMPTY_INPUT).await);
    held.extend(hold_more(pool, &EMPTY_INPUT, 3).await);
    let dialing = permit(pool, 0, &EMPTY_INPUT).await;
    let front = queue(pool, &EMPTY_INPUT);
    held.push(land(pool, 0, dialing, 4, None, &EMPTY_INPUT).await);
    assert!(front.is_woken(), "the landing wakes the front");
    front
}

/// `n` more handouts of id 0 on what is stored.
async fn hold_more(
    pool: &MultiplexPool<Conn, TestId>,
    input: &Extensions,
    n: usize,
) -> Vec<MultiplexedConnection<Conn, TestId>> {
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        let Ok(ConnectionResult::Connection(handout)) =
            pool.get_conn(&TestId(0), input, None).await
        else {
            panic!("a stream of what is stored");
        };
        held.push(handout);
    }
    held
}

#[tokio::test(start_paused = true)]
async fn a_served_waiter_passes_the_streams_left_to_it_on() {
    let pool = MultiplexPool::new();
    let mut held = Vec::new();
    let mut front = landing_for_a_waiter(&pool, &mut held).await;
    let mut newcomer = checkout(&pool, 0);
    assert!(
        newcomer.poll().is_pending(),
        "leaves the woken front the free streams"
    );
    held.push(handout(&mut front));
    assert!(newcomer.is_woken(), "two streams left: its turn");
    held.push(handout(&mut newcomer));
}

#[tokio::test(start_paused = true)]
async fn room_is_passed_on_once_the_woken_ones_ahead_are_served() {
    let pool = MultiplexPool::new();
    let slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut held = vec![land(&pool, 0, slot, 4, None, &EMPTY_INPUT).await];
    held.extend(hold_more(&pool, &EMPTY_INPUT, 3).await);
    let dialing = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut first = queue(&pool, &EMPTY_INPUT);
    let mut second = queue(&pool, &EMPTY_INPUT);
    held.push(land(&pool, 0, dialing, 4, None, &EMPTY_INPUT).await);
    assert!(
        first.is_woken() && second.is_woken(),
        "three streams for two"
    );
    let mut third = checkout(&pool, 0);
    assert!(third.poll().is_pending(), "the third stream is kept for it");
    held.push(handout(&mut first));
    assert!(!third.is_woken(), "the woken second goes first");
    held.push(handout(&mut second));
    assert!(third.is_woken(), "its turn");
    held.push(handout(&mut third));
}

#[tokio::test]
async fn room_a_change_shows_reaches_the_waiters_arriving_after_it() {
    let pool = MultiplexPool::new();
    let slot = new_slot(&pool).await;
    let (conn, admission) = admission_connection(&pool, 1);
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(4));
    let _held = pool
        .create(TestId(0), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap();
    let _slow_dial = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut front = queue(&pool, &EMPTY_INPUT);
    // A change of unknown size wakes each waiter once: the front only.
    admission.set_limit(4);
    assert!(front.is_woken());
    let mut followers: Vec<_> = (0..4).map(|_| checkout(&pool, 0)).collect();
    for follower in &mut followers {
        assert!(
            follower.poll().is_pending(),
            "the free streams are counted: no dial"
        );
    }
    let mut served = vec![handout(&mut front)];
    for follower in &mut followers[..2] {
        assert!(follower.is_woken(), "the room left is passed on");
        served.push(handout(follower));
    }
    assert!(
        !followers[2].is_woken(),
        "no room left: the rest wait for the dial"
    );
}

#[tokio::test(start_paused = true)]
async fn kept_streams_count_free_streams_not_capacity() {
    let pool = MultiplexPool::new();
    let mut held = Vec::new();
    let mut front = landing_for_a_waiter(&pool, &mut held).await;
    // Two streams free past the woken front's: the third newcomer dials.
    let mut newcomers: Vec<_> = (0..3).map(|_| checkout(&pool, 0)).collect();
    assert!(newcomers[0].poll().is_pending());
    assert!(newcomers[1].poll().is_pending());
    assert!(matches!(
        newcomers[2].poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
    held.push(handout(&mut front));
    held.push(handout(&mut newcomers[0]));
    held.push(handout(&mut newcomers[1]));
}

#[tokio::test(start_paused = true)]
async fn a_waiter_served_in_another_lane_passes_its_wake_in_the_group_lane_on() {
    let pool = MultiplexPool::new();
    let one = want(1);
    // The unrestricted lane: the oldest connection, one stream, held.
    let slot = permit(&pool, 0, &one).await;
    let unrestricted = land(&pool, 0, slot, 1, None, &one).await;
    let unrestricted_seq = unrestricted.inner.seq;
    // A keyed connection gives the id its only class.
    let nine = want(9);
    let slot = permit(&pool, 0, &nine).await;
    let _keyed = land(&pool, 0, slot, 1, Some(keyed(0, 9)), &nine).await;
    // Key 1's lane, full, and a connect for it landing with two to spare.
    let slot = permit(&pool, 0, &one).await;
    let mut held = vec![land(&pool, 0, slot, 2, Some(keyed(0, 1)), &one).await];
    held.extend(hold_more(&pool, &one, 1).await);
    let dialing = permit(&pool, 0, &one).await;
    let mut waiter = queue_keyed(&pool, 0, &one);
    held.push(land(&pool, 0, dialing, 3, Some(keyed(0, 1)), &one).await);
    assert!(waiter.is_woken(), "the landing wakes it in key 1's lane");
    let mut newcomer = tokio_test::task::spawn(Box::pin(pool.get_conn(&TestId(0), &one, None)));
    assert!(newcomer.poll().is_pending(), "leaves it the free streams");
    drop(unrestricted);
    let served = handout(&mut waiter);
    assert_eq!(
        served.inner.seq, unrestricted_seq,
        "served in the other lane"
    );
    assert!(newcomer.is_woken(), "its wake in key 1's lane is passed on");
    assert!(matches!(
        newcomer.poll(),
        Poll::Ready(Ok(ConnectionResult::Connection(_)))
    ));
}

#[tokio::test(start_paused = true)]
async fn a_skipped_lane_of_other_connect_groups_keeps_nothing() {
    let pool = MultiplexPool::new();
    let (one, two, nine) = (want(1), want(2), want(9));
    let slot = permit(&pool, 0, &two).await;
    let mut held = vec![land(&pool, 0, slot, 2, None, &two).await];
    held.extend(hold_more(&pool, &two, 1).await);
    let slot = permit(&pool, 0, &nine).await;
    held.push(land(&pool, 0, slot, 1, Some(keyed(0, 9)), &nine).await);
    // A waiter of key 2 ahead in the unrestricted lane, its connect in flight.
    let _dialing_two = permit(&pool, 0, &two).await;
    let _two_waits = queue_keyed(&pool, 0, &two);
    // Key 1's lane: room for three streams as far as its peer goes, admits one.
    let slot = permit(&pool, 0, &one).await;
    let (conn, _admission) = admission_connection(&pool, 1);
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(3));
    conn.extensions.insert(keyed(0, 1));
    held.push(pool.create(TestId(0), conn, slot, &one).await.unwrap());
    let mut front = tokio_test::task::spawn(Box::pin(pool.get_conn(&TestId(0), &one, None)));
    assert!(
        matches!(
            front.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "refused in its own lane, nothing in flight for key 1: it dials"
    );
}

#[tokio::test]
async fn a_look_counting_on_kept_streams_wakes_a_front_left_unwoken() {
    let pool = MultiplexPool::new();
    // One lane: an exclusive connection, older, and one with room for four
    // streams as far as its peer goes that admits one; both held.
    let slot = new_slot(&pool).await;
    let exclusive = land(&pool, 0, slot, 1, None, &EMPTY_INPUT).await;
    let slot = new_slot(&pool).await;
    let (conn, _admission) = admission_connection(&pool, 1);
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(4));
    let _refusing = pool
        .create(TestId(0), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap();
    // A connect in flight brings three spare streams: three wait for it, none
    // counting on kept streams.
    let _slow = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut waiters: Vec<_> = (0..3).map(|_| queue(&pool, &EMPTY_INPUT)).collect();
    drop(exclusive);
    // Served by the exclusive connection before the pool kept any streams: it
    // passes nothing on.
    let _served = handout(&mut waiters[0]);
    assert!(!waiters[1].is_woken());
    let mut newcomers: Vec<_> = (0..2).map(|_| checkout(&pool, 0)).collect();
    for newcomer in &mut newcomers {
        assert!(newcomer.poll().is_pending());
    }
    assert!(
        waiters[1].is_woken(),
        "the look counting on the refused room wakes the front to try it"
    );
    assert!(
        matches!(
            waiters[1].poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "refused, more waiting than the connect in flight serves: it dials"
    );
}

/// A connection that admits one of its two streams, held, a connect in flight
/// with one spare stream, and a waiter for it that a change woke and that
/// looked: refused, it waits. The pool may have kept streams before.
async fn refused_front<'a>(
    pool: &'a MultiplexPool<Conn, TestId>,
    input: &'a Extensions,
    reuse: Option<ConnectionReuse>,
) -> (
    Checkout<'a>,
    MultiplexSlot,
    MultiplexedConnection<Conn, TestId>,
) {
    let slot = permit(pool, 0, input).await;
    let (conn, admission) = admission_connection(pool, 1);
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(2));
    if let Some(reuse) = reuse {
        conn.extensions.insert(reuse);
    }
    let held = pool.create(TestId(0), conn, slot, input).await.unwrap();
    let slow = permit(pool, 0, input).await;
    let mut front = tokio_test::task::spawn(Box::pin(pool.get_conn(&TestId(0), input, None))
        as Pin<Box<dyn Future<Output = _> + Send + 'a>>);
    assert!(front.poll().is_pending());
    admission.set_limit(1);
    assert!(front.is_woken(), "a change wakes it");
    assert!(
        front.poll().is_pending(),
        "refused, the connect in flight covers it"
    );
    (front, slow, held)
}

#[tokio::test(start_paused = true)]
async fn a_count_on_kept_streams_wakes_the_front_whenever_it_holds_no_wake() {
    for kept_before in [false, true] {
        let pool = MultiplexPool::new();
        if kept_before {
            pool.kept_counted.store(true, Ordering::Relaxed);
        }
        let (mut front, _slow, _held) = refused_front(&pool, &EMPTY_INPUT, None).await;
        let mut newcomer = checkout(&pool, 0);
        assert!(
            newcomer.poll().is_pending(),
            "counts the refused stream as kept"
        );
        assert!(
            front.is_woken(),
            "the count wakes the front to try it again"
        );
        assert!(
            matches!(
                front.poll(),
                Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
            ),
            "refused, two waiting for one spare stream: it dials"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_count_on_kept_streams_wakes_the_front_of_its_keyed_group_lane() {
    let pool = MultiplexPool::new();
    let (one, nine) = (want(1), want(9));
    // The id's only class, from a keyed connection; no unrestricted lane.
    let slot = permit(&pool, 0, &nine).await;
    let _keyed = land(&pool, 0, slot, 1, Some(keyed(0, 9)), &nine).await;
    let (mut front, _slow, _held) = refused_front(&pool, &one, Some(keyed(0, 1))).await;
    let mut newcomer = tokio_test::task::spawn(Box::pin(pool.get_conn(&TestId(0), &one, None)));
    assert!(newcomer.poll().is_pending());
    assert!(front.is_woken(), "the front of key 1's lane");
    assert!(matches!(
        front.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

/// A lane with a connection that has room for three streams as far as its peer
/// goes but admits one, held, and a connect in flight with two spare streams.
async fn refusing_lane(
    pool: &MultiplexPool<Conn, TestId>,
) -> (MultiplexSlot, MultiplexedConnection<Conn, TestId>) {
    let slot = permit(pool, 0, &EMPTY_INPUT).await;
    let (conn, _admission) = admission_connection(pool, 1);
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(3));
    let held = pool
        .create(TestId(0), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap();
    (permit(pool, 0, &EMPTY_INPUT).await, held)
}

/// Whether one of `waiters`, polled, dials.
fn one_dials(waiters: &mut [Checkout<'_>]) -> bool {
    waiters.iter_mut().any(|waiter| {
        matches!(
            waiter.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        )
    })
}

#[tokio::test(start_paused = true)]
async fn an_unwoken_front_woken_by_a_count_and_cancelled_passes_the_wake_on() {
    let pool = MultiplexPool::new();
    let (_slow, _held) = refusing_lane(&pool).await;
    let front = queue(&pool, &EMPTY_INPUT);
    assert!(!front.is_woken());
    let mut newcomers: Vec<_> = (0..3).map(|_| checkout(&pool, 0)).collect();
    for newcomer in &mut newcomers {
        assert!(newcomer.poll().is_pending());
    }
    assert!(front.is_woken(), "a count on the refused streams wakes it");
    drop(front);
    assert!(newcomers[0].is_woken(), "its wake reaches the new front");
    assert!(
        one_dials(&mut newcomers),
        "three waiting for two spare streams: one dials"
    );
}

#[tokio::test(start_paused = true)]
async fn room_kept_beside_an_exclusive_service_is_passed_on() {
    let pool = MultiplexPool::new();
    // An exclusive connection, older, in the same lane, held.
    let slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let exclusive = land(&pool, 0, slot, 1, None, &EMPTY_INPUT).await;
    let (_slow, _held) = refusing_lane(&pool).await;
    let mut front = queue(&pool, &EMPTY_INPUT);
    drop(exclusive);
    assert!(
        front.is_woken(),
        "the exclusive connection's release wakes it"
    );
    let mut newcomers: Vec<_> = (0..3).map(|_| checkout(&pool, 0)).collect();
    for newcomer in &mut newcomers {
        assert!(newcomer.poll().is_pending());
    }
    let served = handout(&mut front);
    assert_eq!(
        served.inner.effective_capacity(usize::MAX),
        1,
        "served by the exclusive connection"
    );
    assert!(
        newcomers.iter().any(|newcomer| newcomer.is_woken()),
        "the room kept beside it is passed on"
    );
    assert!(
        one_dials(&mut newcomers),
        "three waiting for two spare streams: one dials"
    );
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_woken_front_passes_its_wake_on() {
    let pool = MultiplexPool::new();
    let mut held = Vec::new();
    let front = landing_for_a_waiter(&pool, &mut held).await;
    let mut newcomer = checkout(&pool, 0);
    assert!(newcomer.poll().is_pending());
    drop(front);
    assert!(newcomer.is_woken(), "the cancelled front's wake reaches it");
    held.push(handout(&mut newcomer));
}

#[tokio::test(start_paused = true)]
async fn streams_left_on_a_refusing_connection_wake_the_next_to_dial() {
    let pool = MultiplexPool::new();
    // Room for three streams, as far as its peer goes, but it admits one.
    let slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let (conn, _admission) = admission_connection(&pool, 1);
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(3));
    let _held = pool
        .create(TestId(0), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap();
    let dialing = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut front = queue(&pool, &EMPTY_INPUT);
    let _landed = land(&pool, 0, dialing, 2, None, &EMPTY_INPUT).await;
    assert!(front.is_woken());
    let mut newcomer = checkout(&pool, 0);
    assert!(
        newcomer.poll().is_pending(),
        "leaves the woken front the free streams"
    );
    let _served = handout(&mut front);
    assert!(newcomer.is_woken(), "the streams left are its to try");
    assert!(
        matches!(
            newcomer.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "refused, nothing in flight: it dials"
    );
}

#[tokio::test(start_paused = true)]
async fn streams_kept_for_another_keys_waiter_are_not_counted() {
    let pool = MultiplexPool::new();
    // A keyed connection gives the id its class: requests derive keys, and
    // those of keys 1 and 2 share the unrestricted lane, each its own connects.
    let keyed_slot = permit(&pool, 0, &want(9)).await;
    let _keyed = land(&pool, 0, keyed_slot, 1, Some(keyed(0, 9)), &want(9)).await;
    let (two, one) = (want(2), want(1));
    let slot = permit(&pool, 0, &two).await;
    let mut held = vec![land(&pool, 0, slot, 2, None, &two).await];
    held.extend(hold_more(&pool, &two, 1).await);
    let dialing = permit(&pool, 0, &two).await;
    let mut front = queue_keyed(&pool, 0, &two);
    held.push(land(&pool, 0, dialing, 2, None, &two).await);
    assert!(front.is_woken(), "the landing wakes the front of key 2");
    let mut newcomer = tokio_test::task::spawn(Box::pin(pool.get_conn(&TestId(0), &one, None)));
    assert!(
        matches!(
            newcomer.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "the free stream is key 2's, nothing in flight for key 1: it dials"
    );
    held.push(handout(&mut front));
}

#[tokio::test]
async fn a_checkout_waiting_for_connects_gives_back_the_ids_slot_it_held() {
    let pool = MultiplexPool::new()
        .with_max_connections_per_id(NonZeroUsize::new(2).unwrap())
        .with_max_connections_total(NonZeroUsize::new(2).unwrap());
    let (_only, max) = admitting_one(&pool, 0).await;
    let other = fresh(&pool, 1).await;
    let mut first = checkout(&pool, 0);
    assert!(
        first.poll().is_pending(),
        "holds an id slot, at the total limit"
    );
    max.set(3);
    let mut second = checkout(&pool, 0);
    assert!(
        second.poll().is_pending(),
        "counts a connect, at the id's limit"
    );
    assert!(first.poll().is_pending(), "waits for that connect");
    assert!(second.poll().is_pending(), "at the total limit");
    close(other);
    assert!(
        matches!(
            second.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "the id slot the first held dials the connect"
    );
}

#[tokio::test]
async fn a_checkout_rejoining_its_connects_is_not_failed_by_one_failing_while_it_was_away() {
    let pool = MultiplexPool::new().with_max_connections_per_id(NonZeroUsize::new(2).unwrap());
    let (_only, max) = admitting_one(&pool, 0).await;
    max.set(10);
    let slot = permit(&pool, 0, &EMPTY_INPUT).await;
    let mut away = checkout(&pool, 0);
    assert!(away.poll().is_pending(), "waits for the connect");
    // One stream each: it dials uncounted, at the id's limit, away from the connect.
    max.set(1);
    assert!(away.poll().is_pending(), "at the id's limit");
    pool.abandon(slot, &refused());
    max.set(10);
    assert!(
        matches!(
            away.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "the failure was not its own: it dials"
    );
}

#[tokio::test(start_paused = true)]
async fn connections_of_one_stream_teach_new_ids_nothing() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let single = dialing(pool.clone(), Dialer::new(Some(1)));
    let _held = hold(&single, 0, 1).await;
    let svc = dialing(pool, Dialer::new(Some(10)));
    let _burst = burst(&svc, 1, 8).await;
    assert_eq!(dials(&svc), 1, "the hint's guess: one connection");
}

#[tokio::test]
async fn a_dial_wait_too_long_for_an_instant_is_no_dial_wait() {
    let pool = MultiplexPool::new()
        .with_streams_hint(expect_ten)
        .with_max_wait_before_dial(Duration::MAX);
    let _claim = permit(&pool, 0, &EMPTY_INPUT).await;
    let waiting = queue(&pool, &EMPTY_INPUT);
    drop(waiting);
}

#[tokio::test(start_paused = true)]
async fn waiters_that_saw_a_landing_dial_their_own_once_connects_fail() {
    /// The first dial lands; every later one fails after a second.
    struct FirstOnly(AtomicUsize);

    impl Service<ServiceInput<u32>> for FirstOnly {
        type Output = EstablishedClientConnection<Conn, ServiceInput<u32>>;
        type Error = ConnectionError;

        async fn serve(&self, input: ServiceInput<u32>) -> Result<Self::Output, Self::Error> {
            let serial = self.0.fetch_add(1, Ordering::Relaxed);
            if serial > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                return Err(ConnectionError::transport(
                    BoxError::from_static_str("connect timed out"),
                    ConnectionErrorKind::Timeout,
                ));
            }
            tokio::time::sleep(HANDSHAKE).await;
            let conn = Conn {
                serial,
                extensions: Extensions::new(),
            };
            conn.extensions.insert(ConnectionHealthWatcher::default());
            conn.extensions.insert(MaxConcurrency::new(10));
            Ok(EstablishedClientConnection { input, conn })
        }
    }

    let svc = PooledConnector::new(
        FirstOnly(AtomicUsize::new(0)),
        MultiplexPool::new().with_streams_hint(expect_ten),
        id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
    )
    .with_wait_for_pool_timeout(Duration::from_secs(5));
    let start = tokio::time::Instant::now();
    // Served ones keep their stream: the landing serves ten.
    let results = join_all((0..30).map(|_| async {
        let result = svc.connect(ServiceInput::new(0)).await;
        (result, start.elapsed())
    }))
    .await;
    let slowest = results
        .iter()
        .filter(|(result, _)| result.is_err())
        .map(|(_, took)| *took)
        .max();
    assert!(
        slowest.is_some_and(|slowest| slowest < Duration::from_millis(2200)),
        "the endpoint stopped accepting: each failed within about a connect, not after {slowest:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_burst_whose_connections_are_filed_for_other_keys_dials_at_once() {
    let mut dialer = Dialer::new(Some(10));
    // Keyed by what was negotiated, not by what the request wanted.
    dialer.key = |_| Some(2);
    let svc = dialing(MultiplexPool::new().with_streams_hint(expect_ten), dialer);
    let start = tokio::time::Instant::now();
    let served = join_all((0..8).map(|_| svc.connect(wanting(1)))).await;
    assert!(served.iter().all(Result::is_ok));
    assert!(
        start.elapsed() < HANDSHAKE * 4,
        "once one shows it, the rest dial at once"
    );
}

#[tokio::test(start_paused = true)]
async fn a_connection_kept_by_none_leaves_other_keys_coalescing() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let mut kept_by_none = Dialer::new(Some(10));
    kept_by_none.kept_by_none = true;
    let kept_by_none = dialing(pool.clone(), kept_by_none);
    let mut keyed = Dialer::new(Some(10));
    keyed.key = want_key;
    let svc = dialing(pool, keyed);
    let _seed = svc.connect(wanting(0)).await.unwrap();
    drop(kept_by_none.connect(wanting(2)).await.unwrap());
    let before = dials(&svc);
    let served = join_all((0..8).map(|_| svc.connect(wanting(1)))).await;
    assert!(served.iter().all(Result::is_ok));
    assert_eq!(
        dials(&svc) - before,
        1,
        "one connection for the burst of key 1"
    );
}

#[tokio::test]
async fn a_claim_moves_with_its_keys_when_its_total_slot_arrives_unannounced() {
    let pool = MultiplexPool::new()
        .with_streams_hint(expect_ten)
        .with_max_connections_total(NonZeroUsize::new(2).unwrap());
    let slot = permit(&pool, 0, &want(0)).await;
    let _seed = land(&pool, 0, slot, 10, Some(keyed(0, 0)), &want(0)).await;
    let other = permit(&pool, 1, &EMPTY_INPUT).await;
    let moving = want(1);
    let mut claimant = queue(&pool, &moving);
    let staying = want(1);
    let mut waiter = queue(&pool, &staying);
    moving.insert(Want(2));
    // Frees the total slot without a wake of any checkout.
    drop(other);
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = claimant.poll() else {
        panic!("the freed slot is the claimant's");
    };
    pool.abandon(slot, &refused());
    assert!(
        !matches!(waiter.poll(), Poll::Ready(Err(_))),
        "another key's connect failing is not its failure"
    );
}

#[tokio::test(start_paused = true)]
async fn a_request_scoped_transport_failure_fails_no_other_request() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let mut dialer = Dialer::new(Some(10));
    // Through a proxy only this request uses, say.
    dialer.fail = |input| {
        (want_key(input) == Some(1)).then(|| {
            ConnectionError::transport(
                BoxError::from_static_str("its proxy refused"),
                ConnectionErrorKind::Unavailable,
            )
            .with_policy_scope(ConnectionPolicyScope::Request)
        })
    };
    dialer.key = want_key;
    let svc = dialing(pool, dialer);
    let (refused, other) = tokio::join!(svc.connect(wanting(1)), svc.connect(wanting(2)));
    assert_eq!(
        refused.map(drop).map_err(|error| error.kind()),
        Err(ConnectionErrorKind::Unavailable)
    );
    assert!(other.is_ok(), "it dials its own");
}

#[tokio::test(start_paused = true)]
async fn a_connector_policy_failure_fails_the_checkouts_that_waited_for_it() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let mut dialer = Dialer::new(Some(10));
    dialer.fail = |_| {
        Some(
            ConnectionError::application(
                BoxError::from_static_str("the connector's pin rejected"),
                ConnectionErrorKind::Authentication,
            )
            .with_policy_scope(ConnectionPolicyScope::Connector),
        )
    };
    let svc = dialing(pool, dialer);
    let results = join_all((0..4).map(|_| svc.connect(ServiceInput::new(0)))).await;
    for result in results {
        assert_eq!(
            result.map(drop).map_err(|error| error.kind()),
            Err(ConnectionErrorKind::Authentication)
        );
    }
    assert_eq!(dials(&svc), 1, "they fail alike, without dialing again");
}

#[tokio::test]
async fn a_shared_failure_is_not_masked_by_a_later_one_of_a_request() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let first = permit(&pool, 0, &EMPTY_INPUT).await;
    let second = pool
        .count_connect(&TestId(0), &EMPTY_INPUT, None)
        .expect("counted");
    let mut waiting = queue(&pool, &EMPTY_INPUT);
    pool.abandon(first, &refused());
    second.failed(
        &ConnectionError::application(
            BoxError::from_static_str("its own pin rejected"),
            ConnectionErrorKind::Authentication,
        )
        .with_policy_scope(ConnectionPolicyScope::Request),
    );
    let Poll::Ready(Err(error)) = waiting.poll() else {
        panic!("the endpoint failed: it fails");
    };
    let error = error.downcast::<ConnectionError>().expect("classified");
    assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
}

#[tokio::test(start_paused = true)]
async fn a_usable_landing_restores_coalescing_for_its_key() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let mut kept_by_none = Dialer::new(Some(10));
    kept_by_none.kept_by_none = true;
    let kept_by_none = dialing(pool.clone(), kept_by_none);
    let mut keyed = Dialer::new(Some(10));
    keyed.key = want_key;
    let svc = dialing(pool, keyed);
    let _seed = svc.connect(wanting(0)).await.unwrap();
    drop(kept_by_none.connect(wanting(1)).await.unwrap());
    // A usable one of the same key, then full.
    let mut held = vec![svc.connect(wanting(1)).await.unwrap()];
    for _ in 1..10 {
        held.push(svc.connect(wanting(1)).await.unwrap());
    }
    let before = dials(&svc);
    let served = join_all((0..8).map(|_| svc.connect(wanting(1)))).await;
    assert!(served.iter().all(Result::is_ok));
    assert_eq!(
        dials(&svc) - before,
        1,
        "the burst waits for one connection again"
    );
}

#[tokio::test]
async fn a_usable_landing_leaves_groups_it_does_not_serve_flagged() {
    let pool = MultiplexPool::new().with_streams_hint(expect_ten);
    let slot = permit(&pool, 0, &want(0)).await;
    let _seed = land(&pool, 0, slot, 10, Some(keyed(0, 0)), &want(0)).await;
    let other: ConnectKey = std::iter::once((
        ReuseKey::from_bits::<KeyPolicy>(0),
        ReuseKey::from_bits::<Want>(2),
    ))
    .collect();
    let group = MultiplexPool::connects_in(&mut pool.storage.lock(), &TestId(0), &other);
    let Coalesce::Dial(Some(claim)) = group.coalesce(10, false, true, None, || 0) else {
        panic!("a claim");
    };
    // Its connect landed where none of its checkouts can use it.
    claim.landed(10, false, false);
    assert!(group.lands_unusable());
    let slot = permit(&pool, 0, &want(1)).await;
    let _usable = land(&pool, 0, slot, 10, Some(keyed(0, 1)), &want(1)).await;
    assert!(group.lands_unusable(), "usable for key 1 only");
}

/// A request wanting a key expects connections of four streams.
fn four_if_keyed(_: &TestId, input: &Extensions) -> Option<NonZeroUsize> {
    input
        .get_ref::<Want>()
        .map(|_| NonZeroUsize::new(4).unwrap())
}

#[tokio::test(start_paused = true)]
async fn a_waiter_for_connects_sleeps_once_its_expiry_timer_fired() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(3).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait)
        .with_streams_hint(four_if_keyed)
        .with_idle_timeout(Duration::from_millis(100));
    let other = fresh(&pool, 9).await;
    let ConnectionResult::CreatePermit(dialing) =
        pool.get_conn(&TestId(0), &want(7), None).await.unwrap()
    else {
        panic!("a connect in flight");
    };
    let slot = pool.test_slot();
    let mut waiter = checkout(&pool, 0);
    assert!(waiter.poll().is_pending(), "at the total limit");
    let conn = Conn {
        serial: 50,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(2));
    let first = pool
        .create(TestId(0), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap();
    let Ok(ConnectionResult::Connection(second)) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await
    else {
        panic!("its second stream");
    };
    assert!(waiter.poll().is_pending(), "now it waits for the connect");
    tokio::time::advance(Duration::from_millis(150)).await;
    for _ in 0..4 {
        assert!(waiter.poll().is_pending());
        tokio::task::yield_now().await;
    }
    assert!(!waiter.is_woken(), "a fired timer does not keep it looking");
    drop((first, second, other, dialing));
}
