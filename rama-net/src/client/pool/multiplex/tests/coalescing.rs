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
fn expect_ten(_: &Extensions) -> Option<NonZeroUsize> {
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

fn hint_using_the_pool(input: &Extensions) -> Option<NonZeroUsize> {
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

fn hint_four(_: &Extensions) -> Option<NonZeroUsize> {
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
    let Coalesce::Dial(Some(claim)) = group.coalesce(10, false, true) else {
        panic!("a claim");
    };
    // Its connect landed where none of its checkouts can use it.
    claim.landed(10, false, false);
    assert!(group.lands_unusable());
    let slot = permit(&pool, 0, &want(1)).await;
    let _usable = land(&pool, 0, slot, 10, Some(keyed(0, 1)), &want(1)).await;
    assert!(group.lands_unusable(), "usable for key 1 only");
}
