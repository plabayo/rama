//! A burst on a multiplexed lane waits for the connects in flight: it opens
//! the connections it needs, in one handshake, not one each.

use super::*;
use rama_core::futures::future::join_all;

const HANDSHAKE: Duration = Duration::from_millis(100);

/// Establishes a connection per call after a handshake, each taking `streams`
/// streams if set; or fails, if `failing`.
struct Dialer {
    dials: AtomicUsize,
    streams: Option<usize>,
    failing: bool,
    handshake: Duration,
}

impl Dialer {
    fn new(streams: Option<usize>) -> Self {
        Self {
            dials: AtomicUsize::new(0),
            streams,
            failing: false,
            handshake: HANDSHAKE,
        }
    }
}

impl Service<ServiceInput<u32>> for Dialer {
    type Output = EstablishedClientConnection<Conn, ServiceInput<u32>>;
    type Error = ConnectionError;

    async fn serve(&self, input: ServiceInput<u32>) -> Result<Self::Output, Self::Error> {
        let serial = self.dials.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(self.handshake).await;
        if self.failing {
            return Err(ConnectionError::transport(
                BoxError::from_static_str("refused"),
                ConnectionErrorKind::Unavailable,
            ));
        }
        let conn = Conn {
            serial,
            extensions: Extensions::new(),
        };
        conn.extensions.insert(ConnectionHealthWatcher::default());
        if let Some(streams) = self.streams {
            conn.extensions.insert(MaxConcurrency::new(streams));
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
    dialer.failing = true;
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
    assert!(connects.iter().all(|(_, connects)| connects.is_unused()));
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
