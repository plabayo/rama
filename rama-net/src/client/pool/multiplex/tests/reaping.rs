//! Taking idle and broken connections out without scanning the pool.

use super::*;

const TIMEOUT: Duration = Duration::from_millis(100);

fn stored_ids(pool: &MultiplexPool<Conn, TestId>) -> Vec<u32> {
    let mut ids: Vec<_> = pool.storage.lock().by_id.keys().map(|id| id.0).collect();
    ids.sort_unstable();
    ids
}

/// Every stored connection is linked once, in order of idle start.
fn assert_linked_matches_storage(pool: &MultiplexPool<Conn, TestId>) {
    let linked = pool.reaper.linked();
    assert!(
        linked.windows(2).all(|pair| pair[0].1 <= pair[1].1),
        "front first by idle start: {linked:?}"
    );
    let mut linked: Vec<u64> = linked.into_iter().map(|(seq, _)| seq).collect();
    linked.sort_unstable();
    let mut stored: Vec<u64> = pool
        .storage
        .lock()
        .by_id
        .values()
        .flat_map(IdBucket::conns)
        .map(|conn| conn.seq)
        .collect();
    stored.sort_unstable();
    assert_eq!(linked, stored);
}

#[tokio::test(start_paused = true)]
async fn a_busy_connection_at_the_front_expires_a_timeout_after_it_goes_idle() {
    let pool = MultiplexPool::new().with_idle_timeout(TIMEOUT);
    let busy = fresh(&pool, 0).await;
    drop(fresh(&pool, 1).await);
    tokio::time::advance(Duration::from_millis(150)).await;
    drop(fresh(&pool, 2).await);
    assert_eq!(
        stored_ids(&pool),
        [0, 2],
        "the idle one expired, the busy one moved back"
    );
    assert_linked_matches_storage(&pool);
    drop(busy);
    tokio::time::advance(Duration::from_millis(60)).await;
    drop(fresh(&pool, 3).await);
    assert!(stored_ids(&pool).contains(&0), "idle for 60ms only");
    tokio::time::advance(Duration::from_millis(60)).await;
    drop(fresh(&pool, 4).await);
    assert!(!stored_ids(&pool).contains(&0), "idle for 120ms");
    assert_linked_matches_storage(&pool);
}

#[tokio::test(start_paused = true)]
async fn a_connection_used_again_restarts_its_idle_deadline() {
    let pool = MultiplexPool::new().with_idle_timeout(TIMEOUT);
    drop(fresh(&pool, 0).await);
    tokio::time::advance(Duration::from_millis(80)).await;
    let reused = pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await;
    assert_matches!(reused, Ok(ConnectionResult::Connection(_)));
    drop(reused);
    tokio::time::advance(Duration::from_millis(70)).await;
    drop(fresh(&pool, 1).await);
    assert!(
        stored_ids(&pool).contains(&0),
        "idle for 70ms since its reuse"
    );
    tokio::time::advance(Duration::from_millis(40)).await;
    drop(fresh(&pool, 2).await);
    assert!(
        !stored_ids(&pool).contains(&0),
        "idle for 110ms since its reuse"
    );
    assert_linked_matches_storage(&pool);
}

#[tokio::test(start_paused = true)]
async fn connections_taken_out_leave_the_idle_list() {
    let pool = MultiplexPool::new().with_idle_timeout(TIMEOUT);
    let mut held = Vec::new();
    for id in 0..8 {
        held.push(fresh(&pool, id).await);
    }
    for handout in held.iter().step_by(2) {
        handout
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();
    }
    drop(held);
    drop(fresh(&pool, 100).await);
    assert_eq!(stored_ids(&pool), [1, 3, 5, 7, 100]);
    assert_linked_matches_storage(&pool);
    tokio::time::advance(Duration::from_millis(150)).await;
    drop(fresh(&pool, 200).await);
    assert_eq!(stored_ids(&pool), [200]);
    assert_linked_matches_storage(&pool);
}

#[tokio::test(start_paused = true)]
async fn a_burst_of_breaks_is_taken_out_a_few_per_checkout() {
    let pool = MultiplexPool::new();
    let mut held = Vec::new();
    for id in 0..64 {
        held.push(fresh(&pool, id).await);
    }
    // All at once, as an outage breaks them.
    for handout in &held {
        handout
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();
    }
    drop(held);
    drop(fresh(&pool, 1000).await);
    assert_eq!(pool.storage.lock().by_id.len(), 64 - REAP_BUDGET + 1);
    while pool.storage.lock().by_id.len() > 1 {
        let reused = pool.get_conn(&TestId(1000), &EMPTY_INPUT, None).await;
        assert_matches!(reused, Ok(ConnectionResult::Connection(_)));
    }
    assert_linked_matches_storage(&pool);
}

#[tokio::test(start_paused = true)]
async fn without_an_idle_timeout_idle_connections_stay() {
    let pool = MultiplexPool::new();
    drop(fresh(&pool, 0).await);
    tokio::time::advance(Duration::from_hours(1)).await;
    drop(fresh(&pool, 1).await);
    assert_eq!(stored_ids(&pool), [0, 1]);
    assert_linked_matches_storage(&pool);
}

#[tokio::test(start_paused = true)]
async fn a_checkout_with_nothing_due_takes_no_reaping_step() {
    let pool = MultiplexPool::new().with_idle_timeout(TIMEOUT);
    drop(fresh(&pool, 0).await);
    // The first step learns when the front is due.
    drop(fresh(&pool, 1).await);
    assert!(!pool.reaper.is_due(now_monotonic_nanos()));
    tokio::time::advance(Duration::from_millis(150)).await;
    assert!(pool.reaper.is_due(now_monotonic_nanos()));
}

#[tokio::test]
async fn a_connection_a_look_sweeps_out_leaves_the_idle_list() {
    let pool = MultiplexPool::new();
    let handout = fresh(&pool, 0).await;
    // A break its listener never hears: a second watcher, not subscribed.
    let replaced = ConnectionHealthWatcher::default();
    replaced.mark_broken();
    handout.extensions().insert(replaced);
    drop(handout);
    drop(fresh(&pool, 1).await);
    let lanes = pool.request_lanes(&TestId(0), &EMPTY_INPUT);
    let mut swept = Swept::default();
    drop(pool.snapshot(
        &mut pool.storage.lock(),
        &TestId(0),
        &lanes,
        &mut swept,
        &mut Look::New,
    ));
    pool.settle(swept);
    assert_eq!(stored_ids(&pool), [1]);
    assert_linked_matches_storage(&pool);
}
