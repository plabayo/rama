//! Connection limits and the saturation policy.

use super::*;

/// A new exclusive connection for `id`, through the pool's own create permit.
async fn fresh(pool: &MultiplexPool<Conn, TestId>, id: u32) -> MultiplexedConnection<Conn, TestId> {
    let ConnectionResult::CreatePermit(slot) =
        pool.get_conn(&TestId(id), &EMPTY_INPUT).await.unwrap()
    else {
        panic!("a create permit");
    };
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(1));
    pool.create(TestId(id), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_unlimited_pool_adds_connections_as_needed() {
    let pool = MultiplexPool::new();
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(fresh(&pool, 0).await);
    }
    assert_eq!(pool.storage.lock().by_id[&TestId(0)].conns().count(), 64);
    drop(held);
    let Ok(ConnectionResult::Connection(_)) = pool.get_conn(&TestId(0), &EMPTY_INPUT).await else {
        panic!("an idle connection is reused");
    };
}

fn per_id(max: usize) -> MultiplexPool<Conn, TestId> {
    MultiplexPool::new().with_max_connections_per_id(NonZeroUsize::new(max).unwrap())
}

#[tokio::test]
async fn a_per_id_limit_holds_back_only_that_id() {
    let pool = per_id(1);
    let held = fresh(&pool, 0).await;
    let mut same = queue(&pool, &EMPTY_INPUT);
    let other = fresh(&pool, 1).await;
    drop(held);
    assert!(same.is_woken(), "the id's own connection serves it");
    drop((handout(&mut same), other));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_closed_connection_frees_its_id_slot_for_a_waiter() {
    let pool = per_id(1);
    let held = fresh(&pool, 0).await;
    let mut waiter = queue(&pool, &EMPTY_INPUT);
    held.inner
        .conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    drop(held);
    assert!(waiter.is_woken());
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = waiter.poll() else {
        panic!("the broken connection's slot goes to the waiter");
    };
    assert!(slot.id.is_some(), "the permit carries the id's slot");
    let mut next = queue(&pool, &EMPTY_INPUT);
    drop(slot);
    assert!(next.is_woken(), "an unused permit frees the slot again");
    assert!(matches!(
        next.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn per_id_slots_of_ids_without_connections_are_forgotten() {
    let pool = per_id(1);
    for id in 0..256 {
        drop(fresh(&pool, id).await);
        pool.storage.lock().by_id.clear();
    }
    let kept = pool.storage.lock().id_slots.len();
    assert!(
        kept < 256,
        "slots of ids nothing holds are dropped ({kept} kept)"
    );
}

/// A pool of two exclusive connections: id 0's sits idle, id 1's is held.
async fn full_pool(
    policy: SaturationPolicy,
) -> (
    MultiplexPool<Conn, TestId>,
    MultiplexedConnection<Conn, TestId>,
) {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(2).unwrap())
        .with_saturation_policy(policy);
    drop(add(&pool, 0, None).await);
    let busy = add(&pool, 1, None).await;
    (pool, busy)
}

#[tokio::test]
async fn the_wait_policy_never_evicts() {
    let (pool, busy) = full_pool(SaturationPolicy::Wait).await;
    let mut cold = checkout(&pool, 2);
    assert!(cold.poll().is_pending(), "id 0's idle connection stays");
    drop(busy);
    if cold.is_woken() {
        assert!(cold.poll().is_pending(), "still no eviction");
    }
    assert_eq!(pool.storage.lock().by_id.len(), 2);
}

#[tokio::test]
async fn evict_idle_when_cold_evicts_only_for_a_cold_checkout() {
    let (pool, busy) = full_pool(SaturationPolicy::EvictIdleWhenCold).await;
    let mut warm = checkout(&pool, 1);
    assert!(
        warm.poll().is_pending(),
        "id 1 waits for its own connection"
    );
    let mut cold = checkout(&pool, 2);
    assert!(
        matches!(
            cold.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "a warm waiter never holds back a cold checkout"
    );
    drop(busy);
    assert!(warm.is_woken());
    let Poll::Ready(Ok(ConnectionResult::Connection(_))) = warm.poll() else {
        panic!("id 1's own connection serves it");
    };
}

#[tokio::test(start_paused = true)]
async fn evict_idle_after_evicts_once_the_checkout_waited() {
    let after = Duration::from_millis(100);
    let (pool, busy) = full_pool(SaturationPolicy::EvictIdleAfter(after)).await;
    let mut warm = checkout(&pool, 1);
    assert!(
        warm.poll().is_pending(),
        "id 1 waits for its own connection first"
    );
    tokio::time::advance(after / 2).await;
    assert!(!warm.is_woken());
    tokio::time::advance(after).await;
    assert!(warm.is_woken(), "its patience ran out");
    assert!(matches!(
        warm.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
    assert!(
        !pool.storage.lock().by_id.contains_key(&TestId(0)),
        "id 0's idle connection went"
    );
    drop(busy);
}

#[tokio::test]
async fn the_default_policy_evicts_for_a_cold_checkout_at_once() {
    let (pool, busy) = full_pool(SaturationPolicy::default()).await;
    assert!(matches!(
        checkout(&pool, 2).poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
    drop(busy);
}
