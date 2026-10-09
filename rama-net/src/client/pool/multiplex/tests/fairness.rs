//! Who gets an idle connection: the oldest of its lane's, the total limit's
//! and its id's waiting checkouts, whatever runs first.

use super::*;

#[tokio::test]
async fn an_evictor_leaving_hands_the_idle_connection_it_was_kept_for_to_its_lane() {
    let total = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let per_id = MultiplexPool::new()
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    // An older checkout that may evict it: of another id, or of another key.
    for (pool, evictor_id) in [(total, 1), (per_id, 0)] {
        let held = fresh_keyed(&pool, 0, 1).await;
        let (other, own) = (want(2), want(1));
        let older = queue_keyed(&pool, evictor_id, &other);
        let mut younger = queue_keyed(&pool, 0, &own);
        drop(held);
        assert!(younger.poll().is_pending(), "kept for the older evictor");
        drop(older);
        assert!(
            younger.is_woken(),
            "the connection it gave way for is its lane's again"
        );
        assert!(matches!(
            younger.poll(),
            Poll::Ready(Ok(ConnectionResult::Connection(_)))
        ));
    }
}

/// Both limits of one, holding an exclusive key 1 connection of id 0.
async fn rival_limits() -> (
    MultiplexPool<Conn, TestId>,
    MultiplexedConnection<Conn, TestId>,
) {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdle);
    let held = fresh_keyed(&pool, 0, 1).await;
    (pool, held)
}

#[tokio::test]
async fn the_older_of_rival_evictors_gets_the_idle_connection_whatever_runs_first() {
    // An id 1 checkout queues for the total slot, an id 0 one for id 0's.
    for (older_id, younger_id) in [(1, 0), (0, 1)] {
        for younger_first in [true, false] {
            let (pool, held) = rival_limits().await;
            let input = want(2);
            let mut older = queue_keyed(&pool, older_id, &input);
            let mut younger = queue_keyed(&pool, younger_id, &input);
            drop(held);
            if younger_first {
                assert!(
                    younger.poll().is_pending(),
                    "the younger evictor leaves it to the older one"
                );
            }
            assert!(older.is_woken());
            let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = older.poll() else {
                panic!("older {older_id}, younger {younger_id}, younger first: {younger_first}");
            };
            if younger_first {
                assert!(younger.is_woken(), "told once the older one left");
            }
            assert!(younger.poll().is_pending(), "the older one holds the slots");
            drop(slot);
        }
    }
}

#[tokio::test]
async fn an_older_checkout_queuing_late_for_eviction_goes_first() {
    for older_first in [true, false] {
        let pool = MultiplexPool::new()
            .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
            .with_max_connections_total(NonZeroUsize::new(2).unwrap())
            .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
        let own = fresh(&pool, 1).await;
        let other = fresh(&pool, 2).await;
        // Warm: it waits for its own connection, not for an eviction chance.
        let mut older = checkout(&pool, 1);
        assert!(older.poll().is_pending());
        let mut younger = checkout(&pool, 3);
        assert!(younger.poll().is_pending());
        assert_eq!(pool.slot_waiters.len(), 1);
        // Its connection breaks: cold now, it queues for chances, late.
        own.extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();
        assert!(older.poll().is_pending() && younger.poll().is_pending());
        assert_eq!(pool.slot_waiters.front_order(), Some(0), "by arrival");
        drop(other);
        if !older_first {
            assert!(younger.poll().is_pending(), "the older one is first");
        }
        let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = older.poll() else {
            panic!("the older checkout evicts the idle connection, older first: {older_first}");
        };
        assert!(younger.poll().is_pending());
        drop((slot, own));
    }
}

#[tokio::test]
async fn a_lane_waiter_never_gives_way_to_its_own_front() {
    for front_first in [true, false] {
        // Every waiter may evict, and so queues for chances too.
        let pool = MultiplexPool::evicting(1, 2);
        let held = [add(&pool, 0, None).await, add(&pool, 0, None).await];
        let mut front = queue(&pool, &EMPTY_INPUT);
        let mut next = queue(&pool, &EMPTY_INPUT);
        assert_eq!(pool.slot_waiters.len(), 2);
        drop(held);
        let served = if front_first {
            [handout(&mut front), handout(&mut next)]
        } else {
            let next = handout(&mut next);
            [handout(&mut front), next]
        };
        drop(served);
    }
}

#[tokio::test]
async fn connections_left_once_the_lane_front_changes_are_offered_to_the_older_evictor() {
    for policy in [
        SaturationPolicy::EvictIdleWhenCold,
        SaturationPolicy::EvictIdle,
        SaturationPolicy::default(),
    ] {
        let pool = exclusive(3, policy);
        let held = [
            add(&pool, 0, None).await,
            add(&pool, 0, None).await,
            add(&pool, 0, None).await,
        ];
        // The lane's front, then a cold checkout of id 1, then two more of id 0.
        let mut first = queue(&pool, &EMPTY_INPUT);
        let mut evictor = checkout(&pool, 1);
        assert!(evictor.poll().is_pending());
        let mut second = queue(&pool, &EMPTY_INPUT);
        let mut third = queue(&pool, &EMPTY_INPUT);
        drop(held);
        let served = handout(&mut first);
        for later in [&mut second, &mut third] {
            assert!(
                later.poll().is_pending(),
                "{policy:?}: the evictor is older"
            );
        }
        assert!(evictor.is_woken(), "{policy:?}: told what was left to it");
        let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = evictor.poll() else {
            panic!("{policy:?}: the evictor takes one of them");
        };
        assert!(
            second.is_woken() && third.is_woken(),
            "{policy:?}: told once it is gone"
        );
        let next = handout(&mut second);
        assert!(third.poll().is_pending(), "{policy:?}: nothing left");
        drop((served, next, slot, third));
    }
}

#[tokio::test]
async fn connections_left_once_the_lane_front_changes_are_offered_to_the_older_id_evictor() {
    let pool = MultiplexPool::new()
        .with_max_connections_per_id(NonZeroUsize::new(3).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let held = [
        fresh_keyed(&pool, 0, 1).await,
        fresh_keyed(&pool, 0, 1).await,
        fresh_keyed(&pool, 0, 1).await,
    ];
    let (own, other) = (want(1), want(2));
    let mut first = queue_keyed(&pool, 0, &own);
    let mut evictor = queue_keyed(&pool, 0, &other);
    let mut second = queue_keyed(&pool, 0, &own);
    let mut third = queue_keyed(&pool, 0, &own);
    drop(held);
    let served = handout(&mut first);
    for later in [&mut second, &mut third] {
        assert!(
            later.poll().is_pending(),
            "the other key's checkout is older"
        );
    }
    assert!(evictor.is_woken(), "told what was left to it");
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = evictor.poll() else {
        panic!("it replaces one of them");
    };
    assert!(
        second.is_woken() && third.is_woken(),
        "told once it is gone"
    );
    let next = handout(&mut second);
    assert!(third.poll().is_pending());
    drop((served, next, slot, third));
}

#[tokio::test]
async fn an_evictor_that_takes_another_connection_hands_back_the_one_kept_for_it() {
    let pool = exclusive(2, SaturationPolicy::EvictIdleWhenCold);
    let older_idle = add(&pool, 2, None).await;
    let held = add(&pool, 0, None).await;
    let mut evictor = checkout(&pool, 1);
    assert!(evictor.poll().is_pending());
    let mut lane = queue(&pool, &EMPTY_INPUT);
    drop(older_idle);
    tokio::time::sleep(Duration::from_millis(2)).await;
    drop(held);
    assert!(lane.poll().is_pending(), "the evictor is older");
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = evictor.poll() else {
        panic!("it evicts the least recently used one");
    };
    assert!(
        lane.is_woken(),
        "told once the evictor is gone, not after its dial"
    );
    drop((handout(&mut lane), slot));
}

#[tokio::test]
async fn an_evictor_served_by_its_own_lane_hands_back_the_one_kept_for_it() {
    let pool = exclusive(2, SaturationPolicy::EvictIdle);
    let held = add(&pool, 0, None).await;
    let own = add(&pool, 1, None).await;
    let mut evictor = checkout(&pool, 1);
    assert!(evictor.poll().is_pending());
    let mut lane = queue(&pool, &EMPTY_INPUT);
    drop(held);
    assert!(lane.poll().is_pending(), "the evictor is older");
    drop(own);
    let served = handout(&mut evictor);
    assert!(lane.is_woken(), "told once the evictor is gone");
    drop((handout(&mut lane), served));
}

#[tokio::test]
async fn an_evictor_that_may_no_longer_evict_hands_back_the_one_kept_for_it() {
    let pool = exclusive(3, SaturationPolicy::EvictIdleWhenCold);
    let held = add(&pool, 0, None).await;
    let busy = add(&pool, 2, None).await;
    let permit = pool.test_slot();
    let mut evictor = checkout(&pool, 1);
    assert!(evictor.poll().is_pending());
    let mut lane = queue(&pool, &EMPTY_INPUT);
    drop(held);
    assert!(lane.poll().is_pending(), "the evictor is older");
    // Id 1 gets a (busy) connection: warm, the evictor waits for it instead.
    let conn = Conn {
        serial: 9,
        extensions: Extensions::new(),
    };
    let own = pool
        .create(TestId(1), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    assert!(evictor.poll().is_pending(), "warm: no eviction");
    assert!(lane.is_woken(), "told once the evictor left the queue");
    drop((handout(&mut lane), evictor, own, busy));
}

#[tokio::test]
async fn a_lane_waiter_at_its_id_limit_never_replaces_what_it_left_to_an_older_evictor() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(2).unwrap())
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdle);
    let held = fresh(&pool, 0).await;
    let busy = fresh(&pool, 2).await;
    let mut evictor = checkout(&pool, 1);
    assert!(evictor.poll().is_pending());
    let mut lane = queue(&pool, &EMPTY_INPUT);
    drop(held);
    assert!(
        lane.poll().is_pending(),
        "neither its to use nor to replace: the evictor is older"
    );
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = evictor.poll() else {
        panic!("the older evictor takes it");
    };
    assert!(lane.poll().is_pending(), "the evictor holds the slot");
    drop((slot, busy));
}

#[tokio::test]
async fn a_broken_connection_wakes_the_waiting_checkouts_once() {
    let pool = exclusive(1, SaturationPolicy::Wait);
    let busy = add(&pool, 0, None).await;
    let health = busy
        .extensions()
        .get_arc::<ConnectionHealthWatcher>()
        .unwrap();
    let max = Arc::new(MaxConcurrency::new(1));
    busy.extensions().insert_arc(max.clone());
    let mut waiting: Vec<_> = (1..=16).map(|id| checkout(&pool, id)).collect();
    for checkout in &mut waiting {
        assert!(checkout.poll().is_pending());
    }
    let mut looks = 0;
    for change in 0..8 {
        if change % 2 == 0 {
            health.mark_broken();
        } else {
            max.set(1);
        }
        for checkout in &mut waiting {
            if checkout.is_woken() {
                looks += 1;
                assert!(checkout.poll().is_pending(), "its handout keeps the slot");
            }
        }
    }
    assert_eq!(looks, waiting.len(), "each looks once");
    drop((busy, waiting));
}

#[test]
fn connections_left_to_an_older_evictor_are_served_on_a_real_runtime() {
    for policy in [
        SaturationPolicy::EvictIdleWhenCold,
        SaturationPolicy::EvictIdle,
        SaturationPolicy::default(),
    ] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let pool = exclusive(3, policy);
            let held = [
                add(&pool, 0, None).await,
                add(&pool, 0, None).await,
                add(&pool, 0, None).await,
            ];
            let waiting = |n: usize| {
                let pool = pool.clone();
                async move {
                    while pool.waiting.load(Ordering::Relaxed) < n {
                        tokio::task::yield_now().await;
                    }
                }
            };
            let release = Arc::new(Notify::new());
            // The lane's front holds its connection like a long request.
            let first = {
                let (pool, release) = (pool.clone(), release.clone());
                tokio::spawn(async move {
                    let result = pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap();
                    release.notified().await;
                    drop(result);
                })
            };
            waiting(1).await;
            let spawn = |id: u32| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    // Holds what it got until the end.
                    pool.get_conn(&TestId(id), &EMPTY_INPUT).await.unwrap()
                })
            };
            let evictor = spawn(1);
            waiting(2).await;
            let later = [spawn(0), spawn(0)];
            waiting(4).await;
            drop(held);
            let within = Duration::from_secs(2);
            let evicted = tokio::time::timeout(within, evictor).await;
            assert!(evicted.is_ok(), "{policy:?}: the evictor is served");
            let [second, third] = later;
            let (second, third) = (
                tokio::time::timeout(within, second).await,
                tokio::time::timeout(Duration::from_millis(50), third).await,
            );
            assert!(
                second.is_ok() || third.is_ok(),
                "{policy:?}: the connection left is served"
            );
            release.notify_one();
            drop((first, evicted, second, third));
        });
    }
}

#[tokio::test]
async fn an_evictor_leaves_an_idle_connection_to_its_lanes_older_front() {
    let pool = exclusive(1, SaturationPolicy::EvictIdleWhenCold);
    let held = add(&pool, 0, None).await;
    let mut lane = queue(&pool, &EMPTY_INPUT);
    let mut evictor = checkout(&pool, 1);
    assert!(evictor.poll().is_pending());
    drop(held);
    // It looks, whatever woke it.
    pool.notify.notify_waiters();
    assert!(evictor.poll().is_pending(), "the lane's front is older");
    drop((handout(&mut lane), evictor));
}
