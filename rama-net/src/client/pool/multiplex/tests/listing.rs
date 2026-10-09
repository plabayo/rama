//! The open index and connection selection.

use super::*;

#[tokio::test]
async fn least_loaded_selection() {
    let pool = MultiplexPool::evicting(3, 2).with_selection(MuxSelection::LeastLoaded);
    let svc = connector(pool);

    let c1 = connect(&svc, 0).await;
    let _c2 = connect(&svc, 0).await;
    let _c3 = connect(&svc, 0).await;
    let _c4 = connect(&svc, 0).await;
    assert_eq!(created(&svc), 2);

    drop(c1);

    let c5 = connect(&svc, 0).await;
    assert_eq!(
        c5.conn.serve(ServiceInput::new(())).await.unwrap(),
        1,
        "least-loaded should pick connection 1 (more free streams)"
    );
}

#[tokio::test]
async fn first_available_selection() {
    let pool = MultiplexPool::evicting(3, 2).with_selection(MuxSelection::FirstAvailable);
    let svc = connector(pool);

    let c1 = connect(&svc, 0).await;
    let _c2 = connect(&svc, 0).await;
    let _c3 = connect(&svc, 0).await;
    let _c4 = connect(&svc, 0).await;
    assert_eq!(created(&svc), 2);

    drop(c1);

    let c5 = connect(&svc, 0).await;
    assert_eq!(
        c5.conn.serve(ServiceInput::new(())).await.unwrap(),
        0,
        "first-available should pick connection 0 (first with a free slot)"
    );
}

#[tokio::test]
async fn selection_walks_idle_exclusive_connections_in_creation_order() {
    for (selection, expected) in [
        (MuxSelection::FirstAvailable, [0, 0, 0, 0, 0, 0]),
        (MuxSelection::LeastLoaded, [0, 0, 0, 0, 0, 0]),
        (MuxSelection::RoundRobin, [0, 1, 2, 3, 0, 1]),
    ] {
        let pool = MultiplexPool::evicting(1, 8).with_selection(selection);
        let svc = connector(pool.clone());
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(connect(&svc, 0).await);
        }
        assert_eq!(created(&svc), 4);
        // Nothing has room, so the index is empty.
        assert!(
            pool.storage.lock().by_id[&TestId(0)]
                .only_lane()
                .open
                .is_empty()
        );
        drop(held);
        assert_open_matches_capacity(&pool);

        let mut serials = Vec::new();
        for _ in 0..expected.len() {
            let handout = connect(&svc, 0).await;
            serials.push(serial_of(&handout.conn).await);
        }
        assert_eq!(serials, expected, "{selection:?}");
        assert_eq!(created(&svc), 4, "idle connections are reused");
        assert_open_matches_capacity(&pool);

        // Concurrent checkouts spread over distinct connections.
        let first = connect(&svc, 0).await;
        let second = connect(&svc, 0).await;
        assert_ne!(serial_of(&first.conn).await, serial_of(&second.conn).await);
        assert_eq!(created(&svc), 4);
        drop((first, second));
        assert_open_matches_capacity(&pool);
    }
}

#[tokio::test]
async fn multiplexed_connection_stays_listed_until_full() {
    let pool = MultiplexPool::evicting(3, 4);
    let svc = connector(pool.clone());
    let first = connect(&svc, 0).await;
    let second = connect(&svc, 0).await;
    assert!(pool.storage.lock().by_id[&TestId(0)].only_lane().open.len() == 1);
    let third = connect(&svc, 0).await;
    assert!(
        pool.storage.lock().by_id[&TestId(0)]
            .only_lane()
            .open
            .is_empty(),
        "the last stream slot unlists the connection"
    );
    drop(second);
    assert_eq!(
        pool.storage.lock().by_id[&TestId(0)].only_lane().open.len(),
        1
    );
    drop((first, third));
    assert_open_matches_capacity(&pool);
    assert_eq!(created(&svc), 1);
}

#[tokio::test]
async fn released_connection_is_found_again_after_its_bucket_was_swept_empty() {
    let pool = MultiplexPool::evicting(1, 2);
    let svc = connector(pool.clone());
    let held = connect(&svc, 0).await;
    held.conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    let mut doomed = Vec::new();
    pool.sweep_all(&mut pool.storage.lock(), &mut doomed);
    drop(doomed);
    assert!(pool.storage.lock().by_id.is_empty());
    // Releasing a retired connection must not resurrect it.
    drop(held);
    assert!(pool.storage.lock().by_id.is_empty());
    let fresh = connect(&svc, 0).await;
    assert_eq!(created(&svc), 2);
    drop(fresh);
    assert_open_matches_capacity(&pool);
}

#[tokio::test]
async fn broken_listed_connection_is_retired_when_selected() {
    let pool = MultiplexPool::evicting(1, 8);
    let svc = connector(pool.clone());
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(connect(&svc, 0).await);
    }
    held[1]
        .conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    drop(held);

    // Serials 0 and 2 serve; the broken 1 sits between them and is retired
    // when selected, not handed out.
    let a = connect(&svc, 0).await;
    let b = connect(&svc, 0).await;
    assert_eq!(serial_of(&a.conn).await, 0);
    assert_eq!(serial_of(&b.conn).await, 2);
    assert_eq!(created(&svc), 3);
    drop((a, b));
    let bucket_len = pool.storage.lock().by_id[&TestId(0)].conns().count();
    assert_eq!(bucket_len, 2);
    assert_open_matches_capacity(&pool);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_checkouts_keep_the_open_index_consistent() {
    for selection in [
        MuxSelection::FirstAvailable,
        MuxSelection::LeastLoaded,
        MuxSelection::RoundRobin,
    ] {
        let pool = MultiplexPool::evicting(1, 12).with_selection(selection);
        let svc = Arc::new(connector(pool.clone()));
        let mut tasks = Vec::new();
        for task in 0..32 {
            let svc = svc.clone();
            tasks.push(tokio::spawn(async move {
                for round in 0..300 {
                    let handout = connect(&svc, 0).await;
                    if (round + task) % 3 == 0 {
                        tokio::task::yield_now().await;
                    }
                    drop(handout);
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        // A checkout racing a release can evict the connection that just went
        // idle and dial another, so `created` may exceed the limit; what is
        // stored may not, and every slot must be accounted for.
        let storage = pool.storage.lock();
        let stored: Vec<_> = storage.by_id[&TestId(0)].conns().collect();
        assert!(stored.len() <= 12);
        assert_eq!(
            pool.free_slots(),
            12 - stored.len(),
            "no slot leaked ({selection:?})"
        );
        for conn in stored {
            assert_eq!(conn.active.load(Ordering::Relaxed), 0);
        }
        drop(storage);
        assert_open_matches_capacity(&pool);
    }
}
