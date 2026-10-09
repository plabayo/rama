//! Checkouts, handouts and per-connection capacity.

use super::*;

#[tokio::test]
async fn non_reusable_policy_keeps_capacity_without_retaining_connections() {
    let pool = MultiplexPool::evicting(10, 1);
    let svc = connector(pool.clone());
    let first = connect(&svc, u32::MAX).await;
    assert!(pool.storage.lock().by_id.is_empty());
    let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(u32::MAX), &EMPTY_INPUT));
    assert!(waiter.poll().is_pending());
    drop(first);
    match waiter.poll() {
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) => {}
        other => panic!("fresh capacity must be released on drop: {other:?}"),
    }
    let second = connect(&svc, u32::MAX).await;
    assert_eq!(created(&svc), 2);
    drop(second);
    assert!(pool.storage.lock().by_id.is_empty());
    assert_eq!(pool.free_slots(), 1);
}

#[tokio::test]
async fn shares_one_connection() {
    let pool = MultiplexPool::evicting(4, 4);
    let svc = connector(pool);

    let mut handles = Vec::new();
    for _ in 0..4 {
        handles.push(connect(&svc, 0).await);
    }
    assert_eq!(
        created(&svc),
        1,
        "all 4 handouts should share one connection"
    );
    for h in &handles {
        assert_eq!(h.conn.serve(ServiceInput::new(())).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn dropping_a_handout_releases_its_stream_slot_immediately() {
    let pool = MultiplexPool::evicting(1, 1);
    let svc = connector(pool.clone());
    let handout = connect(&svc, 0).await;
    let stored = Arc::clone(
        pool.storage.lock().by_id[&TestId(0)]
            .conns()
            .next()
            .unwrap(),
    );

    assert_eq!(stored.active.load(Ordering::Relaxed), 1);
    let previous_idle = stored.last_idle.as_nanos();
    tokio::time::sleep(Duration::from_millis(2)).await;
    drop(handout);
    assert_eq!(stored.active.load(Ordering::Relaxed), 0);
    assert!(stored.is_idle());
    assert!(stored.last_idle.as_nanos() > previous_idle);
}

#[tokio::test]
async fn maxconcurrency_zero_admits_no_streams() {
    let pool = MultiplexPool::evicting(4, 4);
    let svc = connector_with(pool, Some(0));

    let c1 = connect(&svc, 0).await;
    assert_eq!(created(&svc), 1);
    drop(c1);

    // Connection 0 advertises `MaxConcurrency(0)`: even while idle it must not
    // admit a new stream (0 means "no streams", not clamp-to-1), so the pool
    // creates a fresh connection instead of reusing it.
    let _c2 = connect(&svc, 0).await;
    assert_eq!(
        created(&svc),
        2,
        "a connection advertising max_concurrency=0 must not admit new streams"
    );
}

#[tokio::test]
async fn new_connection_when_saturated() {
    let pool = MultiplexPool::evicting(2, 2);
    let svc = connector(pool);

    let _c1 = connect(&svc, 0).await;
    let _c2 = connect(&svc, 0).await;
    assert_eq!(
        created(&svc),
        1,
        "connection 0 should be reused while it has room"
    );

    let c3 = connect(&svc, 0).await;
    assert_eq!(
        created(&svc),
        2,
        "a 3rd concurrent handout needs a new connection"
    );
    assert_eq!(c3.conn.serve(ServiceInput::new(())).await.unwrap(), 1);
}

#[tokio::test]
async fn extensions_propagate_at_establish() {
    let pool = MultiplexPool::evicting(2, 2);
    let svc = connector(pool);

    let c = connect(&svc, 0).await;

    assert!(
        c.conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .is_some()
    );
}

#[tokio::test]
async fn broken_removed_while_handles_survive() {
    let pool = MultiplexPool::evicting(2, 2);
    let svc = connector(pool);

    let c1 = connect(&svc, 0).await;
    let c2 = connect(&svc, 0).await;
    assert_eq!(created(&svc), 1);

    // mark the shared connection broken
    c1.conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();

    // a fresh handout must not reuse the broken connection
    let c3 = connect(&svc, 0).await;
    assert_eq!(created(&svc), 2);
    assert_eq!(c3.conn.serve(ServiceInput::new(())).await.unwrap(), 1);

    // the in-flight handles still work on the (removed but alive) connection
    assert_eq!(c1.conn.serve(ServiceInput::new(())).await.unwrap(), 0);
    assert_eq!(c2.conn.serve(ServiceInput::new(())).await.unwrap(), 0);

    // once they drop, the slot frees and a new handout can be created again
    drop(c1);
    drop(c2);
    drop(c3);
    let _c4 = connect(&svc, 0).await;
    // c4 reuses connection 1 (still in storage), no new connection
    assert_eq!(created(&svc), 2);
}

#[tokio::test]
async fn capacity_one_is_exclusive() {
    let pool = MultiplexPool::evicting(1, 3);
    let svc = connector(pool);

    let c1 = connect(&svc, 0).await;
    let c2 = connect(&svc, 0).await;
    let c3 = connect(&svc, 0).await;
    assert_eq!(created(&svc), 3, "capacity 1 never shares a connection");
    // each landed on a distinct connection
    assert_eq!(c1.conn.serve(ServiceInput::new(())).await.unwrap(), 0);
    assert_eq!(c2.conn.serve(ServiceInput::new(())).await.unwrap(), 1);
    assert_eq!(c3.conn.serve(ServiceInput::new(())).await.unwrap(), 2);
}

#[tokio::test]
async fn capacity_from_extension() {
    // pool cap 5, but each connection advertises only 2 -> effective 2
    let pool = MultiplexPool::evicting(5, 5);
    let svc = connector_with(pool, Some(2));

    let _c1 = connect(&svc, 0).await;
    let _c2 = connect(&svc, 0).await;
    assert_eq!(
        created(&svc),
        1,
        "two streams share the connection (its advertised capacity)"
    );

    let _c3 = connect(&svc, 0).await;
    assert_eq!(
        created(&svc),
        2,
        "a 3rd stream exceeds the advertised capacity -> new connection"
    );
}

#[tokio::test]
async fn capacity_is_read_live() {
    // Connections start advertising 1, pool cap is high.
    let pool = MultiplexPool::evicting(10, 5);
    let svc = connector_with(pool, Some(1));

    let c1 = connect(&svc, 0).await; // conn A, now at its limit of 1
    let _c2 = connect(&svc, 0).await; // A full -> conn B
    assert_eq!(created(&svc), 2);

    // Server raises A's SETTINGS_MAX_CONCURRENT_STREAMS to 3.
    c1.conn
        .extensions()
        .get_ref::<MaxConcurrency>()
        .unwrap()
        .set(3);

    // A now has spare capacity, so the next stream reuses A instead of
    // opening a new connection — proving the limit is read live.
    let _c3 = connect(&svc, 0).await;
    assert_eq!(
        created(&svc),
        2,
        "raising MaxConcurrency lets A take another stream (dynamic capacity)"
    );
}

#[tokio::test]
async fn no_extension_uses_pool_cap() {
    // Without a MaxConcurrency extension there is "no limit", so the pool's
    // max_concurrent_streams governs: cap 2 -> 2 streams share one connection.
    let pool = MultiplexPool::evicting(2, 8);
    let svc = connector_with(pool, None);

    let _c1 = connect(&svc, 0).await;
    let _c2 = connect(&svc, 0).await;
    assert_eq!(
        created(&svc),
        1,
        "two streams share one connection (pool cap 2)"
    );

    let _c3 = connect(&svc, 0).await;
    assert_eq!(
        created(&svc),
        2,
        "a 3rd stream exceeds the pool cap -> new connection"
    );
}

#[test]
fn virtual_conn_is_send_sync() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<MultiplexedConnection<Conn, TestId>>();
    fn assert_pool<P: Pool<Conn, TestId>>() {}
    assert_pool::<MultiplexPool<Conn, TestId>>();
}
