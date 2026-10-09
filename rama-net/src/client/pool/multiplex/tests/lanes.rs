//! Reuse lanes, rekeys and policies running outside the storage lock.

use super::*;

#[tokio::test]
async fn rekey_fences_candidates_selected_under_the_old_lane() {
    let pool = MultiplexPool::evicting(2, 2);
    let held = add(&pool, 0, Some(keyed(0, 1))).await;
    let lanes = pool.request_lanes(&TestId(0), &want(1));

    // The exact path: a snapshot taken before the rekey.
    let snapshot = pool.snapshot(
        &mut pool.storage.lock(),
        &TestId(0),
        &lanes,
        &mut Swept::default(),
        &mut Look::New,
    );
    // The fast path: a claim made before the rekey.
    let claimed = pool
        .storage
        .lock()
        .by_id
        .get_mut(&TestId(0))
        .unwrap()
        .claim(&lanes, MuxSelection::FirstAvailable, 2, &[], None)
        .unwrap();

    held.rekey(keyed(0, 2));
    assert!(
        select_and_admit(
            &snapshot,
            &TestId(0),
            MuxSelection::FirstAvailable,
            &AtomicUsize::new(0),
            2,
            &want(1),
        )
        .is_none(),
        "a snapshot of the old lane admits nothing after the rekey"
    );
    assert!(
        claimed
            .conn
            .try_admit(claimed.lane_gen, 2, &want(1))
            .is_none(),
        "a claim in the old lane admits nothing after the rekey"
    );
    assert_open_matches_capacity(&pool);
    // The new lane does admit.
    let ConnectionResult::Connection(stream) = pool.get_conn(&TestId(0), &want(2)).await.unwrap()
    else {
        panic!("the rekeyed connection serves its new lane");
    };
    drop((stream, held));
}

#[tokio::test]
async fn snapshots_of_several_lanes_keep_creation_order() {
    let pool = MultiplexPool::evicting(4, 4);
    let held = [
        add(&pool, 0, Some(keyed(0, 1))).await,
        add(&pool, 0, None).await,
        add(&pool, 0, Some(keyed(1, 1))).await,
        add(&pool, 0, None).await,
    ];
    let lanes = pool.request_lanes(&TestId(0), &want(1));
    let snapshot = pool.snapshot(
        &mut pool.storage.lock(),
        &TestId(0),
        &lanes,
        &mut Swept::default(),
        &mut Look::New,
    );
    let seqs: Vec<_> = snapshot.iter().map(|(conn, _)| conn.seq).collect();
    assert_eq!(seqs.len(), 4);
    assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]), "{seqs:?}");
    drop(held);
}

#[tokio::test]
async fn emptied_lanes_and_classes_leave_the_bucket() {
    let pool = MultiplexPool::evicting(4, 8);
    let mut held = Vec::new();
    for (class, key) in [(0, 1), (0, 2), (1, 1), (1, 2)] {
        held.push(add(&pool, 0, Some(keyed(class, key))).await);
    }
    held.push(add(&pool, 0, None).await);
    {
        let storage = pool.storage.lock();
        let bucket = &storage.by_id[&TestId(0)];
        assert_eq!(bucket.keyed.len(), 2);
        assert_eq!(bucket.classes.len(), 2);
    }
    let mark_broken = |index: usize| {
        held[index]
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();
    };
    // Class 0 key 1 goes; its class keeps key 2.
    mark_broken(0);
    pool.sweep_all(&mut pool.storage.lock(), &mut Swept::default());
    assert_open_matches_capacity(&pool);
    assert_eq!(
        pool.storage.lock().by_id[&TestId(0)].keyed[0].lanes.len(),
        1
    );
    // Class 0 goes as a whole.
    mark_broken(1);
    pool.sweep_all(&mut pool.storage.lock(), &mut Swept::default());
    assert_open_matches_capacity(&pool);
    {
        let storage = pool.storage.lock();
        let bucket = &storage.by_id[&TestId(0)];
        assert_eq!(bucket.keyed.len(), 1);
        assert_eq!(bucket.classes.len(), 1);
    }
    // The rest goes, and the bucket with it.
    for index in 2..5 {
        mark_broken(index);
    }
    pool.sweep_all(&mut pool.storage.lock(), &mut Swept::default());
    assert!(pool.storage.lock().by_id.is_empty());
    drop(held);
}

#[tokio::test]
async fn connections_that_must_not_be_reused_are_never_stored() {
    let pool = MultiplexPool::evicting(4, 4);
    let fresh = add(
        &pool,
        0,
        Some(ConnectionReuse::new(KeyPolicy {
            key: None,
            class: 0,
        })),
    )
    .await;
    let fresh_id = add(&pool, u32::MAX, None).await;
    assert!(pool.storage.lock().by_id.is_empty());
    // Neither does a rekey file them: one has a non-reusable id.
    fresh_id.rekey(keyed(0, 1));
    assert!(pool.storage.lock().by_id.is_empty());
    fresh.rekey(keyed(0, 1));
    assert_eq!(pool.storage.lock().by_id[&TestId(0)].conns().count(), 1);
    assert_open_matches_capacity(&pool);
    drop((fresh, fresh_id));
}

#[tokio::test]
async fn rekey_lists_a_connection_with_room_in_its_new_lane() {
    let pool = MultiplexPool::evicting(4, 2);
    let held = add(&pool, 0, Some(keyed(0, 1))).await;
    held.rekey(keyed(1, 7));
    assert_open_matches_capacity(&pool);
    let storage = pool.storage.lock();
    let lane = storage.by_id[&TestId(0)].only_lane();
    assert!(lane.open.contains_key(&held.inner.seq));
    drop(storage);
    drop(held);
}

#[tokio::test]
async fn permit_wakeup_rederives_lanes_outside_storage_lock() {
    #[derive(Debug)]
    struct RejectReuse(Weak<Mutex<Storage<Conn, TestId>>>);

    impl ConnectionReusePolicy for RejectReuse {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }

        fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
            let storage = self.0.upgrade().unwrap();
            assert!(
                storage.try_lock().is_some(),
                "connector policy must not run under the pool lock"
            );
            None
        }
    }

    let pool = MultiplexPool::evicting(4, 2);
    let held = create_with_reuse(&pool, |_| {
        ConnectionReuse::new(RejectReuse(Arc::downgrade(&pool.storage)))
    })
    .await;
    let permit = pool.test_slot();
    let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
    assert!(waiter.poll().is_pending());

    // Only the total-slot semaphore wakes this waiter. Its admission path
    // must derive the request's lanes again before selecting spare capacity.
    drop(permit);
    assert!(waiter.is_woken());
    assert_matches!(
        waiter.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_))),
    );
    drop(held);
}

#[tokio::test]
async fn policy_check_cannot_admit_a_connection_marked_broken_during_the_check() {
    #[derive(Debug)]
    struct CloseDuringMatch {
        health: Arc<ConnectionHealthWatcher>,
        enabled: Arc<AtomicBool>,
    }

    impl ConnectionReusePolicy for CloseDuringMatch {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }

        fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
            if !self.enabled.load(Ordering::Relaxed) {
                return None;
            }
            self.health.mark_broken();
            Some(ReuseKey::of::<Self>())
        }
    }

    for selection in [
        MuxSelection::FirstAvailable,
        MuxSelection::LeastLoaded,
        MuxSelection::RoundRobin,
    ] {
        for after_wait in [false, true] {
            let pool = MultiplexPool::evicting(4, 2).with_selection(selection);
            let enabled = Arc::new(AtomicBool::new(!after_wait));
            let held = create_with_reuse(&pool, |conn| {
                ConnectionReuse::new(CloseDuringMatch {
                    health: conn
                        .extensions
                        .get_arc::<ConnectionHealthWatcher>()
                        .unwrap(),
                    enabled: enabled.clone(),
                })
            })
            .await;
            let reserved = after_wait.then(|| pool.test_slot());
            let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
            if after_wait {
                assert!(waiter.poll().is_pending());
                enabled.store(true, Ordering::Relaxed);
                drop(reserved);
                assert!(waiter.is_woken());
            }
            assert_matches!(
                waiter.poll(),
                Poll::Ready(Ok(ConnectionResult::CreatePermit(_))),
                "a close reported during policy evaluation must not yield a broken connection",
            );
            drop(held);
        }
    }
}

#[tokio::test]
async fn policy_check_cannot_admit_a_snapshot_retired_during_the_check() {
    #[derive(Debug)]
    struct RetireDuringMatch {
        pool: MultiplexPool<Conn, TestId>,
        evict: bool,
    }

    impl ConnectionReusePolicy for RetireDuringMatch {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }

        fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
            if self.evict {
                let removed = self.pool.evict_lru_idle(
                    self.pool.storage.lock(),
                    None,
                    &self.pool.slot_waiters,
                    None,
                );
                assert!(removed.is_some());
                drop(removed);
            } else {
                let mut swept = Swept::default();
                {
                    let mut storage = self.pool.storage.lock();
                    storage.by_id[&TestId(0)]
                        .conns()
                        .next()
                        .unwrap()
                        .conn
                        .extensions()
                        .get_ref::<ConnectionHealthWatcher>()
                        .unwrap()
                        .mark_broken();
                    self.pool.sweep_all(&mut storage, &mut swept);
                }
                self.pool.settle(swept);
            }
            Some(ReuseKey::of::<Self>())
        }
    }

    for evict in [false, true] {
        let pool = MultiplexPool::evicting(4, 1);
        let held = create_with_reuse(&pool, |_| {
            ConnectionReuse::new(RetireDuringMatch {
                pool: pool.clone(),
                evict,
            })
        })
        .await;
        drop(held);
        let result = pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap();
        assert_matches!(
            result,
            ConnectionResult::CreatePermit(_),
            "a retired snapshot must not bypass health or pool capacity (evict={evict})",
        );
        drop(result);
        assert_eq!(pool.free_slots(), 1);
    }
}

#[tokio::test]
async fn retired_preferred_candidate_does_not_hide_other_stream_capacity() {
    let pool = MultiplexPool::evicting(1, 2);
    let svc = connector(pool.clone());
    let first = connect(&svc, 0).await;
    let second = connect(&svc, 0).await;
    drop((first, second));
    let mut swept = Swept::default();
    let lanes = pool.request_lanes(&TestId(0), &EMPTY_INPUT);
    let mut snapshot = pool.snapshot(
        &mut pool.storage.lock(),
        &TestId(0),
        &lanes,
        &mut swept,
        &mut Look::New,
    );
    let Evicted {
        conn: retired,
        slots,
        ..
    } = pool
        .evict_lru_idle(pool.storage.lock(), None, &pool.slot_waiters, None)
        .unwrap();
    let transferred_slot = slots.total;
    let retired_index = snapshot
        .iter()
        .position(|(conn, _)| Arc::ptr_eq(conn, &retired))
        .unwrap();
    snapshot.swap(0, retired_index);
    // Retain the transferred permit as an unrelated dial would, so it
    // cannot rescue a selection that overlooks the other idle connection.
    for selection in [MuxSelection::LeastLoaded, MuxSelection::RoundRobin] {
        let conn = select_and_admit(
            &snapshot,
            &TestId(0),
            selection,
            &AtomicUsize::new(0),
            1,
            &EMPTY_INPUT,
        )
        .expect("another compatible connection still has stream capacity");
        assert!(!Arc::ptr_eq(&conn.inner, &retired));
        drop(conn);
    }
    drop(transferred_slot);
}
