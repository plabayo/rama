//! Connections follow the scope they run in: drained in its graceful phase.

use super::*;

use std::{
    pin::Pin,
    sync::atomic::AtomicBool,
    task::{Context, Poll},
};

use rama_core::graceful::{Cause, Scope, WeakScope, attach_scope};
use tokio::{
    sync::{oneshot, oneshot::error::TryRecvError, watch},
    time::{Instant, timeout},
};

/// Bounds every wait of these tests.
const LIMIT: Duration = Duration::from_secs(10);

/// Dropped with the connection whose extensions hold it.
#[derive(Debug, Extension)]
struct Closes {
    _signal: oneshot::Sender<()>,
}

/// Counts the connections dropped, through the one whose extensions hold it.
#[derive(Debug, Extension)]
struct Counted(watch::Sender<usize>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.send_modify(|dropped| *dropped += 1);
    }
}

/// A connection running in `scope` (none: in no scope), and what tells it closed.
fn conn_in(scope: Option<&Scope>) -> (Conn, oneshot::Receiver<()>) {
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    if let Some(scope) = scope {
        attach_scope(&conn.extensions, scope);
    }
    let (signal, closed) = oneshot::channel();
    conn.extensions.insert(Closes { _signal: signal });
    (conn, closed)
}

fn is_closed(closed: &mut oneshot::Receiver<()>) -> bool {
    matches!(closed.try_recv(), Err(TryRecvError::Closed))
}

async fn closes(closed: &mut oneshot::Receiver<()>) {
    timeout(LIMIT, closed)
        .await
        .expect("the connection closes")
        .unwrap_err();
}

/// Wait until no watcher, the only tasks these tests spawn, is left.
async fn watchers_end() {
    let metrics = tokio::runtime::Handle::current().metrics();
    timeout(LIMIT, async {
        while metrics.num_alive_tasks() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every watcher ends");
}

fn stored(pool: &MultiplexPool<Conn, TestId>) -> usize {
    pool.storage
        .lock()
        .by_id
        .values()
        .flat_map(IdBucket::conns)
        .count()
}

async fn get(
    pool: &MultiplexPool<Conn, TestId>,
    id: u32,
) -> ConnectionResult<MultiplexedConnection<Conn, TestId>, MultiplexSlot> {
    timeout(LIMIT, pool.get_conn(&TestId(id), &EMPTY_INPUT, None))
        .await
        .unwrap()
        .unwrap()
}

/// Check out `id`, which must dial, and add `conn` for it.
async fn dial(
    pool: &MultiplexPool<Conn, TestId>,
    id: u32,
    conn: Conn,
) -> MultiplexedConnection<Conn, TestId> {
    let ConnectionResult::CreatePermit(slot) = get(pool, id).await else {
        panic!("a checkout that dials");
    };
    pool.create(TestId(id), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap()
}

/// Check out `id`, which must reuse a stored connection.
async fn reuse(pool: &MultiplexPool<Conn, TestId>, id: u32) -> MultiplexedConnection<Conn, TestId> {
    let ConnectionResult::Connection(handout) = get(pool, id).await else {
        panic!("a checkout that reuses");
    };
    handout
}

async fn assert_dials(pool: &MultiplexPool<Conn, TestId>, id: u32) {
    assert_matches!(get(pool, id).await, ConnectionResult::CreatePermit(_));
}

/// A signal that never completes and runs `0` once dropped, as a scope drops it on its
/// cancel.
struct OnDrop(Option<Box<dyn FnOnce() + Send>>);

impl Future for OnDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for OnDrop {
    fn drop(&mut self) {
        if let Some(on_drop) = self.0.take() {
            on_drop();
        }
    }
}

#[tokio::test]
async fn a_sweep_under_the_storage_lock_never_reads_a_scope() {
    let pool = MultiplexPool::evicting(2, 2);
    let storage = pool.storage.clone();
    // 0: not dropped yet, 1: dropped with the storage lock free, 2: dropped under it.
    let dropped = Arc::new(AtomicUsize::new(0));
    let observed = dropped.clone();
    let scope = Scope::new().with_signal(OnDrop(Some(Box::new(move || {
        let state = if storage.try_lock().is_some() { 1 } else { 2 };
        observed.store(state, Ordering::SeqCst);
    }))));
    let (conn, mut closed) = conn_in(Some(&scope));
    drop(dial(&pool, 0, conn).await);
    let scope = scope.with_deadline(Instant::now());
    let mut swept = Swept::default();
    {
        let mut storage = pool.storage.lock();
        let bucket = storage.by_id.get_mut(&TestId(0)).unwrap();
        pool.sweep_bucket(bucket, &mut swept);
    }
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "the sweep read the scope"
    );
    pool.settle(swept);
    closes(&mut closed).await;
    watchers_end().await;
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    drop(scope);
}

#[tokio::test]
async fn a_scope_cancelled_by_its_deadline_is_observed_outside_the_slot_lock() {
    let pool = MultiplexPool::evicting(2, 4);
    let slot_was_free = Arc::new(AtomicBool::new(false));
    let observed = slot_was_free.clone();
    let probe: Arc<parking_lot::Mutex<Option<Arc<StoredConnection<Conn, TestId>>>>> =
        Arc::default();
    let probed = probe.clone();
    let scope = Scope::new().with_signal(OnDrop(Some(Box::new(move || {
        let free = probed
            .lock()
            .as_ref()
            .is_some_and(|conn| conn.pool_slot.try_lock().is_some());
        observed.store(free, Ordering::SeqCst);
    }))));
    let (conn, mut closed) = conn_in(Some(&scope));
    let first = dial(&pool, 0, conn).await;
    *probe.lock() = Some(first.inner.clone());
    let scope = scope.with_deadline(Instant::now());
    // Admission reads the scope of the connection that is still listed for its free streams.
    let (lane_gen, cap) = (first.inner.lane_gen.load(Ordering::Acquire), 4);
    assert!(first.inner.try_admit(lane_gen, cap, &EMPTY_INPUT).is_none());
    assert!(slot_was_free.load(Ordering::SeqCst));
    probe.lock().take();
    drop(first);
    closes(&mut closed).await;
    drop(scope);
    watchers_end().await;
}

#[tokio::test]
async fn idle_connection_closes_once_its_scope_is_cancelled() {
    let pool = MultiplexPool::evicting(2, 2);
    let scope = Scope::new();
    let (conn, mut closed) = conn_in(Some(&scope));
    drop(dial(&pool, 0, conn).await);
    assert_eq!(stored(&pool), 1);

    scope.cancel(Cause::Owner);
    closes(&mut closed).await;
    assert_eq!(stored(&pool), 0);
    assert_eq!(pool.free_slots(), 2);
    assert_open_matches_capacity(&pool);
    watchers_end().await;
}

#[tokio::test]
async fn busy_multiplexed_connection_serves_its_streams_and_closes_with_the_last() {
    let pool = MultiplexPool::evicting(2, 4);
    let scope = Scope::new();
    let (conn, mut closed) = conn_in(Some(&scope));
    let first = dial(&pool, 0, conn).await;
    let second = reuse(&pool, 0).await;
    assert!(Arc::ptr_eq(&first.inner, &second.inner));

    scope.cancel(Cause::Owner);
    watchers_end().await;
    assert!(!is_closed(&mut closed), "its streams keep it open");
    assert_eq!(stored(&pool), 0);
    assert_eq!(serial_of(&first).await, 0);
    assert_dials(&pool, 0).await;

    drop(first);
    assert!(!is_closed(&mut closed), "one stream keeps it open");
    assert_dials(&pool, 0).await;
    assert_eq!(serial_of(&second).await, 0);
    drop(second);
    assert!(is_closed(&mut closed));
    assert_eq!(stored(&pool), 0);
    assert_eq!(pool.free_slots(), 4);
    assert_open_matches_capacity(&pool);
}

#[tokio::test]
async fn waiting_checkout_dials_once_the_drained_connection_is_released() {
    let pool = exclusive(1, SaturationPolicy::Wait);
    let scope = Scope::new();
    let (conn, mut closed) = conn_in(Some(&scope));
    let held = dial(&pool, 0, conn).await;
    let mut waiter = checkout(&pool, 0);
    assert!(waiter.poll().is_pending(), "the pool is saturated");

    scope.cancel(Cause::Owner);
    watchers_end().await;
    assert!(waiter.poll().is_pending(), "its slot is still taken");
    drop(held);
    assert!(is_closed(&mut closed));
    match waiter.poll() {
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) => {}
        other => panic!("expected a create permit, got {other:?}"),
    }
}

#[tokio::test]
async fn checkout_right_after_the_cancel_dials_instead_of_reusing() {
    let pool = MultiplexPool::evicting(2, 2);
    let scope = Scope::new();
    let (conn, mut closed) = conn_in(Some(&scope));
    drop(dial(&pool, 0, conn).await);

    // Before the watcher ran: the checkout itself refuses the connection.
    scope.cancel(Cause::Owner);
    assert_dials(&pool, 0).await;
    assert!(is_closed(&mut closed));
    assert_eq!(stored(&pool), 0);
    watchers_end().await;
}

#[tokio::test]
async fn connection_made_in_a_cancelled_scope_serves_its_checkout_and_closes() {
    let pool = MultiplexPool::evicting(2, 2);
    let scope = Scope::new();
    scope.cancel(Cause::Owner);
    let (conn, mut closed) = conn_in(Some(&scope));
    let handout = dial(&pool, 0, conn).await;
    assert_eq!(stored(&pool), 0);
    assert_eq!(serial_of(&handout).await, 0);
    // Never filed, not even under new requirements.
    handout.rekey(keyed(0, 1));
    assert_eq!(stored(&pool), 0);
    assert_dials(&pool, 0).await;

    drop(handout);
    assert!(is_closed(&mut closed));
    assert_eq!(pool.free_slots(), 2);
    watchers_end().await;
}

#[tokio::test]
async fn connection_outside_the_cancelled_scope_is_kept() {
    let pool = MultiplexPool::evicting(2, 2);
    let scope = Scope::new();
    let (scoped, mut scoped_closed) = conn_in(Some(&scope));
    let (unscoped, mut unscoped_closed) = conn_in(None);
    drop(dial(&pool, 0, scoped).await);
    drop(dial(&pool, 1, unscoped).await);

    scope.cancel(Cause::Owner);
    closes(&mut scoped_closed).await;
    watchers_end().await;
    assert!(!is_closed(&mut unscoped_closed));
    assert_eq!(stored(&pool), 1);
    drop(reuse(&pool, 1).await);
}

#[tokio::test]
async fn watcher_ends_with_its_connection() {
    let pool = MultiplexPool::evicting(1, 1);
    let scope = Scope::new();
    let (conn, mut closed) = conn_in(Some(&scope));
    drop(dial(&pool, 0, conn).await);
    assert_eq!(
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
        1
    );

    // Evicted for a checkout of another id, before any cancel.
    assert_dials(&pool, 1).await;
    assert!(is_closed(&mut closed));
    watchers_end().await;
    scope.cancel(Cause::Owner);
}

/// Cancels its scope once armed, as the checkout that admits it looks.
#[derive(Debug)]
struct CancelOnAdmission {
    armed: Arc<AtomicBool>,
    scope: WeakScope,
}

impl ConnectionAdmissionPolicy for CancelOnAdmission {
    fn try_acquire(&self, _: &Extensions) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        if self.armed.load(Ordering::SeqCst) {
            self.scope.cancel(Cause::Owner);
        }
        Ok(Some(ConnectionAdmissionLease::new(Arc::new(()), AskToken)))
    }

    fn subscribe(&self, _: Weak<dyn ChangeListener>) {}

    fn in_use(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn connection_whose_scope_is_cancelled_during_admission_is_not_handed_out() {
    let pool = MultiplexPool::evicting(2, 2);
    let scope = Scope::new();
    let (conn, mut closed) = conn_in(Some(&scope));
    let armed = Arc::new(AtomicBool::new(false));
    conn.extensions
        .insert(ConnectionAdmission::new(CancelOnAdmission {
            armed: armed.clone(),
            scope: scope.clone_weak(),
        }));
    drop(dial(&pool, 0, conn).await);
    // Eligible as the checkout looks, cancelled as it admits.
    armed.store(true, Ordering::SeqCst);
    assert_dials(&pool, 0).await;
    watchers_end().await;
    assert!(is_closed(&mut closed));
    assert_eq!(stored(&pool), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_checkouts_never_reuse_a_connection_after_its_cancel() {
    const TASKS: usize = 8;
    const ROUNDS: usize = 64;
    // Two streams each and room for every task: checkouts share, wait and evict.
    let pool = MultiplexPool::evicting(2, TASKS / 2);
    let scope = Scope::new();
    let created = Arc::new(AtomicUsize::new(0));
    let (counter, mut dropped) = watch::channel(0_usize);

    let workers: Vec<_> = (0..TASKS)
        .map(|task| {
            let (pool, scope, created, counter) = (
                pool.clone(),
                scope.clone(),
                created.clone(),
                counter.clone(),
            );
            tokio::spawn(async move {
                for round in 0..ROUNDS {
                    if task == 0 && round == ROUNDS / 2 {
                        scope.cancel(Cause::Owner);
                    }
                    // Observed before the checkout starts: it must not reuse.
                    let cancelled = scope.is_cancelled();
                    let handout = match get(&pool, 0).await {
                        ConnectionResult::Connection(handout) => {
                            assert!(!cancelled, "reused after the cancel");
                            handout
                        }
                        ConnectionResult::CreatePermit(slot) => {
                            created.fetch_add(1, Ordering::SeqCst);
                            let (conn, _closed) = conn_in(Some(&scope));
                            conn.extensions.insert(Counted(counter.clone()));
                            timeout(LIMIT, pool.create(TestId(0), conn, slot, &EMPTY_INPUT))
                                .await
                                .unwrap()
                                .unwrap()
                        }
                    };
                    tokio::task::yield_now().await;
                    drop(handout);
                }
            })
        })
        .collect();
    for worker in workers {
        timeout(LIMIT, worker).await.unwrap().unwrap();
    }

    let created = created.load(Ordering::SeqCst);
    assert!(
        created < TASKS * ROUNDS,
        "connections were reused before the cancel"
    );
    timeout(LIMIT, dropped.wait_for(|dropped| *dropped == created))
        .await
        .expect("every connection closes")
        .unwrap();
    assert_eq!(stored(&pool), 0);
    assert_eq!(pool.free_slots(), TASKS / 2);
    assert_open_matches_capacity(&pool);
}
