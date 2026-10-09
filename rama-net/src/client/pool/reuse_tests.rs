use super::{
    ConnID, ConnectionResult, ConnectionReuse, ConnectionReusePolicy, LeasedConnection,
    LruDropPool, MultiplexPool, MultiplexedConnection, MuxSelection, Pool, ReuseKey, ReuseStrategy,
};
use crate::conn::ConnectionHealthWatcher;
use parking_lot::Mutex;
use rama_core::ServiceInput;
use rama_core::extensions::{Extension, Extensions, ExtensionsRef};
use std::assert_matches;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Route;

impl ConnID for Route {}

#[derive(Debug, Extension)]
struct PolicyId(u8);

#[derive(Debug)]
struct Policy {
    id: u8,
    reusable: bool,
}

impl ConnectionReusePolicy for Policy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        self.reusable
            .then(|| ReuseKey::from_bits::<PolicyId>(self.id.into()))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        let id = input.get_ref::<PolicyId>()?;
        Some(ReuseKey::from_bits::<PolicyId>(id.0.into()))
    }
}

fn input(id: u8) -> Extensions {
    let extensions = Extensions::new();
    extensions.insert(PolicyId(id));
    extensions
}

fn reuse(id: u8, reusable: bool) -> ConnectionReuse {
    ConnectionReuse::new(Policy { id, reusable })
}

fn connection_with(reuse: Option<ConnectionReuse>) -> ServiceInput<()> {
    let conn = ServiceInput::new(());
    if let Some(reuse) = reuse {
        conn.extensions().insert(reuse);
    }
    conn
}

fn connection(id: u8, reusable: bool) -> ServiceInput<()> {
    let conn = connection_with(Some(reuse(id, reusable)));
    conn.extensions().insert(PolicyId(id));
    conn
}

async fn establish_with<P: Pool<ServiceInput<()>, Route>>(
    pool: &P,
    request: &Extensions,
    conn: ServiceInput<()>,
) -> P::Connection {
    let ConnectionResult::CreatePermit(permit) = pool.get_conn(&Route, request).await.unwrap()
    else {
        panic!("a distinct policy must establish its own connection");
    };
    pool.create(Route, conn, permit, &Extensions::new())
        .await
        .unwrap()
}

async fn establish<P: Pool<ServiceInput<()>, Route>>(
    pool: &P,
    id: u8,
    reusable: bool,
) -> P::Connection {
    establish_with(pool, &input(id), connection(id, reusable)).await
}

fn exclusive_pool(max: usize) -> LruDropPool<ServiceInput<()>, Route> {
    LruDropPool::try_new(max, max)
        .unwrap()
        .with_drop_connection_if_no_response(false)
}

async fn idle_incompatible_is_replaced<P: Pool<ServiceInput<()>, Route>>(pool: P) {
    drop(establish(&pool, 1, true).await);
    let conn = establish(&pool, 2, true).await;
    assert_eq!(conn.extensions().get_ref::<PolicyId>().unwrap().0, 2);
    drop(conn);
    let ConnectionResult::Connection(conn) = pool.get_conn(&Route, &input(2)).await.unwrap() else {
        panic!("equivalent policy must reuse the established connection");
    };
    assert_eq!(conn.extensions().get_ref::<PolicyId>().unwrap().0, 2);
}

#[tokio::test]
async fn exclusive_replaces_incompatible_idle_connection_at_capacity() {
    idle_incompatible_is_replaced(exclusive_pool(1)).await;
}

#[tokio::test]
async fn multiplex_replaces_incompatible_idle_connection_at_capacity() {
    idle_incompatible_is_replaced(MultiplexPool::evicting(4, 1)).await;
}

async fn incompatible_waiter_and_cancellation<P: Pool<ServiceInput<()>, Route>>(pool: P) {
    let held = establish(&pool, 1, true).await;
    let request = input(2);
    let mut cancelled = tokio_test::task::spawn(pool.get_conn(&Route, &request));
    assert!(cancelled.poll().is_pending());
    drop(cancelled);

    let mut waiter = tokio_test::task::spawn(pool.get_conn(&Route, &request));
    assert!(
        waiter.poll().is_pending(),
        "spare capacity of an incompatible policy is unusable"
    );
    drop(held);
    assert!(
        waiter.is_woken(),
        "becoming idle must wake the incompatible waiter"
    );
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(permit))) = waiter.poll() else {
        panic!("released incompatible connection must make room for a fresh one");
    };
    drop(permit);
    drop(waiter);
    drop(establish(&pool, 2, true).await);
}

#[tokio::test]
async fn exclusive_incompatible_waiter_cancellation_preserves_capacity() {
    incompatible_waiter_and_cancellation(exclusive_pool(1)).await;
}

#[tokio::test]
async fn multiplex_incompatible_waiter_cancellation_preserves_capacity() {
    incompatible_waiter_and_cancellation(MultiplexPool::evicting(4, 1)).await;
}

#[tokio::test]
async fn multiplex_selection_only_admits_matching_policies() {
    for selection in [
        MuxSelection::FirstAvailable,
        MuxSelection::LeastLoaded,
        MuxSelection::RoundRobin,
    ] {
        let pool = MultiplexPool::evicting(8, 2).with_selection(selection);
        let first = establish(&pool, 1, true).await;
        let second = establish(&pool, 2, true).await;
        for id in [1, 2, 2, 1] {
            let ConnectionResult::Connection(conn) =
                pool.get_conn(&Route, &input(id)).await.unwrap()
            else {
                panic!("matching policy has spare capacity");
            };
            assert_eq!(conn.extensions().get_ref::<PolicyId>().unwrap().0, id);
        }
        drop((first, second));
    }
}

async fn opaque_policy_is_not_retained<P: Pool<ServiceInput<()>, Route>>(pool: P) {
    let held = establish(&pool, 1, false).await;
    let request = input(1);
    let mut waiter = tokio_test::task::spawn(pool.get_conn(&Route, &request));
    assert!(waiter.poll().is_pending());
    drop(held);
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(permit))) = waiter.poll() else {
        panic!("opaque connection must release its capacity without being reused");
    };
    drop((permit, waiter));
    drop(establish(&pool, 1, false).await);
}

#[tokio::test]
async fn exclusive_opaque_policy_is_not_retained() {
    opaque_policy_is_not_retained(exclusive_pool(1)).await;
}

#[tokio::test]
async fn multiplex_opaque_policy_is_not_retained() {
    opaque_policy_is_not_retained(MultiplexPool::evicting(4, 1)).await;
}

#[test]
fn composed_policies_require_every_layer_to_allow_reuse() {
    let compatible = reuse(1, true).and(reuse(1, true));
    assert!(compatible.matches(&input(1)));
    assert!(!compatible.matches(&input(2)));
    let incompatible = compatible.clone().and(reuse(2, true));
    assert!(!incompatible.matches(&input(1)));
    let opaque = compatible.and(reuse(1, false));
    assert!(!opaque.is_reusable());
    assert!(!opaque.matches(&input(1)));
}

#[test]
fn intermediary_restrictions_do_not_certify_endpoint_policy() {
    let inner = reuse(1, true);
    assert!(inner.is_complete());
    let proxy = ConnectionReuse::restriction(Policy {
        id: 1,
        reusable: true,
    });
    assert!(!proxy.is_complete());
    let tunnel = inner.and(proxy).into_restriction();
    assert!(!tunnel.is_complete());
    assert!(tunnel.matches(&input(1)));
    assert!(!tunnel.matches(&input(2)));
    let origin = tunnel.and(reuse(1, true));
    assert!(origin.is_complete());
    assert!(origin.matches(&input(1)));
}

/// Counts how often pools derive a request key.
#[derive(Debug)]
struct CountPolicy {
    calls: Arc<AtomicUsize>,
    id: u8,
}

impl ConnectionReusePolicy for CountPolicy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<PolicyId>(self.id.into()))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let id = input.get_ref::<PolicyId>()?;
        Some(ReuseKey::from_bits::<PolicyId>(id.0.into()))
    }
}

/// Checkout cost must not grow with the policies stored: a hit derives the
/// request's key once, however many connections and lanes the id has.
async fn one_key_derivation_per_classifier<P: Pool<ServiceInput<()>, Route>>(pool: P) {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut held = Vec::new();
    for n in 0..128_u8 {
        let request = input(n % 16);
        let conn = connection_with(Some(ConnectionReuse::new(CountPolicy {
            calls: calls.clone(),
            id: n % 16,
        })));
        conn.extensions().insert(PolicyId(n % 16));
        // Earlier connections are still leased, so each request establishes.
        let ConnectionResult::CreatePermit(permit) = pool.get_conn(&Route, &request).await.unwrap()
        else {
            panic!("all previous connections are leased");
        };
        held.push(
            pool.create(Route, conn, permit, &Extensions::new())
                .await
                .unwrap(),
        );
    }
    drop(held);
    calls.store(0, Ordering::Relaxed);
    let ConnectionResult::Connection(conn) = pool.get_conn(&Route, &input(9)).await.unwrap() else {
        panic!("an idle connection of the lane is stored");
    };
    assert_eq!(conn.extensions().get_ref::<PolicyId>().unwrap().0, 9);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "one request key derivation per classifier"
    );
}

#[tokio::test]
async fn exclusive_derives_one_request_key_per_classifier() {
    one_key_derivation_per_classifier(exclusive_pool(128)).await;
}

#[tokio::test]
async fn multiplex_derives_one_request_key_per_classifier() {
    one_key_derivation_per_classifier(MultiplexPool::evicting(1, 128)).await;
}

#[tokio::test]
async fn exclusive_skips_incompatible_policies_in_both_reuse_orders() {
    for strategy in [ReuseStrategy::FiFo, ReuseStrategy::RoundRobin] {
        let pool = exclusive_pool(2).with_reuse_strategy(strategy);
        let first = establish(&pool, 1, true).await;
        let second = establish(&pool, 2, true).await;
        drop((first, second));
        for id in [1, 2, 2, 1] {
            let ConnectionResult::Connection(conn) =
                pool.get_conn(&Route, &input(id)).await.unwrap()
            else {
                panic!("matching idle policy must be found after a mismatch");
            };
            assert_eq!(conn.extensions().get_ref::<PolicyId>().unwrap().0, id);
        }
    }
}

#[derive(Debug, Extension)]
struct ProxyPolicyId(u8);

#[derive(Debug)]
struct ProxyPolicy;

impl ConnectionReusePolicy for ProxyPolicy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<ProxyPolicyId>(1))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        let id = input.get_ref::<ProxyPolicyId>()?;
        Some(ReuseKey::from_bits::<ProxyPolicyId>(id.0.into()))
    }
}

#[tokio::test]
async fn semaphore_handoff_rechecks_origin_and_proxy_policy_against_current_input() {
    for selection in [
        MuxSelection::FirstAvailable,
        MuxSelection::LeastLoaded,
        MuxSelection::RoundRobin,
    ] {
        for (origin_policy, proxy_policy, reuse) in [(1, 1, true), (2, 1, false), (1, 2, false)] {
            let pool = MultiplexPool::evicting(4, 2).with_selection(selection);
            let conn = connection_with(Some(
                self::reuse(1, true).and(ConnectionReuse::restriction(ProxyPolicy)),
            ));
            conn.extensions().insert(PolicyId(1));
            let established = input(1);
            established.insert(ProxyPolicyId(1));
            let held = establish_with(&pool, &established, conn).await;
            let request = input(2);
            request.insert(ProxyPolicyId(1));
            let ConnectionResult::CreatePermit(reserved) =
                pool.get_conn(&Route, &request).await.unwrap()
            else {
                panic!("different origin policy must reserve the unused connection slot");
            };
            let mut waiter = tokio_test::task::spawn(pool.get_conn(&Route, &request));
            assert!(waiter.poll().is_pending());

            // The connection remains active with spare stream capacity. Only
            // total-slot release wakes this waiter; both policy layers must be
            // evaluated again, using the current request extensions.
            request.insert(PolicyId(origin_policy));
            request.insert(ProxyPolicyId(proxy_policy));
            drop(reserved);
            assert!(waiter.is_woken());
            match waiter.poll() {
                Poll::Ready(Ok(ConnectionResult::Connection(conn))) if reuse => {
                    assert_eq!(conn.extensions().get_ref::<PolicyId>().unwrap().0, 1);
                    drop(conn);
                }
                Poll::Ready(Ok(ConnectionResult::CreatePermit(permit))) if !reuse => drop(permit),
                result => panic!(
                    "unexpected handoff for origin={origin_policy}, proxy={proxy_policy}, selection={selection:?}: {result:?}"
                ),
            }
            drop(waiter);
            drop(held);
            // Neither a rejected policy nor returning an unused create permit
            // may strand the slot needed by the next incompatible request.
            let ConnectionResult::CreatePermit(permit) =
                pool.get_conn(&Route, &input(3)).await.unwrap()
            else {
                panic!("incompatible request must retain a fresh-connection path");
            };
            drop(permit);
        }
    }
}

async fn requirements_are_read_once<P: Pool<ServiceInput<()>, Route>>(pool: P) {
    let held = establish(&pool, 1, true).await;
    // Publishing other requirements later changes nothing for the pool.
    held.extensions().insert(reuse(2, true));
    drop(held);
    assert!(matches!(
        pool.get_conn(&Route, &input(1)).await.unwrap(),
        ConnectionResult::Connection(_),
    ));
}

#[tokio::test]
async fn exclusive_reads_requirements_once() {
    requirements_are_read_once(exclusive_pool(2)).await;
}

#[tokio::test]
async fn multiplex_reads_requirements_once() {
    requirements_are_read_once(MultiplexPool::evicting(1, 2)).await;
}

/// A request is served by a connection of any classifier whose key it matches,
/// and by connections without requirements.
async fn classifiers_share_an_id<P: Pool<ServiceInput<()>, Route>>(pool: P) {
    let unrestricted = establish_with(&pool, &input(5), connection_with(None)).await;
    let proxy = establish_with(
        &pool,
        &input(5),
        connection_with(Some(ConnectionReuse::restriction(ProxyPolicy))),
    )
    .await;
    let origin = establish(&pool, 1, true).await;
    drop((unrestricted, proxy, origin));

    let classifier = |conn: &P::Connection| {
        conn.extensions()
            .get_ref::<ConnectionReuse>()
            .map(|reuse| reuse.classifier().clone())
    };
    let only_origin = input(1);
    let mut served = Vec::new();
    let mut handouts = Vec::new();
    for _ in 0..2 {
        let ConnectionResult::Connection(conn) = pool.get_conn(&Route, &only_origin).await.unwrap()
        else {
            panic!("the origin lane and the unrestricted lane can serve it");
        };
        served.push(classifier(&conn));
        handouts.push(conn);
    }
    assert!(
        served.contains(&None) && served.contains(&Some(ReuseKey::of::<Policy>())),
        "{served:?}"
    );
    assert!(
        matches!(
            pool.get_conn(&Route, &only_origin).await.unwrap(),
            ConnectionResult::CreatePermit(_),
        ),
        "the proxy lane must not serve a request without its key",
    );
    drop(handouts);

    let only_proxy = Extensions::new();
    only_proxy.insert(ProxyPolicyId(1));
    let ConnectionResult::Connection(conn) = pool.get_conn(&Route, &only_proxy).await.unwrap()
    else {
        panic!("the proxy lane and the unrestricted lane can serve it");
    };
    assert!(classifier(&conn).is_none_or(|classifier| classifier == ReuseKey::of::<ProxyPolicy>()));
}

#[tokio::test]
async fn exclusive_classifiers_share_an_id() {
    classifiers_share_an_id(exclusive_pool(4)).await;
}

#[tokio::test]
async fn multiplex_classifiers_share_an_id() {
    classifiers_share_an_id(MultiplexPool::evicting(1, 4)).await;
}

#[tokio::test]
async fn exclusive_rekey_files_the_connection_on_return() {
    let pool = exclusive_pool(2);
    let mut held: LeasedConnection<_, _> = establish(&pool, 1, true).await;
    held.rekey(reuse(2, true));
    assert!(
        held.extensions()
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input(2))
    );
    drop(held);
    assert_matches!(
        pool.get_conn(&Route, &input(1)).await.unwrap(),
        ConnectionResult::CreatePermit(_),
    );
    assert_matches!(
        pool.get_conn(&Route, &input(2)).await.unwrap(),
        ConnectionResult::Connection(_),
    );

    let mut held = establish(&pool, 3, true).await;
    held.rekey(reuse(3, false));
    drop(held);
    assert_matches!(
        pool.get_conn(&Route, &input(3)).await.unwrap(),
        ConnectionResult::CreatePermit(_),
        "a connection rekeyed as not reusable is dropped on return",
    );
}

#[tokio::test]
async fn multiplex_rekey_moves_the_shared_connection() {
    let pool = MultiplexPool::evicting(4, 1);
    let held: MultiplexedConnection<_, _> = establish(&pool, 1, true).await;
    assert_matches!(
        pool.get_conn(&Route, &input(1)).await.unwrap(),
        ConnectionResult::Connection(_),
    );
    held.rekey(reuse(2, true));
    let first_lane = input(1);
    let mut waiter = tokio_test::task::spawn(pool.get_conn(&Route, &first_lane));
    assert!(
        waiter.poll().is_pending(),
        "the old lane no longer has the connection"
    );
    assert_matches!(
        pool.get_conn(&Route, &input(2)).await.unwrap(),
        ConnectionResult::Connection(_),
        "streams of the new lane share it at once",
    );

    held.rekey(reuse(2, false));
    let second_lane = input(2);
    let mut second = tokio_test::task::spawn(pool.get_conn(&Route, &second_lane));
    assert!(second.poll().is_pending(), "unreusable: no lane has it");

    held.rekey(reuse(1, true));
    assert!(waiter.is_woken(), "rekeying into a lane wakes its waiters");
    assert_matches!(
        waiter.poll(),
        Poll::Ready(Ok(ConnectionResult::Connection(_))),
    );
    drop(held);
}

#[tokio::test]
async fn multiplex_rekey_does_not_revive_a_dropped_connection() {
    let pool = MultiplexPool::evicting(4, 2);
    let conn = connection(1, true);
    conn.extensions().insert(ConnectionHealthWatcher::default());
    let held = establish_with(&pool, &input(1), conn).await;
    held.extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    // The next checkout of its lane drops it from the pool.
    let ConnectionResult::CreatePermit(permit) = pool.get_conn(&Route, &input(1)).await.unwrap()
    else {
        panic!("a broken connection is not handed out");
    };
    drop(permit);
    held.rekey(reuse(2, true));
    assert_matches!(
        pool.get_conn(&Route, &input(2)).await.unwrap(),
        ConnectionResult::CreatePermit(_),
        "a dropped connection stays out of the pool",
    );
    drop(held);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
struct Name(&'static str);

/// A keyed policy every request matches, in a lane of its own.
#[derive(Debug)]
struct Always;

impl ConnectionReusePolicy for Always {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }

    fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }
}

/// An older unrestricted connection and a newer keyed one, both serving every
/// request, each held once.
async fn two_lanes(
    selection: MuxSelection,
) -> (
    MultiplexPool<ServiceInput<()>, Route>,
    [MultiplexedConnection<ServiceInput<()>, Route>; 2],
) {
    let pool = MultiplexPool::evicting(10, 2).with_selection(selection);
    // Both permits first: the older connection could serve the second dial.
    let mut permits = Vec::new();
    for _ in 0..2 {
        let ConnectionResult::CreatePermit(permit) =
            pool.get_conn(&Route, &Extensions::new()).await.unwrap()
        else {
            panic!("the pool is empty");
        };
        permits.push(permit);
    }
    let older = connection_with(None);
    older.extensions().insert(Name("older"));
    let newer = connection_with(Some(ConnectionReuse::new(Always)));
    newer.extensions().insert(Name("newer"));
    let mut held = Vec::new();
    for (conn, permit) in [older, newer].into_iter().zip(permits) {
        held.push(
            pool.create(Route, conn, permit, &Extensions::new())
                .await
                .unwrap(),
        );
    }
    let [older, newer] = held.try_into().unwrap();
    (pool, [older, newer])
}

async fn name_of(pool: &MultiplexPool<ServiceInput<()>, Route>) -> &'static str {
    let ConnectionResult::Connection(conn) =
        pool.get_conn(&Route, &Extensions::new()).await.unwrap()
    else {
        panic!("both connections have room");
    };
    conn.extensions().get_ref::<Name>().unwrap().0
}

#[tokio::test]
async fn first_available_selects_across_lanes_in_creation_order() {
    let (pool, held) = two_lanes(MuxSelection::FirstAvailable).await;
    drop(held);
    assert_eq!(name_of(&pool).await, "older");
}

#[tokio::test]
async fn least_loaded_selects_across_lanes() {
    let (pool, [older, newer]) = two_lanes(MuxSelection::LeastLoaded).await;
    // The newer one idle: creation order alone would pick the busy older one.
    drop(newer);
    assert_eq!(
        name_of(&pool).await,
        "newer",
        "an idle connection beats a busy one"
    );
    drop(older);
}

#[tokio::test]
async fn round_robin_cycles_across_lanes() {
    let (pool, held) = two_lanes(MuxSelection::RoundRobin).await;
    drop(held);
    let mut names = Vec::new();
    for _ in 0..4 {
        names.push(name_of(&pool).await);
    }
    assert_eq!(names, ["older", "newer", "older", "newer"]);
}

/// Equal ids whose reuse can be switched off after a connection is stored.
#[derive(Debug, Clone)]
struct SwitchId(Arc<std::sync::atomic::AtomicBool>);

impl PartialEq for SwitchId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SwitchId {}

impl std::hash::Hash for SwitchId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

impl ConnID for SwitchId {
    fn is_reusable(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

async fn non_reusable_ids_get_fresh_connections<P: Pool<ServiceInput<()>, SwitchId>>(pool: P) {
    let id = SwitchId(Arc::new(std::sync::atomic::AtomicBool::new(true)));
    let ConnectionResult::CreatePermit(permit) =
        pool.get_conn(&id, &Extensions::new()).await.unwrap()
    else {
        panic!("empty pool");
    };
    drop(
        pool.create(
            id.clone(),
            ServiceInput::new(()),
            permit,
            &Extensions::new(),
        )
        .await
        .unwrap(),
    );
    id.0.store(false, Ordering::SeqCst);
    assert!(matches!(
        pool.get_conn(&id, &Extensions::new()).await.unwrap(),
        ConnectionResult::CreatePermit(_),
    ));
}

#[tokio::test]
async fn exclusive_non_reusable_ids_get_fresh_connections() {
    non_reusable_ids_get_fresh_connections(
        LruDropPool::try_new(2, 2)
            .unwrap()
            .with_drop_connection_if_no_response(false),
    )
    .await;
}

#[tokio::test]
async fn multiplex_non_reusable_ids_get_fresh_connections() {
    non_reusable_ids_get_fresh_connections(MultiplexPool::evicting(2, 2)).await;
}

#[derive(Debug, Clone, Copy, Extension)]
struct Arm;

/// Derives key 1; while deriving, takes the only connection of its class out
/// of the pool, so the id's classes change under the request.
struct VanishingClass {
    held: Arc<Mutex<Option<MultiplexedConnection<ServiceInput<()>, Route>>>>,
}

impl std::fmt::Debug for VanishingClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VanishingClass").finish_non_exhaustive()
    }
}

impl ConnectionReusePolicy for VanishingClass {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<PolicyId>(1))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        input.get_ref::<Arm>()?;
        if let Some(held) = self.held.lock().take() {
            held.rekey(reuse(1, false));
        }
        Some(ReuseKey::from_bits::<PolicyId>(1))
    }
}

#[tokio::test]
async fn keys_derived_from_stale_classes_never_reach_another_class() {
    let pool = MultiplexPool::evicting(4, 4);
    let held = Arc::new(Mutex::new(None));
    // The vanishing class first, at class index 0.
    let first = connection_with(Some(ConnectionReuse::new(VanishingClass {
        held: held.clone(),
    })));
    first.extensions().insert(Name("vanishing"));
    let established = input(1);
    established.insert(Arm);
    let first = establish_with(&pool, &established, first).await;
    // A `Policy` connection keyed 1 too, at class index 1.
    let second = connection(1, true);
    second.extensions().insert(Name("policy"));
    drop(establish_with(&pool, &input(1), second).await);
    *held.lock() = Some(first);
    // Key 1 for the vanishing class, key 2 for `Policy`: nothing serves it.
    let request = input(2);
    request.insert(Arm);
    if let ConnectionResult::Connection(conn) = pool.get_conn(&Route, &request).await.unwrap() {
        panic!(
            "served by {:?} although none of the request's lanes has a connection",
            conn.extensions().get_ref::<Name>()
        );
    }
}

/// Pools hand a request only connections whose lane matches it, and never
/// establish a connection while a compatible one with room is stored.
mod model {
    use super::*;

    const CLASSES: usize = 3;

    #[derive(Debug, Extension)]
    struct Serial(usize);

    #[derive(Debug, Extension)]
    struct Keys([Option<u8>; CLASSES]);

    /// A policy of class 1 or 2 keyed by `key`; class 0 serves any request.
    #[derive(Debug)]
    struct Class {
        class: usize,
        key: u8,
        reusable: bool,
    }

    impl ConnectionReusePolicy for Class {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::from_bits::<Self>(self.class as u128)
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            self.reusable.then(|| self.key_of(self.key))
        }

        fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
            if self.class == 0 {
                return Some(self.key_of(0));
            }
            Some(self.key_of(input.get_ref::<Keys>()?.0[self.class]?))
        }
    }

    impl Class {
        /// Class 0 serves every request, like a connection without requirements.
        fn key_of(&self, key: u8) -> ReuseKey {
            ReuseKey::from_bits::<Keys>(if self.class == 0 { 0 } else { key.into() })
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct Requirements {
        class: usize,
        key: u8,
        reusable: bool,
    }

    impl Requirements {
        fn decode(byte: u8) -> Self {
            Self {
                class: usize::from(byte) % CLASSES,
                key: (byte / 3) % 3,
                reusable: !(byte / 9).is_multiple_of(4),
            }
        }

        fn reuse(self) -> ConnectionReuse {
            ConnectionReuse::new(Class {
                class: self.class,
                key: self.key,
                reusable: self.reusable,
            })
        }

        /// Reusable class 0 connections are created without requirements.
        fn published(self) -> Option<ConnectionReuse> {
            (self.class != 0 || !self.reusable).then(|| self.reuse())
        }

        fn serves(self, keys: [Option<u8>; CLASSES]) -> bool {
            self.reusable && (self.class == 0 || keys[self.class] == Some(self.key))
        }
    }

    struct ModelConn {
        requirements: Requirements,
        active: usize,
    }

    trait Handout: ExtensionsRef {
        fn rekey(&mut self, reuse: ConnectionReuse);
    }

    impl Handout for LeasedConnection<ServiceInput<()>, Route> {
        fn rekey(&mut self, reuse: ConnectionReuse) {
            Self::rekey(self, reuse);
        }
    }

    impl Handout for MultiplexedConnection<ServiceInput<()>, Route> {
        fn rekey(&mut self, reuse: ConnectionReuse) {
            Self::rekey(self, reuse);
        }
    }

    fn run<P>(pool: &P, streams: usize, ops: &[(u8, u8, u8, u8)])
    where
        P: Pool<ServiceInput<()>, Route, Connection: Handout>,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut conns: Vec<ModelConn> = Vec::new();
        let mut held: Vec<(P::Connection, usize)> = Vec::new();
        for &(op, a, b, c) in ops {
            match op % 4 {
                0 | 1 if conns.len() < 48 => {
                    let decode = |byte: u8| (byte % 4 != 3).then_some(byte % 4);
                    let keys = [None, decode(a), decode(b)];
                    let request = Extensions::new();
                    request.insert(Keys(keys));
                    let fits: Vec<usize> = conns
                        .iter()
                        .enumerate()
                        .filter(|(_, conn)| conn.requirements.serves(keys) && conn.active < streams)
                        .map(|(serial, _)| serial)
                        .collect();
                    match runtime.block_on(pool.get_conn(&Route, &request)).unwrap() {
                        ConnectionResult::Connection(handout) => {
                            let serial = handout.extensions().get_ref::<Serial>().unwrap().0;
                            assert!(
                                fits.contains(&serial),
                                "connection {serial} does not serve {keys:?}"
                            );
                            conns[serial].active += 1;
                            held.push((handout, serial));
                        }
                        ConnectionResult::CreatePermit(permit) => {
                            assert!(
                                fits.is_empty(),
                                "established although {fits:?} can serve {keys:?}"
                            );
                            let requirements = Requirements::decode(c);
                            let conn = connection_with(requirements.published());
                            conn.extensions().insert(Serial(conns.len()));
                            let handout = runtime
                                .block_on(pool.create(Route, conn, permit, &request))
                                .unwrap();
                            held.push((handout, conns.len()));
                            conns.push(ModelConn {
                                requirements,
                                active: 1,
                            });
                        }
                    }
                }
                2 if !held.is_empty() => {
                    let (handout, serial) = held.swap_remove(usize::from(a) % held.len());
                    drop(handout);
                    conns[serial].active -= 1;
                }
                3 if !held.is_empty() => {
                    let index = usize::from(a) % held.len();
                    let requirements = Requirements::decode(b);
                    let (handout, serial) = &mut held[index];
                    handout.rekey(requirements.reuse());
                    conns[*serial].requirements = requirements;
                }
                _ => {}
            }
        }
    }

    #[quickcheck_macros::quickcheck]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "quickcheck generates owned inputs"
    )]
    fn exclusive_pool_hands_out_exactly_the_compatible_connections(ops: Vec<(u8, u8, u8, u8)>) {
        run(&exclusive_pool(64), 1, &ops);
    }

    #[quickcheck_macros::quickcheck]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "quickcheck generates owned inputs"
    )]
    fn multiplex_pool_hands_out_exactly_the_compatible_connections(ops: Vec<(u8, u8, u8, u8)>) {
        for streams in [1, 3] {
            for selection in [
                MuxSelection::FirstAvailable,
                MuxSelection::LeastLoaded,
                MuxSelection::RoundRobin,
            ] {
                let pool = MultiplexPool::evicting(streams, 64).with_selection(selection);
                run(&pool, streams, &ops);
            }
        }
    }
}
