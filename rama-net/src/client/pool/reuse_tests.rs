use super::{
    ConnID, ConnectionResult, ConnectionReuse, ConnectionReusePolicy, LruDropPool, MultiplexPool,
    MuxSelection, Pool, ReuseStrategy,
};
use rama_core::ServiceInput;
use rama_core::extensions::{Extension, Extensions, ExtensionsRef};
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
    fn is_reusable(&self) -> bool {
        self.reusable
    }

    fn matches(&self, input: &Extensions) -> bool {
        input
            .get_ref::<PolicyId>()
            .is_some_and(|id| id.0 == self.id)
    }
}

fn input(id: u8) -> Extensions {
    let extensions = Extensions::new();
    extensions.insert(PolicyId(id));
    extensions
}

fn connection(id: u8, reusable: bool) -> ServiceInput<()> {
    let conn = ServiceInput::new(());
    conn.extensions().insert(PolicyId(id));
    conn.extensions()
        .insert(ConnectionReuse::new(Policy { id, reusable }));
    conn
}

async fn establish<P: Pool<ServiceInput<()>, Route>>(
    pool: &P,
    id: u8,
    reusable: bool,
) -> P::Connection {
    let ConnectionResult::CreatePermit(permit) = pool.get_conn(&Route, &input(id)).await.unwrap()
    else {
        panic!("a distinct policy must establish its own connection");
    };
    pool.create(Route, connection(id, reusable), permit, &Extensions::new())
        .await
        .unwrap()
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
    idle_incompatible_is_replaced(
        LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false),
    )
    .await;
}

#[tokio::test]
async fn multiplex_replaces_incompatible_idle_connection_at_capacity() {
    idle_incompatible_is_replaced(MultiplexPool::try_new(4, 1).unwrap()).await;
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
    incompatible_waiter_and_cancellation(
        LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false),
    )
    .await;
}

#[tokio::test]
async fn multiplex_incompatible_waiter_cancellation_preserves_capacity() {
    incompatible_waiter_and_cancellation(MultiplexPool::try_new(4, 1).unwrap()).await;
}

#[tokio::test]
async fn multiplex_selection_only_admits_matching_policies() {
    for selection in [
        MuxSelection::FirstAvailable,
        MuxSelection::LeastLoaded,
        MuxSelection::RoundRobin,
    ] {
        let pool = MultiplexPool::try_new(8, 2)
            .unwrap()
            .with_selection(selection);
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
    opaque_policy_is_not_retained(
        LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false),
    )
    .await;
}

#[tokio::test]
async fn multiplex_opaque_policy_is_not_retained() {
    opaque_policy_is_not_retained(MultiplexPool::try_new(4, 1).unwrap()).await;
}

#[test]
fn composed_policies_require_every_layer_to_allow_reuse() {
    let compatible = ConnectionReuse::new(Policy {
        id: 1,
        reusable: true,
    })
    .and(ConnectionReuse::new(Policy {
        id: 1,
        reusable: true,
    }));
    assert!(compatible.matches(&input(1)));
    assert!(!compatible.matches(&input(2)));
    let incompatible = compatible.clone().and(ConnectionReuse::new(Policy {
        id: 2,
        reusable: true,
    }));
    assert!(!incompatible.matches(&input(1)));
    let opaque = compatible.and(ConnectionReuse::new(Policy {
        id: 1,
        reusable: false,
    }));
    assert!(!opaque.is_reusable());
    assert!(!opaque.matches(&input(1)));
}

#[test]
fn intermediary_restrictions_do_not_certify_endpoint_policy() {
    let inner = ConnectionReuse::new(Policy {
        id: 1,
        reusable: true,
    });
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
    let origin = tunnel.and(ConnectionReuse::new(Policy {
        id: 1,
        reusable: true,
    }));
    assert!(origin.is_complete());
    assert!(origin.matches(&input(1)));
}

#[tokio::test]
async fn exclusive_only_evaluates_the_first_compatible_policy() {
    #[derive(Debug)]
    struct CountPolicy(Arc<AtomicUsize>);

    impl ConnectionReusePolicy for CountPolicy {
        fn matches(&self, _: &Extensions) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    let pool = LruDropPool::try_new(128, 128)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let calls = Arc::new(AtomicUsize::new(0));
    let input = Extensions::new();
    let mut held = Vec::new();
    for _ in 0..128 {
        let ConnectionResult::CreatePermit(permit) = pool.get_conn(&Route, &input).await.unwrap()
        else {
            panic!("all previous connections remain leased");
        };
        let conn = ServiceInput::new(());
        conn.extensions()
            .insert(ConnectionReuse::new(CountPolicy(calls.clone())));
        held.push(
            pool.create(Route, conn, permit, &Extensions::new())
                .await
                .unwrap(),
        );
    }
    drop(held);
    assert!(matches!(
        pool.get_conn(&Route, &input).await.unwrap(),
        ConnectionResult::Connection(_)
    ));
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "first-compatible checkout must not inspect all idle policies"
    );
}

#[tokio::test]
async fn exclusive_skips_incompatible_policies_in_both_reuse_orders() {
    for strategy in [ReuseStrategy::FiFo, ReuseStrategy::RoundRobin] {
        let pool = LruDropPool::try_new(2, 2)
            .unwrap()
            .with_drop_connection_if_no_response(false)
            .with_reuse_strategy(strategy);
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
    fn matches(&self, input: &Extensions) -> bool {
        input.get_ref::<ProxyPolicyId>().is_some_and(|id| id.0 == 1)
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
            let pool = MultiplexPool::try_new(4, 2)
                .unwrap()
                .with_selection(selection);
            let held = establish(&pool, 1, true).await;
            held.extensions().insert(
                ConnectionReuse::new(Policy {
                    id: 1,
                    reusable: true,
                })
                .and(ConnectionReuse::restriction(ProxyPolicy)),
            );
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
