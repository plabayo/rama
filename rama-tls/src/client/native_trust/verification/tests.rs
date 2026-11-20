use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use parking_lot::{Condvar, Mutex};
use rama_core::error::BoxErrorExt as _;
use tokio::sync::Notify;

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn concurrent_uncached_verification_does_not_block_the_runtime() -> Result<(), BoxError> {
    static STARTED: Notify = Notify::const_new();
    static RELEASE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
    static BUILDS: AtomicUsize = AtomicUsize::new(0);
    const UNEXPECTED_SHARED: SharedStore<()> = SharedStore {
        get: || Err(BoxError::from_static_str("unexpected shared roots")),
        ready: || None,
    };
    static STORES: LazyLock<Stores<()>> = LazyLock::new(|| {
        Stores::new(UNEXPECTED_SHARED, UNEXPECTED_SHARED, |roots, _| {
            assert!(matches!(roots, StoreRoots::Custom(_)));
            BUILDS.fetch_add(1, Ordering::Relaxed);
            STARTED.notify_one();
            let mut released = RELEASE.0.lock();
            if !*released {
                RELEASE.1.wait_for(&mut released, Duration::from_secs(5));
            }
            assert!(*released, "store construction blocked the Tokio runtime");
            Ok(Arc::new(()))
        })
    });

    let trust = TlsServerTrust::custom(
        TlsServerTrustAnchors::try_new([CertificateDer::from(vec![1])]).unwrap(),
    );
    let first = tokio::spawn({
        let trust = trust.clone();
        async move { STORES.acquire_async(&trust).await.unwrap() }
    });
    STARTED.notified().await;

    let mut second = pin!(STORES.acquire_async(&trust));
    poll_fn(|cx| {
        assert!(second.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    *RELEASE.0.lock() = true;
    RELEASE.1.notify_one();

    match (first.await.unwrap(), second.await.unwrap()) {
        (Either::A(first), Either::A(second)) => assert!(Arc::ptr_eq(&first, &second)),
        _ => return Err(BoxError::from_static_str("expected derived root stores")),
    }
    assert_eq!(BUILDS.load(Ordering::Relaxed), 1);
    Ok(())
}
