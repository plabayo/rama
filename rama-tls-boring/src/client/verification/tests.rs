use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};

use parking_lot::{Condvar, Mutex};
use rama_boring::{error::ErrorStack, x509::store::X509StoreBuilder};
use rama_core::error::{BoxErrorExt as _, CauseExt as _};
use tokio::sync::Notify;

use super::*;

#[test]
fn derived_store_cache_is_bounded() {
    let capacity = NonZeroUsize::new(3).unwrap();
    let owner = BoringServerTrustCache::new(capacity);
    let cache = owner.stores();
    let store: BoringServerVerification =
        Either::A(Arc::new(X509StoreBuilder::new().unwrap().build()));
    for index in 0..(capacity.get() + 8) {
        let anchors = TlsServerTrustAnchors::try_new([CertificateDer::from(vec![index as u8])]);
        let trust = TlsServerTrust::custom(anchors.unwrap());
        cache.insert(
            ServerTrustSnapshot::read(&trust).unwrap().key(),
            store.clone(),
        );
    }
    cache.run_pending_tasks();
    assert!((1..=capacity.get() as u64).contains(&cache.entry_count()));
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_uncached_verification_does_not_block_the_runtime() -> Result<(), BoxError> {
    static STARTED: Notify = Notify::const_new();
    static RELEASE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
    static BUILDS: AtomicUsize = AtomicUsize::new(0);
    let cache = BoringServerTrustCache::default();

    let build = |_: &ServerTrustSnapshot| {
        BUILDS.fetch_add(1, Ordering::Relaxed);
        STARTED.notify_one();
        let mut released = RELEASE.0.lock();
        if !*released {
            RELEASE.1.wait_for(&mut released, Duration::from_secs(5));
        }
        assert!(*released, "store construction blocked the Tokio runtime");
        Ok(Either::A(Arc::new(X509StoreBuilder::new()?.build())))
    };

    let trust = TlsServerTrust::custom(
        TlsServerTrustAnchors::try_new([CertificateDer::from(vec![1])]).unwrap(),
    );
    let first = tokio::spawn({
        let trust = trust.clone();
        let cache = cache.clone();
        async move { cache.acquire_async_with(&trust, build).await.unwrap() }
    });
    STARTED.notified().await;

    let mut second = pin!(cache.acquire_async_with(&trust, build));
    poll_fn(|cx| {
        assert!(second.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    *RELEASE.0.lock() = true;
    RELEASE.1.notify_one();

    match (first.await.unwrap(), second.await.unwrap()) {
        (Either::A(first), Either::A(second)) => assert!(Arc::ptr_eq(&first, &second)),
        _ => return Err(BoxError::from_static_str("expected BoringSSL root stores")),
    }
    assert_eq!(BUILDS.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn cached_verification_errors_keep_their_source() {
    let invalid = TlsServerTrustAnchors::try_new([CertificateDer::from(vec![1])]).unwrap();
    let trust = TlsServerTrust::custom(invalid);
    let extensions = Extensions::new();
    extensions.insert(trust);
    let Err(error) = BoringServerTrustCache::default().server_verification(&extensions) else {
        panic!("an unparsable anchor must fail");
    };
    assert!(error.find_cause::<ErrorStack>().is_some());
}
