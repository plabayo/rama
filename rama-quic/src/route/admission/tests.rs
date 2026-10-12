use super::*;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Barrier,
    thread,
};

fn limits() -> AdmissionLimits {
    AdmissionLimits {
        active: NonZeroUsize::new(4).unwrap(),
        active_per_source: NonZeroUsize::new(2).unwrap(),
        sources: NonZeroUsize::new(4).unwrap(),
        tuples: NonZeroUsize::new(8).unwrap(),
        starts_per_window: NonZeroUsize::new(8).unwrap(),
        starts_per_source_window: NonZeroUsize::new(4).unwrap(),
        window: Duration::from_secs(10),
        quarantine: Duration::from_secs(2),
    }
}
fn key(source: u8, port: u16) -> AssociationKey {
    AssociationKey {
        ingress: SocketAddress::local_ipv4(443),
        peer: SocketAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, source)), port),
    }
}

#[test]
fn route_admission_enforces_global_and_source_limits_without_consuming_failures() {
    let admission = Admission::new(limits()).unwrap();
    let a = admission.try_acquire(key(1, 1)).unwrap();
    let b = admission.try_acquire(key(1, 2)).unwrap();
    assert_eq!(
        admission.try_acquire(key(1, 3)).unwrap_err(),
        AdmissionError::SourceLimit
    );
    let c = admission.try_acquire(key(2, 1)).unwrap();
    let d = admission.try_acquire(key(2, 2)).unwrap();
    assert_eq!(
        admission.try_acquire(key(3, 1)).unwrap_err(),
        AdmissionError::ActiveLimit
    );
    assert_eq!(admission.0.state.lock().global.used, 4);
    drop((a, b, c, d));
    assert_eq!(admission.0.state.lock().active, 0);
    admission.try_acquire(key(3, 1)).unwrap();
}

#[tokio::test(start_paused = true)]
async fn route_admission_cancellation_preserves_rate_history_and_tuple_quarantine() {
    let admission = Admission::new(AdmissionLimits {
        starts_per_source_window: NonZeroUsize::new(2).unwrap(),
        ..limits()
    })
    .unwrap();
    let route = key(1, 1);
    drop(admission.try_acquire(route).unwrap());
    assert_eq!(
        admission.try_acquire(route).unwrap_err(),
        AdmissionError::TupleInUse
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    drop(admission.try_acquire(route).unwrap());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        admission.try_acquire(route).unwrap_err(),
        AdmissionError::RateLimit
    );
    // Another port cannot erase the same source's previous starts.
    assert_eq!(
        admission.try_acquire(key(1, 2)).unwrap_err(),
        AdmissionError::RateLimit
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    admission.try_acquire(route).unwrap();
}

#[tokio::test(start_paused = true)]
async fn route_admission_global_rate_survives_source_churn() {
    let admission = Admission::new(AdmissionLimits {
        starts_per_window: NonZeroUsize::new(2).unwrap(),
        ..limits()
    })
    .unwrap();
    drop(admission.try_acquire(key(1, 1)).unwrap());
    drop(admission.try_acquire(key(2, 1)).unwrap());
    assert_eq!(
        admission.try_acquire(key(3, 1)).unwrap_err(),
        AdmissionError::RateLimit
    );
    tokio::time::advance(Duration::from_secs(10)).await;
    admission.try_acquire(key(3, 1)).unwrap();
}

#[tokio::test(start_paused = true)]
async fn route_admission_bounds_both_history_maps_and_expires_inactive_entries() {
    for source_limit in [false, true] {
        let admission = Admission::new(AdmissionLimits {
            sources: NonZeroUsize::new(if source_limit { 1 } else { 4 }).unwrap(),
            tuples: NonZeroUsize::new(if source_limit { 8 } else { 1 }).unwrap(),
            ..limits()
        })
        .unwrap();
        drop(admission.try_acquire(key(1, 1)).unwrap());
        assert_eq!(
            admission.try_acquire(key(2, 1)).unwrap_err(),
            AdmissionError::HistoryLimit
        );
        assert_eq!(admission.0.state.lock().sources.len(), 1);
        assert_eq!(admission.0.state.lock().tuples.len(), 1);
        tokio::time::advance(Duration::from_secs(10)).await;
        admission.try_acquire(key(2, 1)).unwrap();
        assert_eq!(admission.0.state.lock().sources.len(), 1);
        assert_eq!(admission.0.state.lock().tuples.len(), 1);
    }
}

#[test]
fn route_admission_canonicalizes_ip_mapped_tuple_and_source_identity() {
    let admission = Admission::new(AdmissionLimits {
        active_per_source: NonZeroUsize::MIN,
        ..limits()
    })
    .unwrap();
    let original = key(1, 1);
    let a = admission.try_acquire(original).unwrap();
    let mapped = AssociationKey {
        ingress: SocketAddress::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 443),
        peer: SocketAddress::new(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()), 1),
    };
    assert_eq!(
        admission.try_acquire(mapped).unwrap_err(),
        AdmissionError::TupleInUse
    );
    assert_eq!(
        admission
            .try_acquire(AssociationKey {
                peer: SocketAddress::new(mapped.peer.ip_addr, 2),
                ..mapped
            })
            .unwrap_err(),
        AdmissionError::SourceLimit
    );
    drop(a);
}

#[test]
fn route_admission_concurrent_starts_have_one_owner_and_release_once() {
    let admission = Admission::new(AdmissionLimits {
        active: NonZeroUsize::MIN,
        ..limits()
    })
    .unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|index| {
            let admission = admission.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let result = admission.try_acquire(key(1, index));
                barrier.wait();
                result
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(admission.0.state.lock().active, 1);
    drop(results);
    assert_eq!(admission.0.state.lock().active, 0);
}

#[test]
fn route_admission_rejects_zero_and_unrepresentable_deadlines() {
    for duration in [Duration::ZERO, Duration::MAX] {
        assert_eq!(
            Admission::new(AdmissionLimits {
                window: duration,
                ..limits()
            })
            .unwrap_err(),
            AdmissionError::InvalidLimits
        );
        assert_eq!(
            Admission::new(AdmissionLimits {
                quarantine: duration,
                ..limits()
            })
            .unwrap_err(),
            AdmissionError::InvalidLimits
        );
    }
}
