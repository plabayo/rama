use std::{sync::Arc, time::Duration};

use rama_core::error::BoxError;
use tokio::sync::Semaphore;

use super::*;

#[test]
fn identical_observations_do_not_notify() {
    let changes = NetworkChanges::new();
    let mut subscription = changes.subscribe();
    let state = NetworkState {
        revision: 3,
        availability: NetworkAvailability::Available,
    };
    changes.update(state);
    assert!(subscription.has_changed().unwrap());
    assert_eq!(*subscription.borrow_and_update(), state);
    changes.update(state);
    assert!(!subscription.has_changed().unwrap());
    changes.update(NetworkState {
        availability: NetworkAvailability::Unknown,
        ..state
    });
    assert!(subscription.has_changed().unwrap());
}

#[test]
fn local_advances_notify_every_time() {
    let changes = NetworkChanges::new();
    let mut subscription = changes.subscribe();
    changes.advance(NetworkAvailability::Available);
    let first = *subscription.borrow_and_update();
    changes.advance(NetworkAvailability::Available);
    assert!(subscription.has_changed().unwrap());
    let second = *subscription.borrow_and_update();
    assert_ne!(first.revision, second.revision);
    assert_eq!(second.availability, NetworkAvailability::Available);
    assert_eq!(changes.state(), second);
}

#[test]
fn availability_starts_unknown() {
    assert_eq!(
        NetworkChanges::new().state().availability,
        NetworkAvailability::Unknown
    );
}

#[tokio::test]
async fn preparation_holds_the_gate_through_finish() {
    let gate = Semaphore::new(1);
    let value = prepare_network_change(
        Some(&gate),
        Duration::from_secs(5),
        || async { Ok::<_, BoxError>(7) },
        |value| {
            assert_eq!(gate.available_permits(), 0);
            Ok(value * 2)
        },
    )
    .await
    .unwrap();
    assert_eq!(value, 14);
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn queueing_for_the_gate_does_not_consume_the_deadline() {
    let gate = Arc::new(Semaphore::new(1));
    let held = gate.clone().acquire_owned().await.unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(held);
    });
    let value = prepare_network_change(
        Some(&gate),
        Duration::from_secs(1),
        || async { Ok::<_, BoxError>(1) },
        Ok,
    )
    .await
    .unwrap();
    assert_eq!(value, 1);
    release.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn slow_preparation_times_out_without_finishing() {
    let result = prepare_network_change(
        None,
        Duration::from_secs(1),
        || async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<_, BoxError>(())
        },
        |()| -> Result<(), BoxError> { panic!("finish must not run after the deadline") },
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn a_closed_gate_fails_preparation() {
    let gate = Semaphore::new(1);
    gate.close();
    let result = prepare_network_change(
        Some(&gate),
        Duration::from_secs(1),
        || async { Ok::<_, BoxError>(()) },
        Ok,
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn preparation_starts_only_once_admitted() {
    let gate = Semaphore::new(1);
    gate.close();
    let result = prepare_network_change(
        Some(&gate),
        Duration::from_secs(1),
        || -> core::future::Ready<Result<(), BoxError>> {
            panic!("prepare must not be called without a permit")
        },
        Ok,
    )
    .await;
    assert!(result.is_err());
}
