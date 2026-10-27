use super::*;
use rama::{
    ServiceInput,
    service::service_fn,
    ua::profile::{
        capture::completeness::ProfileCaptureCompleteness,
        capture::joint::{CaptureLevel, JointCapture},
        model::identity::{ConnectionContext, ProfileKey},
    },
};
use std::{convert::Infallible, sync::Barrier, thread};

fn owner(authorized: bool, profile: u8) -> CollectionOwner {
    CollectionOwner {
        authorized,
        profile: ValueId([profile; 32]),
    }
}
fn permit(lease: &Arc<CollectionLease>, owner: CollectionOwner) -> ConnectionPermit {
    match lease.claim(owner) {
        CollectionClaim::Connection(permit, None) => {
            assert_eq!(permit.owner(), owner);
            permit
        }
        claim => panic!("expected connection permit, got {claim:?}"),
    }
}

#[test]
fn cancellation_keeps_owner_but_releases_preparation() {
    for authorized in [false, true] {
        let lease = Arc::new(CollectionLease::default());
        let first = owner(authorized, 1);
        let pending = permit(&lease, first);
        assert!(matches!(lease.claim(first), CollectionClaim::RequestOnly));
        drop(pending);
        for other in [owner(authorized, 2), owner(!authorized, 2)] {
            assert!(matches!(lease.claim(other), CollectionClaim::OwnerMismatch));
        }
        let retry = permit(&lease, first);
        assert!(matches!(lease.claim(first), CollectionClaim::RequestOnly));
        drop(retry);
        assert_eq!(
            *lease.state.lock().phase(authorized),
            ConnectionPhase::Available
        );
    }
}

#[test]
fn each_partition_collects_the_connection_once() {
    for authorized in [false, true] {
        let lease = Arc::new(CollectionLease::default());
        let _first = permit(&lease, owner(authorized, 1)).queued();
        assert!(matches!(
            lease.claim(owner(authorized, 1)),
            CollectionClaim::RequestOnly
        ));
        let _other = permit(&lease, owner(!authorized, 1)).queued();
        assert!(matches!(
            lease.claim(owner(!authorized, 1)),
            CollectionClaim::RequestOnly
        ));
    }
}

fn handover() -> Box<ConnectionHandover> {
    let capture = || ProfileCapture {
        profile: ProfileKey::new("handover"),
        connection: ConnectionContext::default(),
        flow: None,
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: Box::default(),
        },
    };
    Box::new(ConnectionHandover {
        request: capture(),
        connection: capture(),
    })
}

#[test]
fn a_public_bootstrap_is_handed_to_the_authorized_partition_once() {
    let lease = Arc::new(CollectionLease::default());
    let _public = permit(&lease, owner(false, 1)).queued();
    lease.offer_handover(handover());
    match lease.claim(owner(true, 1)) {
        CollectionClaim::Connection(permit, Some(_handover)) => drop(permit.queued()),
        claim => panic!("expected the handed-over connection, got {claim:?}"),
    }
    assert!(matches!(
        lease.claim(owner(true, 1)),
        CollectionClaim::RequestOnly
    ));
}

#[test]
fn a_handover_is_kept_only_while_the_authorized_partition_can_use_it() {
    let lease = Arc::new(CollectionLease::default());
    let _authorized = permit(&lease, owner(true, 1)).queued();
    lease.offer_handover(handover());
    assert!(lease.state.lock().handover.is_none());
    // The public partition never receives one.
    let lease = Arc::new(CollectionLease::default());
    lease.offer_handover(handover());
    assert!(matches!(
        lease.claim(owner(false, 1)),
        CollectionClaim::Connection(_, None)
    ));
}

#[test]
fn concurrent_requests_have_one_connection_permit() {
    let lease = Arc::new(CollectionLease::default());
    let barrier = Barrier::new(16);
    let count = thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    let claim = lease.claim(owner(false, 1));
                    // Keep the winner's permit held until every contender has claimed.
                    barrier.wait();
                    matches!(claim, CollectionClaim::Connection(..))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(count, 1);
}

#[test]
fn queued_connections_never_receive_another_id() {
    for outcome in [
        Some(CollectionResult::Stored),
        Some(CollectionResult::Rejected),
        Some(CollectionResult::Unconfirmed),
        None,
    ] {
        let lease = Arc::new(CollectionLease::default());
        let first = owner(true, 1);
        let completion = permit(&lease, first).queued();
        assert_eq!(*lease.state.lock().phase(true), ConnectionPhase::Queued);
        assert!(matches!(lease.claim(first), CollectionClaim::RequestOnly));
        let expected = match outcome {
            Some(CollectionResult::Stored) => ConnectionPhase::Stored,
            Some(CollectionResult::Rejected) => ConnectionPhase::Rejected,
            Some(CollectionResult::Unconfirmed) | None => ConnectionPhase::Unconfirmed,
        };
        if let Some(outcome) = outcome {
            completion.finish(outcome);
        } else {
            drop(completion);
        }
        assert_eq!(*lease.state.lock().phase(true), expected);
        assert!(matches!(lease.claim(first), CollectionClaim::RequestOnly));
        assert!(matches!(
            lease.claim(owner(false, 2)),
            CollectionClaim::OwnerMismatch
        ));
    }
}

#[tokio::test]
async fn layer_allocates_independent_connection_ownership() {
    let service = CollectionLayer.into_layer(service_fn(async |input: ServiceInput<()>| {
        Ok::<_, Infallible>(input.extensions().get_arc::<CollectionLease>().unwrap())
    }));
    let a = service.serve(ServiceInput::new(())).await.unwrap();
    let b = service.serve(ServiceInput::new(())).await.unwrap();
    assert!(!Arc::ptr_eq(&a, &b));
    let _a = permit(&a, owner(false, 1));
    let _b = permit(&b, owner(true, 2));
    assert!(matches!(
        a.claim(owner(false, 2)),
        CollectionClaim::OwnerMismatch
    ));
}
