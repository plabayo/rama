use super::*;

fn begin(issuer: &mut SequenceIssuer, day: u32, nonce: u8) -> PendingSequence<'_> {
    issuer
        .begin(day, day, RetentionWindow::default(), || Ok([nonce; 12]))
        .unwrap()
}

#[test]
fn rejections_do_not_strand_sequences_or_consume_runs() {
    let mut issuer = SequenceIssuer::new(false);
    let first = begin(&mut issuer, 100, 1);
    let id = first.attempt().observation;
    first.finish(WriteDisposition::Rejected);
    for _ in 0..10_000 {
        let rejected = issuer
            .begin(100, 100, RetentionWindow::default(), || {
                panic!("rejection rotated run")
            })
            .unwrap();
        assert_eq!(rejected.attempt().observation, id);
        rejected.finish(WriteDisposition::Rejected);
    }
    begin(&mut issuer, 100, 2).finish(WriteDisposition::Confirmed);
    let next = begin(&mut issuer, 100, 3);
    assert_eq!(next.attempt().observation.run, id.run);
    assert_eq!(next.attempt().observation.sequence, 2);
    next.finish(WriteDisposition::Confirmed);
}

#[test]
fn cancellation_and_uncertain_commits_never_alias_an_id() {
    let mut issuer = SequenceIssuer::new(true);
    let first = begin(&mut issuer, 100, 1);
    let original = first.attempt().observation;
    drop(first);
    let second = begin(&mut issuer, 100, 2);
    assert_ne!(original.run, second.attempt().observation.run);
    assert_eq!(second.attempt().observation.sequence, 1);
    second.finish(WriteDisposition::Unconfirmed);
    let third = begin(&mut issuer, 100, 3);
    assert_eq!(
        third.attempt().observation.run,
        CaptureRunId::new(100, [3; 12]).0
    );
    third.finish(WriteDisposition::Confirmed);
}

#[test]
fn authorization_partitions_have_independent_contiguous_sequences() {
    let mut public = SequenceIssuer::new(false);
    let mut authorized = SequenceIssuer::new(true);
    for sequence in 1..=100 {
        let a = begin(&mut public, 100, 1);
        assert!(!a.attempt().authorized);
        assert_eq!(a.attempt().observation.sequence, sequence);
        a.finish(WriteDisposition::Confirmed);
        if sequence % 2 == 0 {
            let b = begin(&mut authorized, 100, 2);
            assert!(b.attempt().authorized);
            assert_eq!(b.attempt().observation.sequence, sequence / 2);
            b.finish(WriteDisposition::Confirmed);
        }
    }
}

#[test]
fn runs_rotate_only_after_expiry_or_sequence_exhaustion() {
    let mut issuer = SequenceIssuer::new(false);
    begin(&mut issuer, 100, 1).finish(WriteDisposition::Confirmed);
    let last = begin(&mut issuer, 113, 2);
    assert_eq!(
        last.attempt().observation.run,
        CaptureRunId::new(100, [1; 12]).0
    );
    last.finish(WriteDisposition::Confirmed);
    let next = begin(&mut issuer, 114, 2);
    assert_eq!(
        next.attempt().observation.run,
        CaptureRunId::new(114, [2; 12]).0
    );
    next.finish(WriteDisposition::Confirmed);
    issuer.run.as_mut().unwrap().next = u64::MAX;
    let last = begin(&mut issuer, 114, 3);
    assert_eq!(last.attempt().observation.sequence, u64::MAX);
    last.finish(WriteDisposition::Confirmed);
    let next = begin(&mut issuer, 114, 3);
    assert_eq!(
        next.attempt().observation.run,
        CaptureRunId::new(114, [3; 12]).0
    );
    assert_eq!(next.attempt().observation.sequence, 1);
}

#[test]
fn rejected_time_or_entropy_does_not_assign_an_observation() {
    let mut issuer = SequenceIssuer::new(false);
    issuer
        .begin(100, 100, RetentionWindow::default(), || {
            Err(ProfileDataError::Invalid("entropy unavailable").into())
        })
        .unwrap_err();
    assert!(issuer.run.is_none());
    begin(&mut issuer, 100, 1).finish(WriteDisposition::Confirmed);
    issuer
        .begin(101, 100, RetentionWindow::default(), || {
            panic!("existing run requested entropy")
        })
        .unwrap()
        .finish(WriteDisposition::Rejected);
    for (now, observed) in [(100, 100), (101, 102), (101, 87), (101, 99)] {
        issuer
            .begin(now, observed, RetentionWindow::default(), || {
                panic!("invalid time requested entropy")
            })
            .unwrap_err();
    }
    let next = begin(&mut issuer, 101, 2);
    assert_eq!(
        next.attempt().observation.run,
        CaptureRunId::new(100, [1; 12]).0
    );
    assert_eq!(next.attempt().observation.sequence, 2);
}
