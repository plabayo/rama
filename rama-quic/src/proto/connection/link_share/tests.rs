use std::ops::Range;

use super::{LINK_BITS_PER_SECOND, Outcome, Reordering, Rival, Scenario};
use crate::proto::Duration;

/// Scheduling delays of a sender's task: one well below the link's packet time, one above it.
const JITTERS: [Duration; 2] = [Duration::from_micros(200), Duration::from_millis(2)];
/// Packets per acknowledgement of the receivers the sender meets in practice.
const ACK_RATES: [usize; 3] = [1, 2, 8];
/// The queue of the interop simulator's link, a fraction of the packets in flight over it.
const SHALLOW_QUEUE: usize = 25;
/// A queue of about one round trip of the link's traffic, as sized for bulk transfers.
const DEEP_QUEUE: usize = 100;
/// Propagation delay of a short path in each direction.
const LINK_DELAY: Duration = Duration::from_millis(15);
/// The same for a path across a continent, where slow start has more to overshoot.
const LONG_LINK_DELAY: Duration = Duration::from_millis(50);
const KIB: u64 = 1024;

/// The measured flow alone on the short, shallow link with a never-ending stream.
fn scenario(seed: u64) -> Scenario {
    Scenario {
        seed,
        competitor: None,
        rival: Rival::Cubic,
        queue: SHALLOW_QUEUE,
        ack_every: 2,
        jitter: JITTERS[0],
        delay: LINK_DELAY,
        transfer: None,
        reordering: None,
        duration: Duration::from_secs(60),
    }
}

fn outcomes(
    seeds: Range<u64>,
    competitor: Option<usize>,
    ack_every: usize,
    jitter: Duration,
) -> Vec<Outcome> {
    outcomes_on(
        seeds,
        competitor,
        Rival::Cubic,
        SHALLOW_QUEUE,
        ack_every,
        jitter,
    )
}

fn outcomes_on(
    seeds: Range<u64>,
    competitor: Option<usize>,
    rival: Rival,
    queue: usize,
    ack_every: usize,
    jitter: Duration,
) -> Vec<Outcome> {
    seeds
        .map(|seed| {
            Scenario {
                competitor,
                rival,
                queue,
                ack_every,
                jitter,
                ..scenario(seed)
            }
            .run()
        })
        .collect()
}

fn mean(outcomes: &[Outcome], value: fn(&Outcome) -> f64) -> f64 {
    outcomes.iter().map(value).sum::<f64>() / outcomes.len() as f64
}

fn share(outcome: &Outcome) -> f64 {
    outcome.kbps / (outcome.kbps + outcome.competitor_kbps)
}

/// One row of the table: the mean over the seeds, and the spread of the throughput.
#[expect(
    clippy::print_stdout,
    reason = "the measurements are the output of these tests"
)]
fn report(label: &str, ack_every: usize, jitter: Duration, outcomes: &[Outcome]) {
    let slowest = outcomes.iter().map(|o| o.kbps).fold(f64::MAX, f64::min);
    let fastest = outcomes.iter().map(|o| o.kbps).fold(0.0, f64::max);
    println!(
        "jitter {:>4}us {label:<8} ack/{ack_every}: kbps {:5.0} [{slowest:5.0}..{fastest:5.0}] \
         other {:5.0} share {:5.1}% loss {:4.2}% reductions {:5.1} burst {:4.2}",
        jitter.as_micros(),
        mean(outcomes, |o| o.kbps),
        mean(outcomes, |o| o.competitor_kbps),
        100.0 * mean(outcomes, share),
        100.0 * mean(outcomes, |o| o.loss_rate),
        mean(outcomes, |o| o.reductions as f64),
        mean(outcomes, |o| o.mean_burst),
    );
}

#[test]
fn a_flow_alone_on_the_link_uses_nearly_all_of_it() {
    let link_kbps = LINK_BITS_PER_SECOND as f64 / 1000.0;
    for jitter in JITTERS {
        for ack_every in ACK_RATES {
            let outcomes = outcomes(0..2, None, ack_every, jitter);
            report("alone", ack_every, jitter, &outcomes);
            for outcome in outcomes {
                assert!(
                    outcome.kbps >= 0.9 * link_kbps,
                    "ack/{ack_every}, jitter {jitter:?}: {outcome:?}"
                );
            }
        }
    }
}

#[test]
fn equal_scenarios_measure_the_same() {
    let scenario = Scenario {
        competitor: Some(2),
        jitter: Duration::from_millis(2),
        duration: Duration::from_secs(10),
        ..scenario(7)
    };
    assert_eq!(scenario.run(), scenario.run());
    assert_ne!(
        scenario.run(),
        Scenario {
            seed: 8,
            ..scenario
        }
        .run()
    );
}

/// The floors sit a few points of link share under what the sender measures today, which is
/// more than the spread between seeds and less than what a burstier or more timid sender loses.
#[test]
fn a_flow_keeps_its_share_of_the_link_beside_a_cubic_flow() {
    for jitter in JITTERS {
        for (ack_every, floor) in ACK_RATES.into_iter().zip([0.58, 0.48, 0.38]) {
            let outcomes = outcomes(0..5, Some(2), ack_every, jitter);
            report("shared", ack_every, jitter, &outcomes);
            let share = mean(&outcomes, share);
            assert!(
                share >= floor,
                "ack/{ack_every}, jitter {jitter:?}: a share of {share:.3} is under {floor}"
            );
        }
    }
}

#[test]
#[ignore = "a wider sweep to read, not to assert on; run with --ignored --nocapture"]
fn table_of_link_shares_over_more_seeds_and_a_competitor_acknowledged_per_packet() {
    for jitter in JITTERS {
        let alone = outcomes(0..40, None, 2, jitter);
        report("alone", 2, jitter, &alone);
        for (label, competitor) in [("shared", 2), ("vs-ack/1", 1)] {
            for ack_every in ACK_RATES {
                let outcomes = outcomes(0..40, Some(competitor), ack_every, jitter);
                report(label, ack_every, jitter, &outcomes);
            }
        }
    }
}

#[test]
#[ignore = "a wider sweep to read, not to assert on; run with --ignored --nocapture"]
fn table_of_link_shares_on_a_deep_queue_and_beside_a_reno_flow() {
    for jitter in JITTERS {
        for (label, rival, queue) in [
            ("deep", Rival::Cubic, DEEP_QUEUE),
            ("reno", Rival::Reno, SHALLOW_QUEUE),
            ("renodeep", Rival::Reno, DEEP_QUEUE),
        ] {
            let alone = outcomes_on(0..2, None, rival, queue, 2, jitter);
            report("alone", 2, jitter, &alone);
            for ack_every in ACK_RATES {
                let outcomes = outcomes_on(0..20, Some(2), rival, queue, ack_every, jitter);
                report(label, ack_every, jitter, &outcomes);
            }
        }
    }
}

/// The time the link itself needs for a transfer: its bytes at the link's rate and one round
/// trip for the last of them to be asked for and to arrive.
fn link_time(bytes: u64, delay: Duration) -> Duration {
    Duration::from_secs_f64(bytes as f64 * 8.0 / LINK_BITS_PER_SECOND as f64) + 2 * delay
}

fn transfers(
    seeds: Range<u64>,
    bytes: u64,
    competitor: Option<usize>,
    queue: usize,
    delay: Duration,
) -> Vec<Outcome> {
    seeds
        .map(|seed| {
            Scenario {
                competitor,
                queue,
                delay,
                transfer: Some(bytes),
                ..scenario(seed)
            }
            .run()
        })
        .collect()
}

fn millis(outcome: &Outcome) -> f64 {
    outcome
        .completion
        .map_or(f64::INFINITY, |time| time.as_secs_f64() * 1000.0)
}

#[test]
fn a_transfer_alone_on_the_link_takes_little_longer_than_the_link_needs() {
    for delay in [LINK_DELAY, LONG_LINK_DELAY] {
        for queue in [SHALLOW_QUEUE, DEEP_QUEUE] {
            for bytes in [100 * KIB, 1024 * KIB] {
                let ideal = link_time(bytes, delay);
                for outcome in transfers(0..2, bytes, None, queue, delay) {
                    let taken = outcome.completion.expect("the transfer completes");
                    assert!(taken >= ideal, "{taken:?} is less than the link needs");
                    // Slow start from a small window costs round trips the link does not.
                    assert!(
                        taken <= 3 * ideal,
                        "{bytes} bytes, {delay:?}, queue {queue}: {taken:?} against {ideal:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_transfer_completes_beside_a_competing_flow_and_after_losing_packets() {
    let alone = transfers(0..1, 1024 * KIB, None, SHALLOW_QUEUE, LONG_LINK_DELAY)[0];
    let shared = transfers(0..1, 1024 * KIB, Some(2), SHALLOW_QUEUE, LINK_DELAY)[0];
    for outcome in [alone, shared] {
        assert!(outcome.lost > 0, "{outcome:?}");
        assert!(outcome.completion.is_some(), "{outcome:?}");
    }
}

fn reordered(seed: u64, competitor: Option<usize>, reordering: Option<Reordering>) -> Outcome {
    Scenario {
        competitor,
        reordering,
        duration: Duration::from_secs(10),
        ..scenario(seed)
    }
    .run()
}

#[test]
fn packets_that_arrive_in_order_are_not_declared_lost_in_error() {
    let plain = reordered(3, Some(2), None);
    assert_eq!(plain.spurious, 0);
    let none_late = Reordering {
        fraction: 0.0,
        extra: Duration::from_millis(20),
    };
    assert_eq!(reordered(3, Some(2), Some(none_late)), plain);
    // Late by less than the link spends on one packet, so still ahead of the next one.
    let barely_late = Reordering {
        fraction: 0.05,
        extra: Duration::from_micros(500),
    };
    assert_eq!(reordered(3, Some(2), Some(barely_late)).spurious, 0);
}

#[test]
fn packets_overtaken_by_several_others_are_declared_lost_and_acknowledged_later() {
    let late = Reordering {
        fraction: 0.01,
        extra: Duration::from_millis(8),
    };
    let plain = reordered(3, None, None);
    let outcome = reordered(3, None, Some(late));
    assert!(outcome.spurious > 0, "{outcome:?}");
    assert!(outcome.spurious <= outcome.lost, "{outcome:?}");
    assert!(outcome.reductions > plain.reductions, "{outcome:?}");
    assert_eq!(outcome, reordered(3, None, Some(late)));
}

#[test]
fn a_flow_alone_keeps_its_throughput_when_packets_arrive_late() {
    let plain = reordered(3, None, None);
    for extra in [5, 20].map(Duration::from_millis) {
        for fraction in [0.01, 0.05] {
            let late = Reordering { fraction, extra };
            let outcome = reordered(3, None, Some(late));
            assert!(outcome.spurious > 0, "{late:?}: {outcome:?}");
            // Later than loss detection waits however far it adapts, so the undoing carries it.
            if extra == Duration::from_millis(20) {
                assert!(2 * outcome.restored > outcome.spurious, "{outcome:?}");
            }
            assert!(
                outcome.kbps >= 0.95 * plain.kbps,
                "{late:?}: {outcome:?} against {plain:?}"
            );
        }
    }
}

#[test]
fn packets_a_few_others_overtake_stop_being_declared_lost() {
    // Late by about four packets of the link, more than the three loss detection starts at.
    let late = Reordering {
        fraction: 0.05,
        extra: Duration::from_millis(5),
    };
    let outcome = Scenario {
        reordering: Some(late),
        ..scenario(3)
    }
    .run();
    assert!(outcome.spurious > 0, "{outcome:?}");
    // Thousands arrive late; the first few teach loss detection to wait for them.
    assert!(outcome.spurious < 20, "{outcome:?}");
}

#[test]
fn a_flow_keeps_its_share_of_the_link_when_packets_arrive_late() {
    let late = Reordering {
        fraction: 0.05,
        extra: Duration::from_millis(5),
    };
    let outcomes: Vec<Outcome> = (0..5)
        .map(|seed| {
            Scenario {
                competitor: Some(2),
                reordering: Some(late),
                ..scenario(seed)
            }
            .run()
        })
        .collect();
    let share = mean(&outcomes, share);
    // The floor of the same flow with its packets in order.
    assert!(share >= 0.48, "a share of {share:.3}");
}

#[test]
#[ignore = "a wider sweep to read, not to assert on; run with --ignored --nocapture"]
#[expect(
    clippy::print_stdout,
    reason = "the measurements are the output of these tests"
)]
fn table_of_transfer_times() {
    for delay in [LINK_DELAY, LONG_LINK_DELAY] {
        for (depth, queue) in [("shallow", SHALLOW_QUEUE), ("deep", DEEP_QUEUE)] {
            for (label, competitor) in [("alone", None), ("shared", Some(2))] {
                for bytes in [100 * KIB, 1024 * KIB, 5 * 1024 * KIB] {
                    let outcomes = transfers(0..40, bytes, competitor, queue, delay);
                    let fastest = outcomes.iter().map(millis).fold(f64::MAX, f64::min);
                    let slowest = outcomes.iter().map(millis).fold(0.0, f64::max);
                    println!(
                        "delay {:>2}ms {depth:<7} {label:<6} {:>4}KiB: ms {:6.0} \
                         [{fastest:6.0}..{slowest:6.0}] link {:5.0} lost {:5.1} spurious {:4.1} \
                         reductions {:4.1}",
                        delay.as_millis(),
                        bytes / KIB,
                        mean(&outcomes, millis),
                        link_time(bytes, delay).as_secs_f64() * 1000.0,
                        mean(&outcomes, |o| o.lost as f64),
                        mean(&outcomes, |o| o.spurious as f64),
                        mean(&outcomes, |o| o.reductions as f64),
                    );
                }
            }
        }
    }
}

#[test]
#[ignore = "a wider sweep to read, not to assert on; run with --ignored --nocapture"]
#[expect(
    clippy::print_stdout,
    reason = "the measurements are the output of these tests"
)]
fn table_of_losses_declared_in_error_when_packets_arrive_late() {
    for (label, competitor) in [("alone", None), ("shared", Some(2))] {
        for extra in [2, 5, 20].map(Duration::from_millis) {
            for fraction in [0.0, 0.001, 0.01, 0.05] {
                let outcomes: Vec<Outcome> = (0..10)
                    .map(|seed| {
                        Scenario {
                            competitor,
                            reordering: Some(Reordering { fraction, extra }),
                            ..scenario(seed)
                        }
                        .run()
                    })
                    .collect();
                println!(
                    "{label:<6} late {:>2}ms {:4.1}%: kbps {:5.0} share {:5.1}% lost {:6.1} \
                     spurious {:6.1} reductions {:5.1} restored {:5.1}",
                    extra.as_millis(),
                    100.0 * fraction,
                    mean(&outcomes, |o| o.kbps),
                    100.0 * mean(&outcomes, share),
                    mean(&outcomes, |o| o.lost as f64),
                    mean(&outcomes, |o| o.spurious as f64),
                    mean(&outcomes, |o| o.reductions as f64),
                    mean(&outcomes, |o| o.restored as f64),
                );
            }
        }
    }
}
