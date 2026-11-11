use std::ops::Range;

use super::{LINK_BITS_PER_SECOND, Outcome, Scenario};
use crate::proto::Duration;

/// Scheduling delays of a sender's task: one well below the link's packet time, one above it.
const JITTERS: [Duration; 2] = [Duration::from_micros(200), Duration::from_millis(2)];
/// Packets per acknowledgement of the receivers the sender meets in practice.
const ACK_RATES: [usize; 3] = [1, 2, 8];

fn outcomes(
    seeds: Range<u64>,
    competitor: Option<usize>,
    ack_every: usize,
    jitter: Duration,
) -> Vec<Outcome> {
    seeds
        .map(|seed| {
            Scenario {
                seed,
                competitor,
                ack_every,
                jitter,
                duration: Duration::from_secs(60),
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
        seed: 7,
        competitor: Some(2),
        ack_every: 2,
        jitter: Duration::from_millis(2),
        duration: Duration::from_secs(10),
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
        for (ack_every, floor) in ACK_RATES.into_iter().zip([0.55, 0.44, 0.35]) {
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
