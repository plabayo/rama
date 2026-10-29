use super::*;

#[test]
fn a_charge_is_at_least_the_minimum_and_at_most_one_udp_payload() {
    let budget = TunnelBudget::new().with_min_charge(64);
    assert_eq!(budget.cost(0), 64);
    assert_eq!(budget.cost(100), 100);
    assert_eq!(budget.cost(u64::MAX), MAX_CHARGE);
    assert_eq!(TunnelBudget::new().with_min_charge(0).cost(0), 0);
}

#[test]
fn the_quota_admits_up_to_its_last_byte() {
    let account = TunnelBudget::new()
        .with_min_charge(0)
        .with_quota(100)
        .account();
    assert_eq!(account.charge_to_target(60), Charge::Paid);
    assert_eq!(account.charge_to_client(40), Charge::Paid);
    assert_eq!(account.charge_to_target(1), Charge::OverQuota);
    // An oversized declaration costs at most one payload, and still counts.
    let account = TunnelBudget::new().with_quota(MAX_CHARGE).account();
    assert_eq!(account.charge_to_target(u64::MAX), Charge::Paid);
    assert_eq!(account.charge_to_target(0), Charge::OverQuota);
}

#[test]
fn the_unanswered_allowance_ends_at_either_bound_or_an_answer() {
    let account = TunnelBudget::new().with_unanswered(2, 100).account();
    assert!(account.may_reach_target(50));
    assert!(account.may_reach_target(50));
    assert!(!account.may_reach_target(0), "packets spent");

    let account = TunnelBudget::new().with_unanswered(10, 100).account();
    assert!(account.may_reach_target(100));
    assert!(!account.may_reach_target(1), "bytes spent");
    assert_eq!(account.charge_to_client(0), Charge::Paid);
    assert!(account.may_reach_target(1_000), "the target answered");
}

#[tokio::test(start_paused = true)]
async fn a_rate_needs_a_packet_and_the_bytes() {
    let rate = DatagramRate::new(Rate::per_sec(2), Rate::per_sec(1000)).with_byte_burst(150);
    let account = TunnelBudget::new()
        .with_min_charge(0)
        .with_to_target(rate)
        .account();
    assert_eq!(account.charge_to_target(100), Charge::Paid);
    // A packet is left, but not the bytes; the packet stays spent.
    assert_eq!(account.charge_to_target(100), Charge::RateLimited);
    assert_eq!(account.charge_to_target(10), Charge::RateLimited);
    // The other direction has no rate.
    assert_eq!(account.charge_to_client(1_000_000), Charge::Paid);
}

#[test]
fn a_large_minimum_never_charges_more_than_one_payload() {
    assert_eq!(
        TunnelBudget::new().with_min_charge(u64::MAX).cost(0),
        MAX_CHARGE
    );
}

#[test]
fn a_spent_quota_stays_spent_at_the_counters_limit() {
    let account = TunnelBudget::new()
        .with_min_charge(u64::MAX)
        .with_quota(MAX_CHARGE)
        .account();
    assert_eq!(account.charge_to_target(0), Charge::Paid);
    for _ in 0..4 {
        assert_eq!(account.charge_to_target(0), Charge::OverQuota);
    }
    // The counter itself saturates instead of wrapping back below the quota.
    let account = TunnelBudget::new().with_quota(u64::MAX - 1).account();
    account.charged.store(u64::MAX - 10, Ordering::Relaxed);
    assert_eq!(account.charge_to_client(1_000), Charge::OverQuota);
    assert_eq!(account.charge_to_client(1_000), Charge::OverQuota);
    assert_eq!(account.charged.load(Ordering::Relaxed), u64::MAX);

    // The largest quota is spent too once the counter cannot go further.
    let account = TunnelBudget::new()
        .with_min_charge(0)
        .with_quota(u64::MAX)
        .account();
    account.charged.store(u64::MAX - 10, Ordering::Relaxed);
    assert_eq!(account.charge_to_target(10), Charge::Paid);
    assert_eq!(account.charge_to_target(1), Charge::OverQuota);
    assert_eq!(account.charge_to_target(1), Charge::OverQuota);
}
