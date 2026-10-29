use std::sync::Arc;

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
        .account_for(None);
    assert_eq!(account.charge_to_target(60), Charge::Paid);
    assert_eq!(account.charge_to_client(40), Charge::Paid);
    assert_eq!(account.charge_to_target(1), Charge::OverQuota);
    // An oversized declaration costs at most one payload, and still counts.
    let account = TunnelBudget::new().with_quota(MAX_CHARGE).account_for(None);
    assert_eq!(account.charge_to_target(u64::MAX), Charge::Paid);
    assert_eq!(account.charge_to_target(0), Charge::OverQuota);
}

#[test]
fn the_unanswered_allowance_ends_at_either_bound_or_an_answer() {
    let account = TunnelBudget::new()
        .with_unanswered(2, 100)
        .account_for(None);
    assert!(account.may_reach_target(50));
    assert!(account.may_reach_target(50));
    assert!(!account.may_reach_target(0), "packets spent");

    let account = TunnelBudget::new()
        .with_unanswered(10, 100)
        .account_for(None);
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
        .account_for(None);
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
        .account_for(None);
    assert_eq!(account.charge_to_target(0), Charge::Paid);
    for _ in 0..4 {
        assert_eq!(account.charge_to_target(0), Charge::OverQuota);
    }
    // The counter itself saturates instead of wrapping back below the quota.
    let account = TunnelBudget::new()
        .with_quota(u64::MAX - 1)
        .account_for(None);
    account.charged.store(u64::MAX - 10, Ordering::Relaxed);
    assert_eq!(account.charge_to_client(1_000), Charge::OverQuota);
    assert_eq!(account.charge_to_client(1_000), Charge::OverQuota);
    assert_eq!(account.charged.load(Ordering::Relaxed), u64::MAX);

    // The largest quota is spent too once the counter cannot go further.
    let account = TunnelBudget::new()
        .with_min_charge(0)
        .with_quota(u64::MAX)
        .account_for(None);
    account.charged.store(u64::MAX - 10, Ordering::Relaxed);
    assert_eq!(account.charge_to_target(10), Charge::Paid);
    assert_eq!(account.charge_to_target(1), Charge::OverQuota);
    assert_eq!(account.charge_to_target(1), Charge::OverQuota);
}

fn shared(budget: PrincipalBudget) -> Arc<PrincipalSpend> {
    Arc::new(budget.spend())
}

fn packets(burst: u64) -> DatagramRate {
    DatagramRate::new(Rate::per_sec(1), Rate::per_sec(1_000_000)).with_packet_burst(burst)
}

#[tokio::test(start_paused = true)]
async fn a_principals_tunnels_spend_one_budget() {
    let principal = shared(PrincipalBudget::new().with_to_target(packets(3)));
    let first = TunnelBudget::unlimited().account_for(Some(principal.clone()));
    let second = TunnelBudget::unlimited().account_for(Some(principal));
    assert_eq!(first.charge_to_target(10), Charge::Paid);
    assert_eq!(second.charge_to_target(10), Charge::Paid);
    assert_eq!(first.charge_to_target(10), Charge::Paid);
    assert_eq!(second.charge_to_target(10), Charge::RateLimited);
    assert_eq!(first.charge_to_target(10), Charge::RateLimited);
    // The other direction has no principal rate.
    assert_eq!(second.charge_to_client(10), Charge::Paid);
}

#[tokio::test(start_paused = true)]
async fn a_principals_refusal_leaves_the_tunnel_uncharged() {
    let principal = shared(PrincipalBudget::new().with_to_target(packets(1)));
    let account = TunnelBudget::new()
        .with_min_charge(0)
        .with_to_target(packets(2))
        .account_for(Some(principal));
    assert_eq!(account.charge_to_target(1), Charge::Paid);
    // Refused by the principal: the tunnel's second packet is still there, right away.
    assert_eq!(account.charge_to_target(1), Charge::RateLimited);
    let tunnel = account.to_target.as_ref().unwrap();
    assert_eq!(tunnel.packets.try_acquire(1), Acquire::Granted);
}

#[tokio::test(start_paused = true)]
async fn a_principals_quota_window_starts_at_its_first_charge() {
    let principal = shared(PrincipalBudget::new().with_quota(128, Duration::from_secs(10)));
    assert_eq!(
        principal.quota_window(Instant::now()),
        QuotaWindowState::Closed
    );
    tokio::time::advance(Duration::from_secs(5)).await;
    let start = Instant::now();
    let account = TunnelBudget::unlimited()
        .with_min_charge(64)
        .account_for(Some(principal.clone()));
    assert_eq!(account.charge_to_target(0), Charge::Paid);
    assert_eq!(account.charge_to_client(0), Charge::Paid);
    assert_eq!(account.charge_to_target(0), Charge::OverQuota);
    assert_eq!(
        principal.quota_window(Instant::now()),
        QuotaWindowState::OpenUntil(start + Duration::from_secs(10))
    );
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(account.charge_to_target(0), Charge::Paid);
}

/// The first-reply allowance belongs to a tunnel; the principal's rates are shared and keep
/// their debt across tunnels.
#[tokio::test(start_paused = true)]
async fn replacement_tunnels_get_a_fresh_allowance_but_not_fresh_principal_budget() {
    let principal = shared(PrincipalBudget::new().with_to_target(packets(3)));
    let tunnel = TunnelBudget::new().with_unanswered(1, 1_000);
    let a = tunnel.account_for(Some(principal.clone()));
    let b = tunnel.account_for(Some(principal.clone()));
    // A spends the principal's burst on a target that never answers.
    assert_eq!(a.charge_to_target(10), Charge::Paid);
    assert!(a.may_reach_target(10));
    assert_eq!(a.charge_to_target(10), Charge::Paid);
    assert!(!a.may_reach_target(10), "A's allowance is spent");
    // B's target answers: that releases B only.
    assert_eq!(b.charge_to_client(10), Charge::Paid);
    assert!(!a.may_reach_target(10));
    drop(a);
    // C replaces A: a fresh allowance, but the principal's budget is as A and B left it.
    let c = tunnel.account_for(Some(principal));
    assert!(c.may_reach_target(10));
    assert_eq!(b.charge_to_target(10), Charge::Paid);
    assert_eq!(c.charge_to_target(10), Charge::RateLimited);
}

#[tokio::test(start_paused = true)]
async fn a_principals_tunnels_share_its_output_rate() {
    let principal = shared(PrincipalBudget::new().with_to_client(packets(1)));
    let first = TunnelBudget::unlimited().account_for(Some(principal.clone()));
    let second = TunnelBudget::unlimited().account_for(Some(principal));
    assert_eq!(first.charge_to_client(10), Charge::Paid);
    assert_eq!(second.charge_to_client(10), Charge::RateLimited);
    // Input has no principal rate here.
    assert_eq!(second.charge_to_target(10), Charge::Paid);
}

#[tokio::test(start_paused = true)]
async fn an_unbounded_quota_window_never_overflows_or_closes() {
    let principal = shared(PrincipalBudget::new().with_quota(128, Duration::MAX));
    let account = TunnelBudget::unlimited()
        .with_min_charge(64)
        .account_for(Some(principal.clone()));
    assert_eq!(account.charge_to_target(0), Charge::Paid);
    assert_eq!(account.charge_to_target(0), Charge::Paid);
    assert_eq!(account.charge_to_target(0), Charge::OverQuota);
    tokio::time::advance(Duration::from_secs(3600)).await;
    assert_eq!(account.charge_to_target(0), Charge::OverQuota);
    assert_eq!(
        principal.quota_window(Instant::now()),
        QuotaWindowState::OpenBeyond
    );
}
