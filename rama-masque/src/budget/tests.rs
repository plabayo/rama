use super::*;
use std::{sync::atomic::Ordering, time::Duration};

// Exercise a protocol charge ceiling independently of a wire packet format.
const MAX_CHARGE: u64 = 128;

#[test]
fn a_spent_quota_stays_spent_at_the_counters_limit() {
    let account = TunnelBudget::new()
        .with_min_charge(u64::MAX)
        .with_quota(MAX_CHARGE)
        .account_for(None, MAX_CHARGE);
    assert_eq!(account.charge(false, 0), Charge::Paid);
    for _ in 0..4 {
        assert_eq!(account.charge(false, 0), Charge::OverQuota);
    }
    // The counter itself saturates instead of wrapping back below the quota.
    let account = TunnelBudget::new()
        .with_quota(u64::MAX - 1)
        .account_for(None, MAX_CHARGE);
    account.charged.store(u64::MAX - 10, Ordering::Relaxed);
    assert_eq!(account.charge(true, 1_000), Charge::OverQuota);
    assert_eq!(account.charge(true, 1_000), Charge::OverQuota);
    assert_eq!(account.charged.load(Ordering::Relaxed), u64::MAX);

    // The largest quota is spent too once the counter cannot go further.
    let account = TunnelBudget::new()
        .with_min_charge(0)
        .with_quota(u64::MAX)
        .account_for(None, MAX_CHARGE);
    account.charged.store(u64::MAX - 10, Ordering::Relaxed);
    assert_eq!(account.charge(false, 10), Charge::Paid);
    assert_eq!(account.charge(false, 1), Charge::OverQuota);
    assert_eq!(account.charge(false, 1), Charge::OverQuota);
}

#[tokio::test(start_paused = true)]
async fn rate_refusal_does_not_consume_tunnel_quota() {
    let rate = DatagramRate::new(Rate::per_sec(1), Rate::per_sec(1000));
    for to_client in [false, true] {
        let account = TunnelBudget::new()
            .with_to_target(rate)
            .with_to_client(rate)
            .with_quota(200)
            .account_for(None, u64::MAX);
        assert_eq!(account.charge(to_client, 100), Charge::Paid);
        assert_eq!(account.charge(to_client, 100), Charge::RateLimited);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(account.charge(to_client, 100), Charge::Paid);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(account.charge(to_client, 1), Charge::OverQuota);
    }
}

#[tokio::test(start_paused = true)]
async fn a_principals_refusal_leaves_the_tunnel_uncharged() {
    let principal = std::sync::Arc::new(
        PrincipalBudget::new()
            .with_to_target(DatagramRate::new(Rate::per_sec(1), Rate::per_sec(1000)))
            .spend(),
    );
    let account = TunnelBudget::new()
        .with_min_charge(0)
        .with_to_target(
            DatagramRate::new(Rate::per_sec(1), Rate::per_sec(1000))
                .with_packet_burst(std::num::NonZeroU64::new(2).unwrap()),
        )
        .account_for(Some(principal), u64::MAX);
    assert_eq!(account.charge(false, 1), Charge::Paid);
    // Refused by the principal: the tunnel's second packet is still there, right away.
    assert_eq!(account.charge(false, 1), Charge::RateLimited);
    let tunnel = account.to_target.as_ref().unwrap();
    assert!(tunnel.try_spend(0));
}
