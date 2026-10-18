use super::fixture::selected;
use super::*;
use rama_core::extensions::Extensions;
use rama_net::client::pool::ConnectionReuse;
use rama_tls::client::ServerVerifyMode;
use rama_ua::profile::{
    format::canonical::ValueId, replay::connection::preparation::ConnectionPreparation,
};

#[tokio::test]
async fn negotiated_profile_reuse_matches_the_caller_before_compilation() {
    let (context, selection) = selected("prepared-profile");
    let connection = super::connection::established(Some((&context, &selection))).await;
    let reuse = connection.get_ref::<ConnectionReuse>().unwrap();
    let next = Extensions::new();
    context.clone().publish(&next);
    assert!(reuse.is_reusable());
    assert!(
        reuse.matches(&next),
        "uncompiled request must reuse the prepared connection"
    );

    TlsClientConfig::new()
        .with_server_verify(ServerVerifyMode::Disable)
        .write_to(&next);
    assert!(
        !reuse.matches(&next),
        "caller security policy must still partition the pool"
    );
    assert!(
        !reuse.matches(&Extensions::new()),
        "ordinary traffic cannot use a captured connection"
    );

    let (other, _) = selected("other-profile");
    let next = Extensions::new();
    other.publish(&next);
    assert!(
        !reuse.matches(&next),
        "different profiles must remain isolated"
    );

    let mut pinned = context;
    pinned.pins.connection = Some(ValueId([99; 32]));
    let next = Extensions::new();
    pinned.publish(&next);
    assert!(
        !reuse.matches(&next),
        "a new explicit pin cannot reuse an unpinned connection"
    );
}

#[test]
fn mismatched_pin_cannot_supply_a_profile_reuse_witness() {
    let (mut context, _) = selected("prepared-profile");
    context.pins.connection = Some(ValueId([99; 32]));
    let request = input();
    context.publish(request.extensions());
    ConnectionPreparation::prepare(&request, |_, _, _| Ok(())).unwrap_err();
}
