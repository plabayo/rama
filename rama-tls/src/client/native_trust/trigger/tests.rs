use super::*;
use rama_core::futures::{
    StreamExt as _,
    stream::{Empty, Iter, Once, empty, iter, once},
};
use std::{array, task::Waker};

#[test]
fn manual_requests_coalesce_and_report_closure() {
    let (first, trigger) = ChannelReloadTrigger::new();
    let second = first.clone();
    let mut trigger = (trigger, ChannelReloadTrigger::new().1).into_reload_stream();
    let cx = &mut Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut trigger).poll_next(cx).is_pending());
    first.request_reload().unwrap();
    second.request_reload().unwrap();
    assert_eq!(Pin::new(&mut trigger).poll_next(cx), Poll::Ready(Some(())));
    assert!(Pin::new(&mut trigger).poll_next(cx).is_pending());
    drop(trigger);
    let closed = second.request_reload().unwrap_err();
    assert_eq!(closed, ChannelReloadClosed::new());
    assert_eq!(closed.to_string(), "native trust reload channel is closed");
}

#[tokio::test]
async fn grouped_triggers_accept_nested_custom_sources_and_pinned_streams() {
    struct CustomTrigger;
    struct CustomKind;

    impl IntoNativeTrustReloadTrigger<CustomKind> for CustomTrigger {
        type Stream = Iter<array::IntoIter<(), 2>>;

        fn into_reload_stream(self) -> Self::Stream {
            iter([(), ()])
        }
    }

    // A single stream keeps its concrete, !Unpin type.
    let first: Once<_> = once(async {}).into_reload_stream();
    let pulse = || once(async {});
    let events = (
        first,
        (CustomTrigger, pulse()),
        pulse(),
        pulse(),
        pulse(),
        pulse(),
        pulse(),
        pulse(),
        pulse(),
        pulse(),
        pulse(),
        pulse(),
    )
        .into_reload_stream();
    assert_eq!(events.count().await, 14);
}

#[test]
fn four_triggers_keep_a_balanced_select_type() {
    type Pair = Select<Empty<()>, Empty<()>>;
    let _events: Select<Pair, Pair> = (empty(), empty(), empty(), empty()).into_reload_stream();
}
