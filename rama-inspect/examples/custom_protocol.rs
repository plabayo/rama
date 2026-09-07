//! A custom protocol controller requires no HTTP, TLS or filesystem feature.
use rama_core::futures::StreamExt;
use rama_inspect::intercept::{Interception, QueueLimits};
use std::time::Duration;

#[derive(Debug)]
struct Message {
    channel: u32,
    payload: Vec<u8>,
}
#[derive(Debug, PartialEq)]
enum Decision {
    Continue,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let controller = Interception::<Message, Decision>::default();
    let mut views = Box::pin(controller.subscribe());
    let message = Message {
        channel: 7,
        payload: vec![1, 2, 3],
    };
    let retained = message.payload.len() + std::mem::size_of::<Message>();
    let ticket = controller.enqueue(message, retained, QueueLimits::default())?;
    let pending = views.next().await.ok_or("controller closed")?;
    assert_eq!(pending[0].1.channel, 7);
    assert!(controller.resolve(pending[0].0, Decision::Continue));
    assert_eq!(
        ticket.wait(Duration::from_secs(30)).await,
        Ok(Decision::Continue)
    );
    Ok(())
}
