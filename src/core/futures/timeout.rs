use std::{future::Future, pin, task, time};

pub struct Timeout {
    start_time: time::Instant,
    duration: time::Duration,
}

impl Timeout {
    pub fn new(duration: time::Duration) -> Self {
        Self {
            start_time: time::Instant::now(),
            duration,
        }
    }
}

impl Default for Timeout {
    fn default() -> Self {
        Self::new(time::Duration::from_secs(30))
    }
}

impl Future for Timeout {
    type Output = ();

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        if self.start_time.elapsed() >= self.duration {
            task::Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            task::Poll::Pending
        }
    }
}
