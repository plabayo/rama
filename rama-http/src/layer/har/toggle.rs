use std::future::ready;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

use rama_core::telemetry::tracing;

pub trait Toggle: Send + Sync + 'static {
    fn status(&self) -> impl Future<Output = bool> + Send + '_;
}

impl Toggle for bool {
    fn status(&self) -> impl Future<Output = Self> + Send + '_ {
        ready(*self)
    }
}

impl<T: Toggle> Toggle for Option<T> {
    async fn status(&self) -> bool {
        if let Some(toggle) = self {
            toggle.status().await
        } else {
            false
        }
    }
}

impl Toggle for AtomicBool {
    fn status(&self) -> impl Future<Output = bool> + Send + '_ {
        ready(self.load(Ordering::Acquire))
    }
}

impl<T: Toggle> Toggle for Arc<T> {
    fn status(&self) -> impl Future<Output = bool> + Send + '_ {
        (**self).status()
    }
}

impl<F, Fut> Toggle for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output: Toggle> + Send + 'static,
{
    async fn status(&self) -> bool {
        (self)().await.status().await
    }
}

macro_rules! impl_toggle_either {
    ($id:ident, $($variant:ident),+ $(,)?) => {
        impl<$($variant),+> Toggle for rama_core::combinators::$id<$($variant),+>
        where
            $($variant: Toggle),+
        {
            async fn status(&self) -> bool {
                match self {
                    $(
                        rama_core::combinators::$id::$variant(inner) => inner.status().await,
                    )+
                }
            }
        }
    };
}

rama_core::combinators::impl_either!(impl_toggle_either);

pub fn toggle_from_mpsc_recv<T, C>(mut rx: mpsc::Receiver<T>, cancel: C) -> Arc<AtomicBool>
where
    T: Send + 'static,
    C: Future + Send + 'static,
{
    let toggle: Arc<AtomicBool> = Default::default();
    let flag = toggle.clone();
    tokio::spawn(async move {
        let mut cancel = std::pin::pin!(cancel);
        loop {
            tokio::select! {
                _ = cancel.as_mut() => {
                    tracing::trace!("MPSC Toggle cancelled via cancel future; exit");
                    return;
                }
                res = rx.recv() => {
                    if res.is_some() {
                        let state = !flag.fetch_xor(true, Ordering::AcqRel);
                        tracing::trace!("MPSC Toggle received trigger via receiver, new state: {state}");
                    } else {
                        tracing::trace!("MPSC Toggle cancelled via closed channel; exit");
                        return;
                    }
                }
            }
        }
    });
    toggle
}

pub fn mpsc_toggle<C>(buffer: usize, cancel: C) -> (Arc<AtomicBool>, mpsc::Sender<()>)
where
    C: Future + Send + 'static,
{
    let (tx, rx) = mpsc::channel(buffer);
    let toggle = toggle_from_mpsc_recv(rx, cancel);
    (toggle, tx)
}

pub fn toggle_from_mpsc_unbounded_recv<T, C>(
    mut rx: mpsc::UnboundedReceiver<T>,
    cancel: C,
) -> Arc<AtomicBool>
where
    T: Send + 'static,
    C: Future + Send + 'static,
{
    let toggle: Arc<AtomicBool> = Default::default();
    let flag = toggle.clone();
    tokio::spawn(async move {
        let mut cancel = std::pin::pin!(cancel);
        loop {
            tokio::select! {
                _ = cancel.as_mut() => {
                    tracing::trace!("uMPSC Toggle cancelled via cancel future; exit");
                    return;
                }
                res = rx.recv() => {
                    if res.is_some() {
                        let state = flag.fetch_xor(true, Ordering::AcqRel);
                        tracing::trace!("uMPSC Toggle received trigger via receiver, new state: {state}");
                    } else {
                        tracing::trace!("uMPSC Toggle cancelled via closed channel; exit");
                        return;
                    }
                }
            }
        }
    });
    toggle
}

pub fn mpsc_unbounded_toggle<C>(cancel: C) -> (Arc<AtomicBool>, mpsc::UnboundedSender<()>)
where
    C: Future + Send + 'static,
{
    let (tx, rx) = mpsc::unbounded_channel();
    let toggle = toggle_from_mpsc_unbounded_recv(rx, cancel);
    (toggle, tx)
}

#[cfg(target_family = "unix")]
pub fn mpsc_toggle_for_unix_signal<C>(
    signal: tokio::signal::unix::SignalKind,
    cancel: C,
) -> Result<Arc<AtomicBool>, std::io::Error>
where
    C: Future + Send + 'static,
{
    let mut signal = tokio::signal::unix::signal(signal)?;

    let toggle: Arc<AtomicBool> = Default::default();
    let flag = toggle.clone();

    tokio::spawn(async move {
        let mut cancel = std::pin::pin!(cancel);
        loop {
            tokio::select! {
                _ = cancel.as_mut() => {
                    tracing::trace!("unix signal trigger cancelled via cancel future; exit");
                    return;
                }
                res = signal.recv() => {
                    if res.is_some() {
                        let state = flag.fetch_xor(true, Ordering::AcqRel);
                        tracing::trace!("unix signal triggered, new state: {state}");
                    } else {
                        tracing::trace!("unix signal closed: cancel and exit");
                        return;
                    }
                }
            }
        }
    });

    Ok(toggle)
}
