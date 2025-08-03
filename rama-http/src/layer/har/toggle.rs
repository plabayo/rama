use crate::dep::core::futures::future::Either;
use std::future::ready;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub trait Toggle: Clone + Send + Sync + 'static {
    fn status(&self) -> impl Future<Output = bool> + Send + '_;
}

impl Toggle for bool {
    fn status(&self) -> impl Future<Output = bool> + Send + '_ {
        ready(*self)
    }
}

impl<T: Toggle> Toggle for Option<T> {
    async fn status(&self) -> bool {
        match self {
            Some(inner) => inner.status().await,
            None => false,
        }
    }
}

impl Toggle for Arc<AtomicBool> {
    fn status(&self) -> impl Future<Output = bool> + Send + '_ {
        ready(self.load(Ordering::SeqCst))
    }
}

impl<T: Toggle> Toggle for Arc<T> {
    fn status(&self) -> impl Future<Output = bool> + Send + '_ {
        (**self).status()
    }
}

impl<T: Toggle, F: Fn() -> T + Clone + Send + Sync + 'static> Toggle for F {
    fn status(&self) -> impl Future<Output = bool> + Send + '_ {
        async { (self)().status().await }
    }
}

impl<L: Toggle, R: Toggle> Toggle for Either<L, R> {
    async fn status(&self) -> bool {
        match self {
            Either::Left(l) => l.status().await,
            Either::Right(r) => r.status().await,
        }
    }
}
