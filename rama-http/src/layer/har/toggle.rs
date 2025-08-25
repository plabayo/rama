use std::future::ready;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub trait Toggle: Send + Sync + 'static {
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

impl<T: Toggle, F: Fn() -> T + Clone + Send + Sync + 'static> Toggle for F {
    async fn status(&self) -> bool {
        (self)().status().await
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
