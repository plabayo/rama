#[cfg(feature = "tracing")]
pub(crate) use tracing::{error, trace, warn};

#[cfg(not(feature = "tracing"))]
mod noop {
    #[allow(unused_macros)]
    macro_rules! trace {
        ($($tt:tt)*) => {};
    }

    #[allow(unused_macros)]
    macro_rules! warn {
        ($($tt:tt)*) => {};
    }

    #[allow(unused_macros)]
    macro_rules! error {
        ($($tt:tt)*) => {};
    }
}
#[cfg(not(feature = "tracing"))]
pub(crate) use noop::*;
