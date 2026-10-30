use std::ffi::c_void;

use block2::RcBlock;

use crate::{ffi::xpc_object_t, util::abort_on_unwind};

/// A libxpc `xpc_handler_t` block (`void (^)(xpc_object_t)`).
///
/// libxpc runs handlers on dispatch threads, so the closure must be `Send + Sync`, and
/// it must not unwind into libxpc frames.
pub(crate) struct XpcHandler {
    // Safety invariant: built only by `XpcHandler::new`: the closure is
    // `Send + Sync + 'static` and runs under `abort_on_unwind`.
    block: RcBlock<dyn Fn(xpc_object_t) + 'static>,
}

impl XpcHandler {
    pub(crate) fn new(handler: impl Fn(xpc_object_t) + Send + Sync + 'static) -> Self {
        Self {
            block: RcBlock::new(move |object: xpc_object_t| abort_on_unwind(|| handler(object))),
        }
    }

    /// # Safety-usable invariant
    ///
    /// Returns a live `void (^)(xpc_object_t)` block, valid while `self` lives, whose
    /// closure is `Send + Sync + 'static` and never unwinds.
    pub(crate) fn as_block_ptr(&self) -> *mut c_void {
        RcBlock::as_ptr(&self.block).cast::<c_void>()
    }
}
