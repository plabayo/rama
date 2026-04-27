use std::{
    marker::PhantomData,
    mem::{self, ManuallyDrop},
    ops::{Deref, DerefMut},
    os::raw::{c_int, c_ulong},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicPtr, Ordering},
    },
};

use crate::ffi::{_Block_copy, _Block_release, _NSConcreteStackBlock};

#[repr(C)]
struct Class {
    _private: [u8; 0],
}

pub(crate) trait IntoConcreteBlock<A>: Sized {
    type Ret;

    fn into_concrete_block(self) -> ConcreteBlock<A, Self::Ret, Self>;
}

#[repr(C)]
struct BlockBase<A, R> {
    isa: *const Class,
    flags: c_int,
    _reserved: c_int,
    invoke: unsafe extern "C" fn(*mut Block<A, R>, ...) -> R,
}

#[repr(C)]
pub(crate) struct Block<A, R> {
    _base: PhantomData<BlockBase<A, R>>,
}

pub(crate) struct RcBlock<A, R> {
    ptr: *mut Block<A, R>,
}

impl<A, R> RcBlock<A, R> {
    unsafe fn copy(ptr: *mut Block<A, R>) -> Self {
        let ptr = unsafe { _Block_copy(ptr.cast()) }.cast::<Block<A, R>>();
        Self { ptr }
    }
}

impl<A, R> Deref for RcBlock<A, R> {
    type Target = Block<A, R>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<A, R> Drop for RcBlock<A, R> {
    fn drop(&mut self) {
        unsafe { _Block_release(self.ptr.cast()) };
    }
}

#[repr(C)]
pub(crate) struct ConcreteBlock<A, R, F> {
    base: BlockBase<A, R>,
    descriptor: *const BlockDescriptor<Self>,
    closure: ManuallyDrop<Arc<F>>,
}

impl<A, R, F> ConcreteBlock<A, R, F>
where
    F: IntoConcreteBlock<A, Ret = R>,
{
    pub(crate) fn new(closure: F) -> Self {
        closure.into_concrete_block()
    }
}

impl<A, R, F> ConcreteBlock<A, R, F> {
    unsafe fn closure_ref(&self) -> &F {
        let arc: &Arc<F> = &self.closure;
        arc.as_ref()
    }

    unsafe fn with_invoke(invoke: unsafe extern "C" fn(*mut Self, ...) -> R, closure: F) -> Self {
        Self {
            base: BlockBase {
                isa: ptr::addr_of!(_NSConcreteStackBlock).cast::<Class>(),
                flags: 1 << 25,
                _reserved: 0,
                invoke: unsafe {
                    mem::transmute::<
                        unsafe extern "C" fn(*mut Self, ...) -> R,
                        unsafe extern "C" fn(*mut Block<A, R>, ...) -> R,
                    >(invoke)
                },
            },
            descriptor: descriptor_for::<A, R, F>(),
            closure: ManuallyDrop::new(Arc::new(closure)),
        }
    }
}

impl<A, R, F> Drop for ConcreteBlock<A, R, F> {
    fn drop(&mut self) {
        // SAFETY: closure is always initialised in with_invoke. This is the sole drop
        // site for stack blocks (used without copy()). copy() wraps self in ManuallyDrop
        // to suppress this impl and handles the Arc decrement manually, so there is no
        // double-drop. block_context_dispose handles the heap-copy side.
        unsafe { ManuallyDrop::drop(&mut self.closure) }
    }
}

impl<A, R, F> ConcreteBlock<A, R, F>
where
    F: 'static,
{
    pub(crate) fn copy(self) -> RcBlock<A, R> {
        unsafe {
            // ManuallyDrop::new suppresses the Drop impl so it does not fire when
            // `block` goes out of scope at the end of this function — we handle the
            // Arc decrement ourselves below.
            let mut block = ManuallyDrop::new(self);
            // `**block`: ManuallyDrop<ConcreteBlock> → ConcreteBlock → Block (DerefMut).
            let copied = RcBlock::copy(&mut **block);
            // Decrement the Arc that was cloned into the heap copy by block_context_copy.
            ManuallyDrop::drop(&mut block.closure);
            copied
        }
    }
}

impl<A, R, F> Deref for ConcreteBlock<A, R, F> {
    type Target = Block<A, R>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(&self.base as *const _ as *const Block<A, R>) }
    }
}

impl<A, R, F> DerefMut for ConcreteBlock<A, R, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(&mut self.base as *mut _ as *mut Block<A, R>) }
    }
}

unsafe extern "C" fn block_context_dispose<A, R, F>(block: *mut ConcreteBlock<A, R, F>) {
    unsafe {
        ManuallyDrop::drop(&mut (*block).closure);
    }
}

unsafe extern "C" fn block_context_copy<A, R, F>(
    dst: *mut ConcreteBlock<A, R, F>,
    src: *const ConcreteBlock<A, R, F>,
) {
    unsafe {
        ptr::addr_of_mut!((*dst).closure).write(ManuallyDrop::new(Arc::clone(&(*src).closure)));
    }
}

/// Returns a pointer to the one-per-type `BlockDescriptor` for `ConcreteBlock<A, R, F>`.
///
/// The descriptor is allocated at most once per concrete `(A, R, F)` triple and then
/// intentionally leaked so that it remains valid for the entire lifetime of the process
/// (XPC may retain the descriptor pointer across block copies and releases).
///
/// # Per-monomorphisation statics
///
/// The `static DESCRIPTOR` inside this function is instantiated separately for every
/// monomorphisation of the generic function — a property of rustc/LLVM that is relied
/// upon throughout the Rust ecosystem (e.g. `once_cell`). The language reference does
/// not formally guarantee it, but it is stable in practice.
fn descriptor_for<A, R, F>() -> *const BlockDescriptor<ConcreteBlock<A, R, F>> {
    static DESCRIPTOR: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

    let p = DESCRIPTOR.load(Ordering::Acquire);
    if !p.is_null() {
        return p.cast();
    }

    // First call for this monomorphisation: allocate one descriptor and publish it.
    // If two threads race we allocate two but keep only the winner; the loser is freed.
    let fresh =
        Box::into_raw(Box::new(BlockDescriptor::<ConcreteBlock<A, R, F>>::new())).cast::<()>();
    match DESCRIPTOR.compare_exchange(ptr::null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh.cast(),
        Err(winner) => {
            // Another thread beat us; drop our allocation and return theirs.
            // SAFETY: fresh was just produced by Box::into_raw for this exact type.
            drop(unsafe { Box::from_raw(fresh.cast::<BlockDescriptor<ConcreteBlock<A, R, F>>>()) });
            winner.cast()
        }
    }
}

#[repr(C)]
struct BlockDescriptor<B> {
    reserved: c_ulong,
    size: c_ulong,
    copy_helper: unsafe extern "C" fn(*mut B, *const B),
    dispose_helper: unsafe extern "C" fn(*mut B),
}

impl<A, R, F> BlockDescriptor<ConcreteBlock<A, R, F>> {
    fn new() -> Self {
        Self {
            reserved: 0,
            size: mem::size_of::<ConcreteBlock<A, R, F>>() as c_ulong,
            copy_helper: block_context_copy::<A, R, F>,
            dispose_helper: block_context_dispose::<A, R, F>,
        }
    }
}

impl<R, X> IntoConcreteBlock<()> for X
where
    X: Fn() -> R,
{
    type Ret = R;

    fn into_concrete_block(self) -> ConcreteBlock<(), R, X> {
        unsafe extern "C" fn invoke<R, X>(block_ptr: *mut ConcreteBlock<(), R, X>) -> R
        where
            X: Fn() -> R,
        {
            let block = unsafe { &*block_ptr };
            let f = unsafe { block.closure_ref() };
            f()
        }

        let invoke_fn: unsafe extern "C" fn(*mut ConcreteBlock<(), R, X>) -> R = invoke;
        unsafe {
            ConcreteBlock::with_invoke(
                mem::transmute::<
                    unsafe extern "C" fn(*mut ConcreteBlock<(), R, X>) -> R,
                    unsafe extern "C" fn(*mut ConcreteBlock<(), R, X>, ...) -> R,
                >(invoke_fn),
                self,
            )
        }
    }
}

impl<A, R, X> IntoConcreteBlock<(A,)> for X
where
    X: Fn(A) -> R,
{
    type Ret = R;

    fn into_concrete_block(self) -> ConcreteBlock<(A,), R, X> {
        unsafe extern "C" fn invoke<A, R, X>(block_ptr: *mut ConcreteBlock<(A,), R, X>, a: A) -> R
        where
            X: Fn(A) -> R,
        {
            let block = unsafe { &*block_ptr };
            let f = unsafe { block.closure_ref() };
            f(a)
        }

        let invoke_fn: unsafe extern "C" fn(*mut ConcreteBlock<(A,), R, X>, A) -> R = invoke;
        unsafe {
            ConcreteBlock::with_invoke(
                mem::transmute::<
                    unsafe extern "C" fn(*mut ConcreteBlock<(A,), R, X>, A) -> R,
                    unsafe extern "C" fn(*mut ConcreteBlock<(A,), R, X>, ...) -> R,
                >(invoke_fn),
                self,
            )
        }
    }
}

impl<A, B, R, X> IntoConcreteBlock<(A, B)> for X
where
    X: Fn(A, B) -> R,
{
    type Ret = R;

    fn into_concrete_block(self) -> ConcreteBlock<(A, B), R, X> {
        unsafe extern "C" fn invoke<A, B, R, X>(
            block_ptr: *mut ConcreteBlock<(A, B), R, X>,
            a: A,
            b: B,
        ) -> R
        where
            X: Fn(A, B) -> R,
        {
            let block = unsafe { &*block_ptr };
            let f = unsafe { block.closure_ref() };
            f(a, b)
        }

        let invoke_fn: unsafe extern "C" fn(*mut ConcreteBlock<(A, B), R, X>, A, B) -> R = invoke;
        unsafe {
            ConcreteBlock::with_invoke(
                mem::transmute::<
                    unsafe extern "C" fn(*mut ConcreteBlock<(A, B), R, X>, A, B) -> R,
                    unsafe extern "C" fn(*mut ConcreteBlock<(A, B), R, X>, ...) -> R,
                >(invoke_fn),
                self,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A probe value that increments an `Arc<AtomicUsize>` counter when dropped.
    /// - count == 0 after the expected drop → the value was **leaked**
    /// - count == 1 after the expected drop → correct single drop
    /// - count >= 2 → **double-free** (drop was called more than once)
    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Construct a fresh `DropProbe` together with the shared counter.
    fn probe() -> (DropProbe, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        (DropProbe(counter.clone()), counter)
    }

    // ------------------------------------------------------------------
    // Stack block (no copy) — tests the `Drop` impl on `ConcreteBlock`
    // ------------------------------------------------------------------

    /// A stack block that is never copied must drop its closure exactly once.
    /// Before the `Drop` impl was added the `ManuallyDrop<Arc<F>>` was never
    /// released, yielding count == 0 (leak).
    #[test]
    fn stack_block_drops_closure_exactly_once() {
        let (p, counter) = probe();
        {
            let _block = ConcreteBlock::new(move || {
                let _ = &p; // capture probe
            });
            // block goes out of scope here → Drop impl fires
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "stack block must drop closure exactly once (0 = leak, >1 = double-free)"
        );
    }

    /// Closures that take an argument: same guarantee.
    #[test]
    fn stack_block_with_arg_drops_closure_exactly_once() {
        let (p, counter) = probe();
        {
            let _block = ConcreteBlock::new(move |_x: u32| {
                let _ = &p;
            });
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Closures that take two arguments.
    #[test]
    fn stack_block_with_two_args_drops_closure_exactly_once() {
        let (p, counter) = probe();
        {
            let _block = ConcreteBlock::new(move |_x: u32, _y: u32| {
                let _ = &p;
            });
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ------------------------------------------------------------------
    // copy() does not double-drop: ManuallyDrop mechanics
    // ------------------------------------------------------------------

    /// `copy()` wraps `self` in `ManuallyDrop` before it manually decrements the
    /// stack-side Arc reference.  This test verifies that the `ConcreteBlock::Drop`
    /// impl does NOT fire a second time when that `ManuallyDrop` goes out of scope,
    /// which would be a double-free.
    ///
    /// Concretely: after `ManuallyDrop::drop(&mut block.closure)` the counter is 1
    /// (exactly one drop).  If the `Drop` impl fired again it would increment to 2.
    #[test]
    fn copy_manual_drop_does_not_double_free() {
        let (p, counter) = probe();
        let block = ConcreteBlock::new(move || {
            let _ = &p;
        });

        // Replicate what copy() does on the stack side.
        let mut block = ManuallyDrop::new(block);

        assert_eq!(counter.load(Ordering::SeqCst), 0, "not dropped yet");

        // Manually drop the sole Arc reference — this is what copy() does after
        // _Block_copy has cloned it into the heap block.
        unsafe { ManuallyDrop::drop(&mut block.closure) };

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "closure dropped exactly once by the explicit ManuallyDrop::drop"
        );

        // block goes out of scope here.  The Drop impl is suppressed by ManuallyDrop,
        // so the counter must remain 1.  A counter value of 2 would indicate a
        // double-free.  (We do not call `drop(block)` explicitly because doing so
        // on a `ManuallyDrop` is a compiler lint error — the suppression happens
        // implicitly when the binding goes out of scope.)
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "ManuallyDrop must suppress the Drop impl (counter == 2 means double-free)"
        );
    }

    /// Two independent stack blocks, each dropped normally — no cross-contamination.
    #[test]
    fn two_independent_stack_blocks_each_dropped_once() {
        let (p1, c1) = probe();
        let (p2, c2) = probe();

        let b1 = ConcreteBlock::new(move || {
            let _ = &p1;
        });
        let b2 = ConcreteBlock::new(move || {
            let _ = &p2;
        });

        drop(b1);
        assert_eq!(c1.load(Ordering::SeqCst), 1, "first block dropped once");
        assert_eq!(c2.load(Ordering::SeqCst), 0, "second block not yet dropped");

        drop(b2);
        assert_eq!(
            c1.load(Ordering::SeqCst),
            1,
            "first block still exactly once"
        );
        assert_eq!(c2.load(Ordering::SeqCst), 1, "second block dropped once");
    }

    // ------------------------------------------------------------------
    // copy_helper / dispose_helper — direct Arc reference-count tests
    //
    // These tests bypass _Block_copy/_Block_release (the macOS Block runtime)
    // and call our own helpers directly via the descriptor function-pointer slots.
    // This isolates our Arc-management logic from any Block-runtime behaviour
    // that may differ across macOS versions or test-binary linking contexts.
    // ------------------------------------------------------------------

    /// `block_context_copy` must Arc::clone the source closure into the
    /// destination — incrementing the reference count — so that the heap copy
    /// and the original both own a reference.
    ///
    /// Sequence modelled here (same as _Block_copy would perform):
    ///   1. memcpy src → dst  (bitwise copy, refcount still 1)
    ///   2. call copy_helper  (Arc::clone; refcount 1 → 2)
    ///   3. call dispose_helper on dst  (refcount 2 → 1)
    ///   4. drop src normally  (refcount 1 → 0 → DropProbe fires)
    #[test]
    fn copy_helper_increments_arc_refcount() {
        let (p, counter) = probe();
        let src = ConcreteBlock::new(move || {
            let _ = &p;
        });

        // Step 1: bitwise copy (as _Block_copy does via memmove before copy_helper).
        // ManuallyDrop prevents the Drop impl from running on this copy.
        let mut dst = ManuallyDrop::new(unsafe { ptr::read(&src) });

        // Step 2: call copy_helper through the descriptor — increments Arc refcount.
        let copy_fn = unsafe { (*src.descriptor).copy_helper };
        unsafe { copy_fn(&mut *dst as *mut _, &src) };

        assert_eq!(counter.load(Ordering::SeqCst), 0, "both refs still live");

        // Step 3: call dispose_helper — decrements dst's Arc reference (refcount 2 → 1).
        let dispose_fn = unsafe { (*src.descriptor).dispose_helper };
        unsafe { dispose_fn(&mut *dst as *mut _) };

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "src still holds its reference (refcount 1)"
        );

        // Step 4: drop src normally — refcount 1 → 0 → DropProbe fires.
        drop(src);
        assert_eq!(counter.load(Ordering::SeqCst), 1, "dropped exactly once");
    }

    /// `block_context_dispose` must drop the Arc reference stored in the block,
    /// freeing the closure when it is the sole owner.
    #[test]
    fn dispose_helper_drops_arc() {
        let (p, counter) = probe();
        let block = ConcreteBlock::new(move || {
            let _ = &p;
        });

        // Retrieve the dispose helper before wrapping in ManuallyDrop.
        let dispose_fn = unsafe { (*block.descriptor).dispose_helper };

        // Suppress the Drop impl so it does not double-free after we call dispose.
        let mut block = ManuallyDrop::new(block);

        // Sole Arc reference: refcount 1 → 0 → DropProbe fires.
        unsafe { dispose_fn(&mut *block as *mut _) };

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "dispose_helper must drop the Arc exactly once (0 = leak, >1 = double-free)"
        );
    }

    // ------------------------------------------------------------------
    // Descriptor singleton
    // ------------------------------------------------------------------

    /// Two blocks of the same concrete type must share the exact same descriptor
    /// pointer — verifying the per-type singleton in `descriptor_for`.
    #[test]
    fn descriptor_is_singleton_per_type() {
        // Use a non-capturing fn-pointer closure so the type is fully determined.
        fn noop(_: u32) {}

        let b1 = ConcreteBlock::new(noop as fn(u32));
        let b2 = ConcreteBlock::new(noop as fn(u32));

        assert_eq!(
            b1.descriptor, b2.descriptor,
            "descriptor must be a singleton: different pointers mean per-call allocation (leak)"
        );
    }

    /// The descriptor `size` field must reflect the actual byte-size of the
    /// `ConcreteBlock` struct for the given type triple.
    #[test]
    fn descriptor_size_field_is_correct() {
        fn noop() {}
        let b = ConcreteBlock::new(noop as fn());
        let reported = unsafe { (*b.descriptor).size as usize };
        let actual = mem::size_of::<ConcreteBlock<(), (), fn()>>();
        assert_eq!(
            reported, actual,
            "descriptor.size must equal sizeof(ConcreteBlock)"
        );
    }

    // NOTE: "descriptor_differs_across_types" is intentionally absent.
    //
    // LLVM is permitted — and in practice does — merge monomorphisations that
    // produce identical machine code.  Two fn-pointer types of the same size
    // (e.g. `fn(u32)` vs `fn(u64)`) produce byte-for-byte identical
    // `descriptor_for` instantiations, so the compiler may assign them the same
    // `static DESCRIPTOR` and therefore the same pointer.  This is *correct*:
    // the descriptor's only observable contents are `size`, `copy_helper`, and
    // `dispose_helper`, all of which are identical for layout-equivalent types.

    // ------------------------------------------------------------------
    // Invocation
    // ------------------------------------------------------------------

    /// Invoke a stack block via its `base.invoke` function pointer to ensure the
    /// closure is called and returns the correct value.
    #[test]
    fn stack_block_invoke_no_args() {
        let block = ConcreteBlock::new(|| 42u32);

        // SAFETY: invoke is correctly set up by with_invoke; block is on the stack.
        let result = unsafe {
            let invoke: unsafe extern "C" fn(*mut ConcreteBlock<(), u32, fn() -> u32>) -> u32 =
                mem::transmute(block.base.invoke);
            let ptr = &block as *const _ as *mut ConcreteBlock<(), u32, fn() -> u32>;
            invoke(ptr)
        };

        assert_eq!(result, 42);
    }

    /// Invoke a one-argument block.
    #[test]
    fn stack_block_invoke_one_arg() {
        let block = ConcreteBlock::new(|x: u32| x * 2);

        let result = unsafe {
            let invoke: unsafe extern "C" fn(
                *mut ConcreteBlock<(u32,), u32, fn(u32) -> u32>,
                u32,
            ) -> u32 = mem::transmute(block.base.invoke);
            let ptr = &block as *const _ as *mut ConcreteBlock<(u32,), u32, fn(u32) -> u32>;
            invoke(ptr, 21)
        };

        assert_eq!(result, 42);
    }

    /// Invoke a two-argument block.
    #[test]
    fn stack_block_invoke_two_args() {
        let block = ConcreteBlock::new(|x: u32, y: u32| x + y);

        let result = unsafe {
            let invoke: unsafe extern "C" fn(
                *mut ConcreteBlock<(u32, u32), u32, fn(u32, u32) -> u32>,
                u32,
                u32,
            ) -> u32 = mem::transmute(block.base.invoke);
            let ptr =
                &block as *const _ as *mut ConcreteBlock<(u32, u32), u32, fn(u32, u32) -> u32>;
            invoke(ptr, 20, 22)
        };

        assert_eq!(result, 42);
    }

    /// A copied block can still be invoked through the `RcBlock` (which derefs to `Block`).
    /// This smoke-tests the full copy + invoke path without calling into the real XPC FFI.
    #[test]
    fn copied_block_closure_is_reachable_via_concrete_ptr() {
        // We can't call RcBlock through the public API without real XPC, but we can
        // grab the pointer stored inside it and invoke directly.
        let block = ConcreteBlock::new(|| 7u32);
        let rc = block.copy();

        let result = unsafe {
            // rc.ptr is *mut Block<(),u32>; reinterpret as *mut ConcreteBlock to reach invoke.
            let concrete_ptr = rc.ptr as *mut ConcreteBlock<(), u32, fn() -> u32>;
            let invoke: unsafe extern "C" fn(*mut ConcreteBlock<(), u32, fn() -> u32>) -> u32 =
                mem::transmute((*concrete_ptr).base.invoke);
            invoke(concrete_ptr)
        };

        assert_eq!(result, 7);
    }
}
