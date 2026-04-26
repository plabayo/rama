use std::{
    marker::PhantomData,
    mem::{self, ManuallyDrop},
    ops::{Deref, DerefMut},
    os::raw::{c_int, c_ulong},
    ptr,
    sync::Arc,
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
            descriptor: Box::leak(Box::new(BlockDescriptor::new())),
            closure: ManuallyDrop::new(Arc::new(closure)),
        }
    }
}

impl<A, R, F> ConcreteBlock<A, R, F>
where
    F: 'static,
{
    pub(crate) fn copy(self) -> RcBlock<A, R> {
        unsafe {
            let mut block = self;
            let copied = RcBlock::copy(&mut *block);
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
