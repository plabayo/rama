use std::{
    marker::PhantomData,
    mem::{self, ManuallyDrop},
    ops::{Deref, DerefMut},
    os::raw::{c_int, c_ulong},
    ptr,
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
    descriptor: Box<BlockDescriptor<Self>>,
    closure: F,
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
            descriptor: Box::new(BlockDescriptor::new()),
            closure,
        }
    }
}

impl<A, R, F> ConcreteBlock<A, R, F>
where
    F: 'static,
{
    pub(crate) fn copy(self) -> RcBlock<A, R> {
        unsafe {
            let mut block = ManuallyDrop::new(self);
            RcBlock::copy(&mut **block)
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

unsafe extern "C" fn block_context_dispose<B>(block: &mut B) {
    unsafe { ptr::read(block) };
}

unsafe extern "C" fn block_context_copy<B>(_dst: &mut B, _src: &B) {}

#[repr(C)]
struct BlockDescriptor<B> {
    _reserved: c_ulong,
    block_size: c_ulong,
    copy_helper: unsafe extern "C" fn(&mut B, &B),
    dispose_helper: unsafe extern "C" fn(&mut B),
}

impl<B> BlockDescriptor<B> {
    fn new() -> Self {
        Self {
            _reserved: 0,
            block_size: mem::size_of::<B>() as c_ulong,
            copy_helper: block_context_copy::<B>,
            dispose_helper: block_context_dispose::<B>,
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
            (block.closure)()
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
            (block.closure)(a)
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
            (block.closure)(a, b)
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
