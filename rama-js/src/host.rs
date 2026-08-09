use std::any::Any;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::error::{JsError, JsErrorKind};
use crate::func::{JsFnOutput, extract_js_arg};
use crate::value::{JsArg, JsStr, JsValue};

type TypedHostCallback<T> = dyn Fn(&mut T, Vec<JsValue>) -> Result<JsValue, JsError> + Send + Sync;
type ErasedHostCallback =
    dyn Fn(&mut dyn Any, Vec<JsValue>) -> Result<JsValue, JsError> + Send + Sync;

/// The raw form of a method on a [`JsHostObject`].
#[doc(hidden)]
pub struct RawHostMethod<T> {
    callback: Arc<TypedHostCallback<T>>,
    arity: Option<usize>,
}

impl<T> RawHostMethod<T> {
    fn new<F>(arity: Option<usize>, callback: F) -> Self
    where
        F: Fn(&mut T, Vec<JsValue>) -> Result<JsValue, JsError> + Send + Sync + 'static,
    {
        Self {
            callback: Arc::new(callback),
            arity,
        }
    }

    fn erase(self) -> HostCallback
    where
        T: Send + 'static,
    {
        let callback = self.callback;
        HostCallback {
            callback: Arc::new(move |resource, args| {
                let resource = resource.downcast_mut::<T>().ok_or_else(|| {
                    JsError::new(
                        JsErrorKind::Setup,
                        "host object resource has an unexpected rust type",
                    )
                })?;
                callback(resource, args)
            }),
            arity: self.arity,
        }
    }
}

/// A read-only method with typed, extractor-style arguments.
///
/// This trait is implemented for closures whose first argument is `&T`.
/// The remaining arguments are extracted from the JavaScript call.
pub trait JsHostFn<T, A>: Send + Sync + 'static {
    /// Lower this function into its raw form.
    #[doc(hidden)]
    fn into_raw_host_method(self) -> RawHostMethod<T>;
}

/// A mutable method with typed, extractor-style arguments.
///
/// This trait is implemented for closures whose first argument is `&mut T`.
/// The remaining arguments are extracted from the JavaScript call.
pub trait JsHostFnMut<T, A>: Send + Sync + 'static {
    /// Lower this function into its raw form.
    #[doc(hidden)]
    fn into_raw_host_method(self) -> RawHostMethod<T>;
}

/// A typed getter for a [`JsHostObject`] property.
pub trait JsHostGetter<T, M>: Send + Sync + 'static {
    /// Lower this getter into its raw form.
    #[doc(hidden)]
    fn into_raw_host_getter(self) -> RawHostMethod<T>;
}

impl<T, F, R, M> JsHostGetter<T, M> for F
where
    T: 'static,
    F: Fn(&T) -> R + Send + Sync + 'static,
    R: JsFnOutput<M>,
    M: 'static,
{
    fn into_raw_host_getter(self) -> RawHostMethod<T> {
        RawHostMethod::new(Some(0), move |resource, _args| {
            (self)(&*resource).into_js_fn_output()
        })
    }
}

/// A typed setter for a [`JsHostObject`] property.
pub trait JsHostSetter<T, A, M>: Send + Sync + 'static {
    /// Lower this setter into its raw form.
    #[doc(hidden)]
    fn into_raw_host_setter(self) -> RawHostMethod<T>;
}

impl<T, F, R, A, M> JsHostSetter<T, A, M> for F
where
    T: 'static,
    F: Fn(&mut T, A) -> R + Send + Sync + 'static,
    R: JsFnOutput<M>,
    A: JsArg + 'static,
    M: 'static,
{
    fn into_raw_host_setter(self) -> RawHostMethod<T> {
        RawHostMethod::new(Some(1), move |resource, mut args| {
            (self)(resource, extract_js_arg::<A>(&mut args, 0)?).into_js_fn_output()
        })
    }
}

macro_rules! impl_js_host_fn {
    ($($arg:ident.$idx:tt),*) => {
        impl<T, F, R, M, $($arg),*> JsHostFn<T, (($($arg,)*), M)> for F
        where
            T: 'static,
            F: Fn(&T, $($arg),*) -> R + Send + Sync + 'static,
            R: JsFnOutput<M>,
            M: 'static,
            $($arg: JsArg + 'static,)*
        {
            fn into_raw_host_method(self) -> RawHostMethod<T> {
                RawHostMethod::new(Some(count_args!($($arg),*)), move |resource, mut args| {
                    let _ = &mut args;
                    (self)(&*resource, $(extract_js_arg::<$arg>(&mut args, $idx)?),*)
                        .into_js_fn_output()
                })
            }
        }

        impl<T, F, R, M, $($arg),*> JsHostFnMut<T, (($($arg,)*), M)> for F
        where
            T: 'static,
            F: Fn(&mut T, $($arg),*) -> R + Send + Sync + 'static,
            R: JsFnOutput<M>,
            M: 'static,
            $($arg: JsArg + 'static,)*
        {
            fn into_raw_host_method(self) -> RawHostMethod<T> {
                RawHostMethod::new(Some(count_args!($($arg),*)), move |resource, mut args| {
                    let _ = &mut args;
                    (self)(resource, $(extract_js_arg::<$arg>(&mut args, $idx)?),*)
                        .into_js_fn_output()
                })
            }
        }
    };
}

macro_rules! count_args {
    () => { 0 };
    ($head:ident $(, $tail:ident)*) => { 1 + count_args!($($tail),*) };
}

impl_js_host_fn!();
impl_js_host_fn!(A1.0);
impl_js_host_fn!(A1.0, A2.1);
impl_js_host_fn!(A1.0, A2.1, A3.2);
impl_js_host_fn!(A1.0, A2.1, A3.2, A4.3);
impl_js_host_fn!(A1.0, A2.1, A3.2, A4.3, A5.4);
impl_js_host_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5);
impl_js_host_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6);
impl_js_host_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7);
impl_js_host_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7, A9.8);
impl_js_host_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7, A9.8, A10.9);
impl_js_host_fn!(
    A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7, A9.8, A10.9, A11.10
);
impl_js_host_fn!(
    A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7, A9.8, A10.9, A11.10, A12.11
);

#[derive(Clone)]
pub(crate) struct HostCallback {
    callback: Arc<ErasedHostCallback>,
    arity: Option<usize>,
}

impl HostCallback {
    pub(crate) fn arity(&self) -> Option<usize> {
        self.arity
    }

    fn call(&self, resource: &mut dyn Any, args: Vec<JsValue>) -> Result<JsValue, JsError> {
        (self.callback)(resource, args)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostMemberKind {
    Method,
    Getter,
    Setter,
}

#[derive(Clone)]
pub(crate) struct HostMember {
    pub(crate) name: JsStr,
    pub(crate) kind: HostMemberKind,
    pub(crate) callback: HostCallback,
}

pub(crate) struct HostClass {
    pub(crate) members: Vec<HostMember>,
}

pub(crate) struct HostResourceCell {
    value: Mutex<Option<Box<dyn Any + Send>>>,
}

impl HostResourceCell {
    fn new<T: Send + 'static>(value: T) -> Self {
        Self {
            value: Mutex::new(Some(Box::new(value))),
        }
    }

    pub(crate) fn call(
        &self,
        callback: &HostCallback,
        args: Vec<JsValue>,
    ) -> Result<JsValue, JsError> {
        let mut guard = self.value.lock();
        let value = guard
            .as_deref_mut()
            .ok_or_else(|| JsError::throw("host object resource is no longer available"))?;
        callback.call(value, args)
    }

    fn take<T: Send + 'static>(&self) -> Result<T, JsError> {
        let mut guard = self.value.lock();
        let value = guard.take().ok_or_else(|| {
            JsError::new(
                JsErrorKind::Setup,
                "host object resource is no longer available",
            )
        })?;
        value.downcast::<T>().map(|value| *value).map_err(|_value| {
            JsError::new(
                JsErrorKind::Setup,
                "host object resource has an unexpected rust type",
            )
        })
    }
}

/// A reusable definition of the methods and properties exposed by a
/// [`JsHostObject`].
///
/// A class contains no instance data. Build it once, clone it cheaply, and
/// bind each Rust value separately with [`JsHostClass::bind`].
pub struct JsHostClass<T> {
    class: Arc<HostClass>,
    marker: PhantomData<fn() -> T>,
}

impl<T> Clone for JsHostClass<T> {
    fn clone(&self) -> Self {
        Self {
            class: self.class.clone(),
            marker: PhantomData,
        }
    }
}

impl<T> fmt::Debug for JsHostClass<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsHostClass")
            .field("members", &self.class.members.len())
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static> JsHostClass<T> {
    /// Start defining a reusable native-object class.
    pub fn builder() -> JsHostClassBuilder<T> {
        JsHostClassBuilder {
            members: Vec::new(),
            marker: PhantomData,
        }
    }

    /// Bind a Rust-owned value to this class.
    pub fn bind(&self, value: T) -> (JsHostObject<T>, JsHostHandle<T>) {
        let resource = Arc::new(HostResourceCell::new(value));
        (
            JsHostObject {
                resource: Arc::clone(&resource),
                class: self.class.clone(),
                marker: PhantomData,
            },
            JsHostHandle {
                resource,
                marker: PhantomData,
            },
        )
    }
}

/// Builder for a reusable [`JsHostClass`].
pub struct JsHostClassBuilder<T> {
    members: Vec<HostMember>,
    marker: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for JsHostClassBuilder<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsHostClassBuilder")
            .field("members", &self.members.len())
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static> JsHostClassBuilder<T> {
    /// Add a read-only method.
    #[must_use]
    pub fn method<A, F>(mut self, name: impl Into<JsStr>, method: F) -> Self
    where
        F: JsHostFn<T, A>,
    {
        self.members.push(HostMember {
            name: name.into(),
            kind: HostMemberKind::Method,
            callback: method.into_raw_host_method().erase(),
        });
        self
    }

    /// Add a method which may mutate the Rust value.
    #[must_use]
    pub fn method_mut<A, F>(mut self, name: impl Into<JsStr>, method: F) -> Self
    where
        F: JsHostFnMut<T, A>,
    {
        self.members.push(HostMember {
            name: name.into(),
            kind: HostMemberKind::Method,
            callback: method.into_raw_host_method().erase(),
        });
        self
    }

    /// Add a read-only property getter.
    #[must_use]
    pub fn getter<M, F>(mut self, name: impl Into<JsStr>, getter: F) -> Self
    where
        F: JsHostGetter<T, M>,
    {
        self.members.push(HostMember {
            name: name.into(),
            kind: HostMemberKind::Getter,
            callback: getter.into_raw_host_getter().erase(),
        });
        self
    }

    /// Add a property setter which may mutate the Rust value.
    #[must_use]
    pub fn setter<A, M, F>(mut self, name: impl Into<JsStr>, setter: F) -> Self
    where
        F: JsHostSetter<T, A, M>,
    {
        self.members.push(HostMember {
            name: name.into(),
            kind: HostMemberKind::Setter,
            callback: setter.into_raw_host_setter().erase(),
        });
        self
    }

    /// Finish this reusable class definition.
    pub fn build(self) -> JsHostClass<T> {
        JsHostClass {
            class: Arc::new(HostClass {
                members: self.members,
            }),
            marker: PhantomData,
        }
    }
}

/// A Rust-owned value exposed to JavaScript as a native object.
///
/// The Rust value is not converted into a [`JsValue`] or copied into the
/// JavaScript heap. Scripts interact with it through the configured methods
/// and properties. A host object can only be installed on an existing
/// [`JsRuntime`][crate::JsRuntime], which keeps request-local resources out of
/// reusable [`JsRuntimeBuilder`][crate::JsRuntimeBuilder] blueprints.
pub struct JsHostObject<T> {
    resource: Arc<HostResourceCell>,
    class: Arc<HostClass>,
    marker: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for JsHostObject<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsHostObject")
            .field("members", &self.class.members.len())
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static> JsHostObject<T> {
    /// Start defining a native object around `value`.
    pub fn builder(value: T) -> JsHostObjectBuilder<T> {
        JsHostObjectBuilder {
            value,
            class: JsHostClass::builder(),
        }
    }

    pub(crate) fn into_erased(self) -> ErasedHostObject {
        ErasedHostObject {
            resource: self.resource,
            class: self.class,
        }
    }
}

/// Builder for a [`JsHostObject`].
pub struct JsHostObjectBuilder<T> {
    value: T,
    class: JsHostClassBuilder<T>,
}

impl<T> fmt::Debug for JsHostObjectBuilder<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsHostObjectBuilder")
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static> JsHostObjectBuilder<T> {
    /// Add a read-only method.
    #[must_use]
    pub fn method<A, F>(mut self, name: impl Into<JsStr>, method: F) -> Self
    where
        F: JsHostFn<T, A>,
    {
        self.class = self.class.method(name, method);
        self
    }

    /// Add a method which may mutate the Rust value.
    #[must_use]
    pub fn method_mut<A, F>(mut self, name: impl Into<JsStr>, method: F) -> Self
    where
        F: JsHostFnMut<T, A>,
    {
        self.class = self.class.method_mut(name, method);
        self
    }

    /// Add a read-only property getter.
    #[must_use]
    pub fn getter<M, F>(mut self, name: impl Into<JsStr>, getter: F) -> Self
    where
        F: JsHostGetter<T, M>,
    {
        self.class = self.class.getter(name, getter);
        self
    }

    /// Add a property setter which may mutate the Rust value.
    #[must_use]
    pub fn setter<A, M, F>(mut self, name: impl Into<JsStr>, setter: F) -> Self
    where
        F: JsHostSetter<T, A, M>,
    {
        self.class = self.class.setter(name, setter);
        self
    }

    /// Finish the definition and return both the JavaScript capability and
    /// the handle used to recover the Rust value.
    pub fn build(self) -> (JsHostObject<T>, JsHostHandle<T>) {
        self.class.build().bind(self.value)
    }
}

/// A one-shot handle used to recover a value owned by a [`JsHostObject`].
///
/// Taking the value invalidates the JavaScript object. Later method or
/// property access throws a JavaScript error instead of accessing stale data.
pub struct JsHostHandle<T> {
    resource: Arc<HostResourceCell>,
    marker: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for JsHostHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsHostHandle").finish_non_exhaustive()
    }
}

impl<T: Send + 'static> JsHostHandle<T> {
    /// Recover the Rust value and invalidate its JavaScript object.
    pub fn take(self) -> Result<T, JsError> {
        self.resource.take()
    }
}

pub(crate) struct ErasedHostObject {
    pub(crate) resource: Arc<HostResourceCell>,
    pub(crate) class: Arc<HostClass>,
}
