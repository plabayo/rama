//! Host ("FFI") function support.
//!
//! Host functions are registered on the
//! [`JsRuntimeBuilder`][crate::JsRuntimeBuilder] and called from scripts
//! like any other js function. Arguments are extracted into typed rust
//! values ([`JsArg`]) and return values converted back, web-handler style.

use std::ops::Deref;
use std::sync::Arc;

use crate::error::JsError;
use crate::value::{JsArg, JsValue};

/// The raw, untyped shape every host function is lowered into.
///
/// The callback is shared so registered functions can be cloned as part
/// of a runtime blueprint. `arity` is `None` for variadic functions; fixed
/// arity lets the engine avoid materializing extra arguments that JavaScript
/// semantics say the host function will ignore.
#[derive(Clone)]
#[doc(hidden)]
pub struct RawHostFn {
    callback: Arc<dyn Fn(Vec<JsValue>) -> Result<JsValue, JsError> + Send + Sync>,
    arity: Option<usize>,
}

impl RawHostFn {
    pub(crate) fn new<F>(arity: Option<usize>, callback: F) -> Self
    where
        F: Fn(Vec<JsValue>) -> Result<JsValue, JsError> + Send + Sync + 'static,
    {
        Self {
            callback: Arc::new(callback),
            arity,
        }
    }

    pub(crate) fn arity(&self) -> Option<usize> {
        self.arity
    }

    pub(crate) fn call(&self, args: Vec<JsValue>) -> Result<JsValue, JsError> {
        (self.callback)(args)
    }
}

/// All arguments of a host function call, for variadic host functions.
///
/// Use this as the sole argument of a host function to receive
/// every call argument as-is, in js fashion.
#[derive(Debug, Clone, Default)]
pub struct JsArgs(Vec<JsValue>);

impl JsArgs {
    /// Consume into the underlying values.
    #[must_use]
    pub fn into_vec(self) -> Vec<JsValue> {
        self.0
    }
}

impl Deref for JsArgs {
    type Target = [JsValue];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[JsValue]> for JsArgs {
    fn as_ref(&self) -> &[JsValue] {
        &self.0
    }
}

impl IntoIterator for JsArgs {
    type Item = JsValue;
    type IntoIter = std::vec::IntoIter<JsValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// A value a host function can return: either a plain value
/// convertible [`Into<JsValue>`], or a `Result` thereof with an
/// error convertible [`Into<JsError>`] (thrown inside the script).
///
/// The `M` parameter is an inference marker; ignore it.
pub trait JsFnOutput<M>: Send + 'static {
    /// Convert into the raw host function output.
    fn into_js_fn_output(self) -> Result<JsValue, JsError>;
}

/// [`JsFnOutput`] marker for plain values.
#[derive(Debug)]
#[non_exhaustive]
pub struct ValueOutput;

/// [`JsFnOutput`] marker for `Result` values.
#[derive(Debug)]
#[non_exhaustive]
pub struct ResultOutput;

impl<T> JsFnOutput<ValueOutput> for T
where
    T: Into<JsValue> + Send + 'static,
{
    fn into_js_fn_output(self) -> Result<JsValue, JsError> {
        Ok(self.into())
    }
}

impl<T, E> JsFnOutput<ResultOutput> for Result<T, E>
where
    T: Into<JsValue> + Send + 'static,
    E: Into<JsError> + Send + 'static,
{
    fn into_js_fn_output(self) -> Result<JsValue, JsError> {
        self.map(Into::into).map_err(Into::into)
    }
}

/// A host function with typed, extractor-style arguments.
///
/// Implemented for closures of up to twelve [`JsArg`] arguments as well
/// as for variadic closures taking a single [`JsArgs`], returning any
/// [`JsFnOutput`]. Extra call arguments are ignored (js style), missing
/// ones error unless the parameter is an `Option`.
///
/// The `A` parameter is an inference marker; ignore it.
pub trait JsFn<A>: Send + Sync + 'static {
    /// Lower this function into its raw untyped shape.
    #[doc(hidden)]
    fn into_raw_host_fn(self) -> RawHostFn;
}

/// [`JsFn`] marker for variadic [`JsArgs`] functions.
#[derive(Debug)]
#[non_exhaustive]
pub struct VariadicMarker;

impl<F, R, M> JsFn<(VariadicMarker, M)> for F
where
    F: Fn(JsArgs) -> R + Send + Sync + 'static,
    R: JsFnOutput<M>,
    M: 'static,
{
    fn into_raw_host_fn(self) -> RawHostFn {
        RawHostFn::new(None, move |args| (self)(JsArgs(args)).into_js_fn_output())
    }
}

/// Take (not copy) the argument at `index` and extract it as a `T`.
fn extract_js_arg<T: JsArg>(args: &mut [JsValue], index: usize) -> Result<T, JsError> {
    match args.get_mut(index) {
        Some(value) => T::from_js(std::mem::take(value)).map_err(|err| {
            JsError::conversion(format!("argument {}: {}", index + 1, err.message()))
        }),
        None => T::from_missing_js_arg().map_err(|err| {
            JsError::conversion(format!("argument {}: {}", index + 1, err.message()))
        }),
    }
}

macro_rules! impl_js_fn {
    ($($t:ident.$idx:tt),*) => {
        impl<F, R, M, $($t),*> JsFn<(($($t,)*), M)> for F
        where
            F: Fn($($t),*) -> R + Send + Sync + 'static,
            R: JsFnOutput<M>,
            M: 'static,
            $($t: JsArg + 'static,)*
        {
            fn into_raw_host_fn(self) -> RawHostFn {
                RawHostFn::new(Some(count_args!($($t),*)), move |mut args| {
                    let _ = &mut args;
                    (self)($(extract_js_arg::<$t>(&mut args, $idx)?),*).into_js_fn_output()
                })
            }
        }
    };
}

macro_rules! count_args {
    () => { 0 };
    ($head:ident $(, $tail:ident)*) => { 1 + count_args!($($tail),*) };
}

impl_js_fn!();
impl_js_fn!(A1.0);
impl_js_fn!(A1.0, A2.1);
impl_js_fn!(A1.0, A2.1, A3.2);
impl_js_fn!(A1.0, A2.1, A3.2, A4.3);
impl_js_fn!(A1.0, A2.1, A3.2, A4.3, A5.4);
impl_js_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5);
impl_js_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6);
impl_js_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7);
impl_js_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7, A9.8);
impl_js_fn!(A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7, A9.8, A10.9);
impl_js_fn!(
    A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7, A9.8, A10.9, A11.10
);
impl_js_fn!(
    A1.0, A2.1, A3.2, A4.3, A5.4, A6.5, A7.6, A8.7, A9.8, A10.9, A11.10, A12.11
);
