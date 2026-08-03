use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rama_net::address::ip::ipnet::IpNet;
use rama_net::address::{Authority, Domain, Host, SocketAddress};

use super::{JsArray, JsObject, JsStr, JsValue};
use crate::error::JsError;

/// A typed host function argument, extracted from a [`JsValue`].
///
/// Implemented for primitives, strings, common network types and
/// containers; see the crate documentation for the full list. Implement
/// it for your own types to use them directly as typed arguments in
/// host functions registered via
/// [`JsRuntimeBuilder::with_fn`][crate::JsRuntimeBuilder::with_fn].
///
/// A failed extraction is thrown as a `TypeError` inside the
/// calling script.
pub trait JsArg: Sized {
    /// Extract this argument from the given value.
    fn from_js(value: JsValue) -> Result<Self, JsError>;

    /// Extract this argument when the caller did not provide it.
    ///
    /// Defaults to an arity error; optional arguments override this.
    fn from_missing_js_arg() -> Result<Self, JsError> {
        Err(JsError::conversion("missing required argument"))
    }
}

macro_rules! impl_js_arg_via_try_from {
    ($($t:ty),+ $(,)?) => {
        $(
            impl JsArg for $t {
                fn from_js(value: JsValue) -> Result<Self, JsError> {
                    <$t>::try_from(value)
                }
            }
        )+
    };
}

impl_js_arg_via_try_from!(
    bool,
    f32,
    f64,
    i8,
    i16,
    i32,
    i64,
    i128,
    u8,
    u16,
    u32,
    u64,
    u128,
    isize,
    usize,
    String,
    JsStr,
    JsArray,
    JsObject,
    IpNet,
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    Domain,
    Host,
    Authority,
    SocketAddress,
);

impl JsArg for JsValue {
    fn from_js(value: JsValue) -> Result<Self, JsError> {
        Ok(value)
    }
}

impl<T: JsArg> JsArg for Option<T> {
    fn from_js(value: JsValue) -> Result<Self, JsError> {
        if value.is_null_or_undefined() {
            Ok(None)
        } else {
            T::from_js(value).map(Some)
        }
    }

    fn from_missing_js_arg() -> Result<Self, JsError> {
        Ok(None)
    }
}

impl<T: JsArg> JsArg for Vec<T> {
    fn from_js(value: JsValue) -> Result<Self, JsError> {
        JsArray::try_from(value)?
            .iter()
            .cloned()
            .map(T::from_js)
            .collect()
    }
}
