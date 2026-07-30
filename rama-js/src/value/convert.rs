//! The `From` / `TryFrom` conversion matrix between rust types and [`JsValue`].

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rama_net::address::{Authority, Domain, Host, SocketAddress};

use super::{JsArray, JsObject, JsStr, JsValue};
use crate::error::JsError;

/// The largest integer magnitude a js number can represent exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn conversion_err(expected: &str, actual: &JsValue) -> JsError {
    JsError::conversion(format!("expected {expected}, got {}", actual.type_name()))
}

/// Bounded, quoted preview of an input string: error messages must not
/// balloon to the full snapshot string budget.
fn quoted_preview(s: &str) -> String {
    const MAX_PREVIEW_BYTES: usize = 256;
    if s.len() <= MAX_PREVIEW_BYTES {
        format!("{s:?}")
    } else {
        let mut cut = MAX_PREVIEW_BYTES;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{:?}…", &s[..cut])
    }
}

// ── infallible: rust → js ──────────────────────────────────────────────────

impl From<()> for JsValue {
    fn from(_: ()) -> Self {
        Self::Undefined
    }
}

impl From<bool> for JsValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

macro_rules! impl_from_num {
    ($($t:ty),+ $(,)?) => {
        $(
            impl From<$t> for JsValue {
                fn from(n: $t) -> Self {
                    Self::Number(f64::from(n))
                }
            }
        )+
    };
}

impl_from_num!(i8, i16, i32, u8, u16, u32, f32, f64);

macro_rules! impl_try_from_big_num {
    ($(($t:ty, $n:ident => $abs:expr)),+ $(,)?) => {
        $(
            impl TryFrom<$t> for JsValue {
                type Error = JsError;

                fn try_from($n: $t) -> Result<Self, Self::Error> {
                    if $abs <= u128::from(MAX_SAFE_INTEGER) {
                        Ok(Self::Number($n as f64))
                    } else {
                        Err(JsError::conversion(format!(
                            "integer {} cannot be represented exactly as a js number",
                            $n,
                        )))
                    }
                }
            }
        )+
    };
}

impl_try_from_big_num!(
    (i64, n => u128::from(n.unsigned_abs())),
    (u64, n => u128::from(n)),
    (i128, n => n.unsigned_abs()),
    (u128, n => n),
    (isize, n => n.unsigned_abs() as u128),
    (usize, n => n as u128),
);

impl From<char> for JsValue {
    fn from(c: char) -> Self {
        Self::String(c.into())
    }
}

impl From<&str> for JsValue {
    fn from(s: &str) -> Self {
        Self::String(s.into())
    }
}

impl From<&String> for JsValue {
    fn from(s: &String) -> Self {
        Self::String(s.into())
    }
}

impl From<String> for JsValue {
    fn from(s: String) -> Self {
        Self::String(s.into())
    }
}

impl From<Cow<'_, str>> for JsValue {
    fn from(s: Cow<'_, str>) -> Self {
        Self::String(s.into())
    }
}

impl From<JsStr> for JsValue {
    fn from(s: JsStr) -> Self {
        Self::String(s)
    }
}

impl From<JsArray> for JsValue {
    fn from(arr: JsArray) -> Self {
        Self::Array(arr)
    }
}

impl From<JsObject> for JsValue {
    fn from(obj: JsObject) -> Self {
        Self::Object(obj)
    }
}

impl<T: Into<Self>> From<Option<T>> for JsValue {
    fn from(opt: Option<T>) -> Self {
        opt.map(Into::into).unwrap_or(Self::Null)
    }
}

impl<T: Into<Self>> From<Vec<T>> for JsValue {
    fn from(values: Vec<T>) -> Self {
        Self::Array(values.into())
    }
}

impl<T: Into<Self>, const N: usize> From<[T; N]> for JsValue {
    fn from(values: [T; N]) -> Self {
        Self::Array(values.into())
    }
}

macro_rules! impl_from_display {
    ($($t:ty),+ $(,)?) => {
        $(
            impl From<$t> for JsValue {
                fn from(value: $t) -> Self {
                    Self::String(value.to_string().into())
                }
            }

            impl From<&$t> for JsValue {
                fn from(value: &$t) -> Self {
                    Self::String(value.to_string().into())
                }
            }
        )+
    };
}

impl_from_display!(
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    Domain,
    Host,
    Authority,
    SocketAddress,
);

// ── fallible: js → rust ─────────────────────────────────────────────────────

impl TryFrom<JsValue> for bool {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        value
            .as_bool()
            .ok_or_else(|| conversion_err("a boolean", &value))
    }
}

impl TryFrom<JsValue> for f64 {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        value
            .as_f64()
            .ok_or_else(|| conversion_err("a number", &value))
    }
}

impl TryFrom<JsValue> for f32 {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        f64::try_from(value).map(|n| n as Self)
    }
}

macro_rules! impl_try_from_value_int {
    ($($t:ty),+ $(,)?) => {
        $(
            impl TryFrom<JsValue> for $t {
                type Error = JsError;

                fn try_from(value: JsValue) -> Result<Self, Self::Error> {
                    let n = value
                        .as_f64()
                        .ok_or_else(|| conversion_err("an integer number", &value))?;
                    if n.fract() != 0.0 || !n.is_finite() {
                        return Err(JsError::conversion(format!(
                            "expected an integer number, got {n}"
                        )));
                    }
                    if n.abs() > MAX_SAFE_INTEGER as f64 {
                        return Err(JsError::conversion(format!(
                            "number {n} exceeds the exactly representable integer range"
                        )));
                    }
                    <$t>::try_from(n as i64).map_err(|_| {
                        JsError::conversion(format!(
                            "number {n} is out of range for {}",
                            stringify!($t)
                        ))
                    })
                }
            }
        )+
    };
}

impl_try_from_value_int!(
    i8, i16, i32, i64, u8, u16, u32, u64, isize, usize, i128, u128
);

impl TryFrom<JsValue> for JsStr {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        match value {
            JsValue::String(s) => Ok(s),
            other => Err(conversion_err("a string", &other)),
        }
    }
}

impl TryFrom<JsValue> for String {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        JsStr::try_from(value).map(Into::into)
    }
}

impl TryFrom<JsValue> for JsArray {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        match value {
            JsValue::Array(arr) => Ok(arr),
            other => Err(conversion_err("an array", &other)),
        }
    }
}

impl TryFrom<JsValue> for JsObject {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        match value {
            JsValue::Object(obj) => Ok(obj),
            other => Err(conversion_err("an object", &other)),
        }
    }
}

impl<T: TryFrom<JsValue, Error = JsError>> TryFrom<JsValue> for Option<T> {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        if value.is_null_or_undefined() {
            Ok(None)
        } else {
            T::try_from(value).map(Some)
        }
    }
}

impl<T: TryFrom<JsValue, Error = JsError>> TryFrom<JsValue> for Vec<T> {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        JsArray::try_from(value)?
            .iter()
            .cloned()
            .map(T::try_from)
            .collect()
    }
}

macro_rules! impl_try_from_value_parse {
    ($($t:ty => $expected:literal),+ $(,)?) => {
        $(
            impl TryFrom<JsValue> for $t {
                type Error = JsError;

                fn try_from(value: JsValue) -> Result<Self, Self::Error> {
                    match value {
                        JsValue::String(s) => s.as_str().parse().map_err(|err| {
                            JsError::conversion(format!(
                                "invalid {}: {}: {err}", $expected, quoted_preview(&s),
                            ))
                        }),
                        other => Err(conversion_err($expected, &other)),
                    }
                }
            }
        )+
    };
}

impl_try_from_value_parse!(
    IpAddr => "an ip address",
    Ipv4Addr => "an ipv4 address",
    Ipv6Addr => "an ipv6 address",
    SocketAddr => "a socket address",
);

macro_rules! impl_try_from_value_net {
    ($($t:ty => $expected:literal),+ $(,)?) => {
        $(
            impl TryFrom<JsValue> for $t {
                type Error = JsError;

                fn try_from(value: JsValue) -> Result<Self, Self::Error> {
                    match value {
                        JsValue::String(s) => <$t>::try_from(s.as_str()).map_err(|err| {
                            JsError::conversion(format!(
                                "invalid {}: {}: {err}", $expected, quoted_preview(&s),
                            ))
                        }),
                        other => Err(conversion_err($expected, &other)),
                    }
                }
            }
        )+
    };
}

impl_try_from_value_net!(
    Domain => "a domain",
    Host => "a host",
    Authority => "an authority",
    SocketAddress => "a socket address",
);
