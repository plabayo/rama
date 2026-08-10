//! Engine-agnostic values crossing the js boundary.
//!
//! Values are deeply materialized when they cross the boundary in either
//! direction: they carry no engine handles or lifetimes, are `Send + Sync`,
//! and clone in `O(1)` thanks to shared backing storage for strings, arrays
//! and objects.

mod array;
mod convert;
mod object;
mod str;

mod arg;
pub use arg::JsArg;

pub use array::JsArray;
pub use object::JsObject;
pub use str::JsStr;

/// An engine-agnostic js value.
///
/// This is the type in which values cross the js boundary in both
/// directions: script results, host function arguments and return
/// values, and configured globals.
///
/// Function values cannot cross the boundary: a top-level function
/// result is a [`JsErrorKind::Conversion`][crate::JsErrorKind::Conversion]
/// error, and function properties are skipped when snapshotting objects
/// (mirroring `JSON.stringify` semantics).
#[derive(Debug, Clone, Default)]
pub enum JsValue {
    /// `undefined`
    #[default]
    Undefined,
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// any js number (always an `f64`, like in js itself)
    Number(f64),
    /// a string value
    String(JsStr),
    /// an array snapshot
    Array(JsArray),
    /// an object snapshot
    Object(JsObject),
}

impl JsValue {
    /// Returns `true` if this value is `undefined`.
    #[must_use]
    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    /// Returns `true` if this value is `null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns `true` if this value is `null` or `undefined`.
    #[must_use]
    pub fn is_null_or_undefined(&self) -> bool {
        matches!(self, Self::Undefined | Self::Null)
    }

    /// The inner [`bool`], if this value is a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The inner number, if this value is a number.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// The inner string as a [`str`][prim@str], if this value is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The inner [`JsStr`], if this value is a string.
    #[must_use]
    pub fn as_string(&self) -> Option<&JsStr> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The inner [`JsArray`], if this value is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&JsArray> {
        match self {
            Self::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// The inner [`JsObject`], if this value is an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&JsObject> {
        match self {
            Self::Object(obj) => Some(obj),
            _ => None,
        }
    }

    /// The js name of this value's type, useful in error messages.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

/// Values are compared structurally without recursing, so host-constructed
/// values of absurd depth cannot overflow the stack.
impl PartialEq for JsValue {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(self, other)];
        while let Some((left, right)) = pending.pop() {
            match (left, right) {
                (Self::Undefined, Self::Undefined) | (Self::Null, Self::Null) => {}
                (Self::Bool(l), Self::Bool(r)) if l == r => {}
                (Self::Number(l), Self::Number(r)) if l == r => {}
                (Self::String(l), Self::String(r)) if l == r => {}
                (Self::Array(l), Self::Array(r)) if l.len() == r.len() => {
                    pending.extend(l.iter().zip(r.iter()));
                }
                (Self::Object(l), Self::Object(r)) if l.len() == r.len() => {
                    for ((lk, lv), (rk, rv)) in l.iter().zip(r.iter()) {
                        if lk != rk {
                            return false;
                        }
                        pending.push((lv, rv));
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

/// Iteratively drop a worklist of values and every value nested inside
/// them, so tearing down a host-constructed value of absurd depth cannot
/// overflow the stack (mirroring the iterative [`PartialEq`]/[`Display`]).
///
/// Each container hands its direct children back to the worklist and is left
/// empty, so its own `Drop` re-entry is a cheap no-op.
pub(crate) fn drain_value_tree(mut stack: Vec<JsValue>) {
    while let Some(value) = stack.pop() {
        match value {
            JsValue::Array(mut array) => array.drain_children_into(&mut stack),
            JsValue::Object(mut object) => object.drain_children_into(&mut stack),
            _ => {}
        }
    }
}

/// Rendering depth beyond which nested containers elide to `…`,
/// so host-constructed values of absurd depth cannot overflow the stack.
const MAX_DISPLAY_DEPTH: usize = 128;

impl std::fmt::Display for JsValue {
    /// Console-style rendering: top-level strings print raw,
    /// nested values render JSON-like.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => f.write_str(s),
            other => fmt_nested(other, f, 0),
        }
    }
}

fn fmt_nested(value: &JsValue, f: &mut std::fmt::Formatter<'_>, depth: usize) -> std::fmt::Result {
    match value {
        JsValue::Undefined => f.write_str("undefined"),
        JsValue::Null => f.write_str("null"),
        JsValue::Bool(b) => write!(f, "{b}"),
        JsValue::Number(n) => write!(f, "{n}"),
        JsValue::String(s) => write!(f, "{:?}", s.as_str()),
        JsValue::Array(_) | JsValue::Object(_) if depth >= MAX_DISPLAY_DEPTH => f.write_str("…"),
        JsValue::Array(arr) => {
            f.write_str("[")?;
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                fmt_nested(v, f, depth + 1)?;
            }
            f.write_str("]")
        }
        JsValue::Object(obj) => {
            f.write_str("{")?;
            for (i, (k, v)) in obj.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{:?}: ", k.as_str())?;
                fmt_nested(v, f, depth + 1)?;
            }
            f.write_str("}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deeply_nested_array_drops_without_overflow() {
        let mut value = JsValue::Number(0.0);
        for _ in 0..200_000 {
            value = JsValue::Array(JsArray::from(vec![value]));
        }
        // a recursive drop would overflow the stack and abort the process
        drop(value);
    }

    #[test]
    fn deeply_nested_object_drops_without_overflow() {
        let mut value = JsValue::Number(0.0);
        for _ in 0..200_000 {
            value = JsValue::Object(JsObject::from_iter([("next", value)]));
        }
        drop(value);
    }

    #[test]
    fn shared_nested_array_is_untouched_by_a_dropped_clone() {
        let inner = JsArray::from(vec![JsValue::Number(1.0), JsValue::Number(2.0)]);
        let value = JsValue::Array(JsArray::from(vec![JsValue::Array(inner.clone())]));
        drop(value); // shared `inner` must survive
        assert_eq!(inner.get(0), Some(&JsValue::Number(1.0)));
        assert_eq!(inner.len(), 2);
    }
}
