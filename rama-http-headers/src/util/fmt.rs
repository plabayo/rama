use std::fmt::Display;

use rama_http_types::HeaderValue;

#[expect(
    clippy::panic,
    reason = "vendored from upstream `headers`: callers always produce HeaderValue-safe strings; an Err here is a bug in the typed-header impl"
)]
pub(crate) fn fmt<T: Display>(fmt: T) -> HeaderValue {
    let s = fmt.to_string();
    match HeaderValue::from_maybe_shared(s) {
        Ok(val) => val,
        Err(err) => panic!("illegal HeaderValue; error = {err:?}, fmt = \"{fmt}\""),
    }
}
