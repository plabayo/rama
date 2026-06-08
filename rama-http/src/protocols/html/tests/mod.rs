//! Test coverage for the `html` module — both the runtime traits in
//! [`super::core`] / [`super::either_impls`] / [`super::rama_impls`]
//! and the proc-macro layer exposed from `rama-http-macros`.
//!
//! The braces around single-element `if`/`else` arms in template tests
//! look "redundant" to rustc — they are not, the proc-macro looks for
//! `Expr::Block` to know where to insert `Either::A(..)` etc. So most
//! test files set `#![allow(unused_braces)]`.

mod attributes;
mod branching;
mod content;
mod custom_elements;
mod elements;
mod escape;
mod rama_types;
mod response;
mod user_types;

use crate::BodyExtractExt;
use crate::Response;

/// Block on collecting `resp`'s body into a UTF-8 string. Tokio runtime is
/// spun up locally so the helper can be called from sync `#[test]` fns.
pub(super) fn collect_body(resp: Response) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move { resp.try_into_string().await.expect("body") })
}
