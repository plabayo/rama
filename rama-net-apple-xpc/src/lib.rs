//! Apple XPC support for rama.
//!
//! Official Apple documentation:
//!
//! - XPC overview: <https://developer.apple.com/documentation/xpc>
//! - Creating XPC services:
//!   <https://developer.apple.com/documentation/xpc/creating_xpc_services>
//! - XPC connections:
//!   <https://developer.apple.com/documentation/xpc/xpc-connections?language=objc>
//! - XPC updates:
//!   <https://developer.apple.com/documentation/updates/xpc>
//!
//! This crate uses bindgen-generated `libXPC` bindings as its low-level core.
//! It then layers small Rust wrappers on top so that Rama applications can use
//! XPC in a more ergonomic, service-oriented style.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

#[cfg(target_vendor = "apple")]
mod imp;

#[cfg(target_vendor = "apple")]
#[doc(hidden)]
pub mod ffi {
    #![allow(
        dead_code,
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        clippy::all
    )]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[cfg(target_vendor = "apple")]
pub use imp::*;
