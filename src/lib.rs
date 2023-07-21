//! # Rama
//!
//! rama is early work in progress, use at your own risk.
//!
//! Not everything that exists is documented and not everything that is documented is implemented.

#![warn(
    missing_debug_implementations,
    // missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]
#![forbid(unsafe_code)]
#![allow(incomplete_features)]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_projections)]
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]

pub mod transport;
