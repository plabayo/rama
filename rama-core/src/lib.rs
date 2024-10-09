//! `async fn serve(&self, Context<S>, Request) -> Result<Response, Error>`
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! # rama service
//!
//! Heavily inspired by [tower-service](https://docs.rs/tower-service/0.3.0/tower_service/trait.Service.html)
//! and the vast [Tokio](https://docs.rs/tokio/latest/tokio/) ecosystem which makes use of it.
//!
//! Initially the goal was to rely on `tower-service` directly, but it turned out to be
//! too restrictive and difficult to work with, for the use cases we have in Rama.
//! See <https://ramaproxy.org/book/faq.html> for more information regarding this and more.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

pub mod context;
pub use context::Context;

pub use ::rama_error as error;

pub mod graceful;
pub mod rt;

pub mod service;
pub use service::Service;

pub mod layer;
pub use layer::Layer;

pub mod combinators;
pub mod matcher;

pub mod username;

#[cfg(feature = "telemetry")]
pub mod telemetry;
