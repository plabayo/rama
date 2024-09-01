//! `async fn serve(&self, Context<S>, Request) -> Result<Response, Error>`
//!
//! # rama service
//!
//! Heavily inspired by [tower-service](https://docs.rs/tower-service/0.3.0/tower_service/trait.Service.html)
//! and the vast [Tokio](https://docs.rs/tokio/latest/tokio/) ecosystem which makes use of it.
//!
//! Initially the goal was to rely on `tower-service` directly, but it turned out to be
//! too restrictive and difficult to work with, for the use cases we have in Rama.
//! See <https://ramaproxy.org/book/faq.html> for more information regarding this and more.

pub mod context;
pub use context::Context;

pub mod error;

pub mod dns;
pub mod graceful;
pub mod rt;

pub mod service;
pub use service::Service;

pub mod layer;
pub use layer::Layer;

pub mod combinators;
pub mod matcher;

pub mod net;

#[macro_use]
pub mod utils;
