//! `async fn serve(&self, Context<S>, Request) -> Result<Response, Error>`
//!
//! Heavily inspired by [tower-service](https://docs.rs/tower-service/0.3.0/tower_service/trait.Service.html)
//! and the vast [Tokio](https://docs.rs/tokio/latest/tokio/) ecosystem which makes use of it.
//!
//! Initially the goal was to rely on `tower-service` directly, but it turned out to be
//! too restrictive and difficult to work with, for the use cases we have in Rama.
//! See <https://ramaproxy.org/book/faq.html> for more information regarding this and more.

pub mod context;
pub use context::Context;

mod svc;
#[doc(inline)]
pub use svc::{BoxService, Service};

pub mod handler;
pub use handler::service_fn;

mod svc_hyper;
#[doc(inline)]
pub(crate) use svc_hyper::HyperService;

pub mod layer;
pub use layer::Layer;

mod builder;
#[doc(inline)]
pub use builder::ServiceBuilder;

mod identity;
#[doc(inline)]
pub use identity::IdentityService;

pub mod matcher;
pub use matcher::Matcher;
