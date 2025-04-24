//! Tower support for Rama.
//!
//! See <https://github.com/plabayo/rama/blob/main/examples/http_rama_tower.rs>
//! for an example on how to use this crate with opt-in tower support for rama.
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

mod service;
mod service_ready;

pub mod layer;

#[doc(inline)]
pub use service::{ServiceAdapter, SharedServiceAdapter};

#[doc(inline)]
pub use layer::{LayerAdapter, LayerAdapterService};

pub mod core {
    //! re-exported tower-rs crates

    pub use ::tower_layer as layer;
    #[doc(inline)]
    pub use layer::Layer;

    pub use ::tower_service as service;
    #[doc(inline)]
    pub use service::Service;
}
