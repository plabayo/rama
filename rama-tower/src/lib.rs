//! Tower support for Rama.
//!
//! See <https://github.com/plabayo/rama/blob/main/examples/http_rama_tower.rs>
//! for an example on how to use this crate with opt-in tower support for rama.
//!
//! ### [`tower::Service`] adapters
//!
//! Adapters to use a [`tower::Service`] as a [`rama::Service`].
//!
//! - either [`ServiceAdapter`]: [`Clone`] / call, most commonly used and also what we do for the layer version;
//! - or [`SharedServiceAdapter`]: shared service across all calls, locked using an async [`Mutex`], less commonly
//!   done, but there if you really have to.
//!
//! ### [`tower::Layer`] adapters
//!
//! Next to that there is the fact that a layer produces
//! a service which also has to be wrapped, or in our case we have to wrap 2 times.
//! Once we have to wrap it to turn the "inner" [`rama::Service`] ("service C" in the above diagram)
//! into a [`tower::Service`] and produce the resulting [`tower::Service`] produced by the wrapped
//! [`tower::Layer`] also into a [`rama::Service`] ("service A" in the above diagram).
//!
//! To make this all happen and possible we have the following components:
//!
//! - [`LayerAdapter`]: use a [`tower::Layer`] as a [`rama::Layer`], which ensures that:
//!   - the inner [`rama::Service`] passed to the adapted [`tower::Layer`] is first
//!     wrapped by a [`TowerAdapterService`] to ensure it is a [`tower::Service`];
//!   - the produced [`tower::Service`] by the [`tower::Layer`] is turned into a [`rama::Service`]
//!     by wrapping it with a [`LayerAdapterService`].
//!
//! [`tower::Service`]: tower_service::Service
//! [`tower::Layer`]: tower_layer::Layer
//! [`rama::Service`]: rama_core::Service
//! [`rama::Layer`]: rama_core::Layer
//!
//! ## Halting
//!
//! The adapters in this carate assumes that a [`tower::Service`] will always become ready eventually,
//! as it will call [`poll_ready`] until ready prior to [`calling`] the [`tower::Service`].
//! Please ensure that your [`tower::Service`] does not require a side-step to prevent such halting.
//!
//! [`poll_ready`]: tower_service::Service::poll_ready
//! [`calling`]: tower_service::Service::call
//!
//! ## Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! ## Rama Tower Origins
//!
//! Initially Rama was designed fully around the idea of Tower, directly. The initial design of Rama took many
//! iterations and was R&D'd over a timespan of about a year, in between other work and parenting.
//! We switched between [`tower`](https://crates.io/crates/tower),
//! [`tower-async`](https://crates.io/crates/tower-async)
//! (our own public fork of tower) and back to [`tower`](https://crates.io/crates/tower) again...
//!
//! It became clear however that the version of [`tower`](https://crates.io/crates/tower)
//! at the time was incompatible (and still is) with the ideas which we wanted it to have:
//!
//! - We are not interested in the `poll_ready` code of tower,
//!   and in fact it would be harmful if something is used which makes use of it
//!   (Axum warns for it, but strictly it is possible...);
//!   - This idea is also further elaborated in the FAQ of our tower-async fork:
//!     <https://github.com/plabayo/tower-async?tab=readme-ov-file#faq>
//! - We want to start to prepare for an `async`-ready future as soon as we can...
//!
//! All in all, it was clear after several iterations that usage of tower did more
//! harm then it did good. What was supposed to be a stack to help us implement our vision,
//! became a hurdle instead.
//!
//! This is not the fault of tower, but more a sign that it did not age well,
//! or perhaps... it is actually a very different beast altogether.
//!
//! As both tower and rama are still in their pre "1.0" days, and
//! we are still evolving together and with the rest of the wider ecosystems,
//! it is possible that we grow closer once again.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

mod service;
mod service_ready;

pub mod layer;

#[doc(inline)]
pub use service::{ServiceAdapter, SharedServiceAdapter};

#[doc(inline)]
pub use layer::{LayerAdapter, LayerAdapterService, TowerAdapterService};

pub mod core {
    //! re-exported tower-rs crates

    pub use ::tower_layer as layer;
    #[doc(inline)]
    pub use layer::Layer;

    pub use ::tower_service as service;
    #[doc(inline)]
    pub use service::Service;
}
