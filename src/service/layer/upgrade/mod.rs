//! middleware to handle branching into http upgrade services
//!
//! See [`UpgradeService`] for more details.

mod service;
#[doc(inline)]
pub use service::UpgradeService;

mod layer;
#[doc(inline)]
pub use layer::UpgradeLayer;

mod upgraded;
#[doc(inline)]
pub use upgraded::Upgraded;
