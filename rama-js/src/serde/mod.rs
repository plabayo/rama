//! Serde integration.
//!
//! The [`Serde`] wrapper lets any `serde`-capable type cross the js
//! boundary: as a typed host function argument (via `Deserialize`) and
//! as a host function return value or global (via `Serialize`).

mod de;
mod error;
mod ser;
mod value;
mod wrapper;

pub use wrapper::{Serde, SerdeOutput};

use error::SerdeError;

/// The largest integer magnitude a js number can represent exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
