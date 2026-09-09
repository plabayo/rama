//! Inspection building blocks independent of traffic protocol and user interface.
//!
//! Applications share lifecycle and controller handles with their protocol adapters,
//! GUI, or API. Storage accepts streaming sources and returns streaming readers.
//! Protocol and encryption adapters live in their owning crates.

mod direction;
pub use direction::Direction;

pub mod intercept;
pub mod lifecycle;
pub mod storage;
pub mod subscription;

pub use lifecycle::{InspectionGate, InspectionPermit, InspectionSession, InspectionState};

mod observation;
pub use observation::Observations;

pub mod search;
