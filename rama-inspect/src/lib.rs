//! Inspection building blocks independent of traffic protocol and user interface.
//!
//! Applications share lifecycle and controller handles with their protocol adapters,
//! GUI, or API. Storage accepts streaming sources and returns streaming readers.
//! Filesystem storage and encryption are independently optional features.

pub mod intercept;
pub mod lifecycle;
pub mod storage;
pub mod subscription;

pub use lifecycle::{InspectionGate, InspectionPermit, InspectionSession, InspectionState};

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "websocket")]
pub mod websocket;
