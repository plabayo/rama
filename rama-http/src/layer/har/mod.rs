//! HAR support, mostly to export using a [`recorder`] (e.g. export to files on the local FS).
//!
//! However you can also import pre-recorded _HAR_ data by (json) deserialzing it,
//! and for example turn the _HAR_ requests into _HTTP_ requests ready for use (more or less).

pub mod extensions;
pub mod layer;
pub mod recorder;
pub mod service;
pub mod spec;
pub mod toggle;
