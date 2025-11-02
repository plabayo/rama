//! UA [`Layer`]s provided by Rama.
//!
//! A [`Layer`], as defined in [`rama_core::Service`],
//! is a middleware that can modify the request and/or response of a [`Service`]s.
//! It is also capable of branching between two or more [`Service`]s.
//!
//! Most layers are implemented as a [`Service`], and then wrapped in a [`Layer`].
//! This is done to allow the layer to be used as a service, and to allow it to be
//! composed with other layers.
//!
//! [`Layer`]: rama_core::Layer
//! [`Service`]: rama_core::Service

pub mod classifier;
pub mod emulate;
