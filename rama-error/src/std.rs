#[cfg(feature = "std")]
pub(crate) use std::{boxed::Box, string::String, vec::Vec};

#[cfg(all(feature = "std", target_has_atomic = "ptr"))]
pub(crate) use std::sync::Arc;

#[cfg(not(feature = "std"))]
pub(crate) use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(all(not(feature = "std"), target_has_atomic = "ptr"))]
pub(crate) use alloc::sync::Arc;
