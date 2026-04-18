#[cfg(feature = "std")]
pub(crate) use std::{boxed::Box, string::String, vec::Vec};

#[cfg(not(feature = "std"))]
pub(crate) use alloc::{boxed::Box, string::String, vec::Vec};
