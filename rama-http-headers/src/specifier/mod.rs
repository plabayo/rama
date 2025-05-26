//! Specifiers that can be used as part of header values.
//!
//! An example is the [`QValue`] used in function of several headers such as 'accept-encoding'.

mod quality_value;
pub use quality_value::{Quality, QualityValue};
