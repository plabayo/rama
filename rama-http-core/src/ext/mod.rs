//! HTTP extensions.

mod h1_reason_phrase;
pub use h1_reason_phrase::ReasonPhrase;

mod informational;
pub(crate) use informational::OnInformational;
pub use informational::on_informational;
// pub(crate) use informational::{on_informational_raw, OnInformationalCallback}; // ffi feature in hyperium/hyper
