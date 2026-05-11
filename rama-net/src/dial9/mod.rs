//! Shared helpers for `dial9` support in `rama-net` and dependent crates.

mod std_io;
mod trace_field;

pub use std_io::{io_error_kind_code, io_error_raw_os_code};
