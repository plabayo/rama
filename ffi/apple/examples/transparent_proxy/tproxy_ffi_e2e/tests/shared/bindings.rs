// bindgen output: its zeroing `Default` impls have no `// SAFETY:` proofs.
#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
