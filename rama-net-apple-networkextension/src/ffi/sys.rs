#![allow(
    dead_code,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unreachable_pub,
    clippy::all
)]

// On macOS we use the bindgen output produced by build.rs. On non-Apple hosts
// running under `--cfg rama_docsrs` (cross-platform doc build), we substitute a
// checked-in copy of that bindgen output so this module type-checks. None of
// the declarations are linkable; rustdoc only type-checks. Regenerate the
// committed copy by re-running bindgen on macOS — see build.rs.
#[cfg(target_os = "macos")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(all(rama_docsrs, not(target_os = "macos")))]
include!("_doc_sys_stub.rs");
