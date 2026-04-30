// Doc-only FFI stub `include!`d from `ffi.rs` when this crate is documented
// from a non-Apple host under `--cfg rama_docsrs`. These declarations exist
// solely so that rustdoc can type-check the rest of the crate when
// bindgen-against-the-Apple-SDK is not available. None of the symbols are
// linkable; rustdoc never produces an executable. Keep signatures aligned with
// the real `<xpc/*.h>` and `<dispatch/dispatch.h>` declarations — type-check
// failures here mean a `crate::ffi::SYMBOL` reference in src/ introduced a new
// symbol that needs a stub line, or an existing signature changed.
//
// Adding a new symbol:
//   1. Declare it below in the appropriate section (type / static / fn).
//   2. Use opaque pointer types (`*mut c_void`) for all XPC handle types.
//   3. Match the real Apple SDK signature.
//
// `dead_code` / `non_*_case` / etc. allows are inherited from `ffi.rs` (the
// host of `include!`); inner attributes are not permitted in `include!`d files.

use std::os::raw::{c_char, c_int, c_void};

// ---- Opaque handle types ---------------------------------------------------

pub type xpc_object_t = *mut c_void;
pub type xpc_connection_t = *mut c_void;
pub type xpc_endpoint_t = *mut c_void;
pub type dispatch_queue_t = *mut c_void;

// XPC's primary identifier types — match libxpc.
pub type pid_t = c_int;
pub type uid_t = u32;
pub type gid_t = u32;
pub type au_asid_t = c_int;
pub type uuid_t = [u8; 16];

// ---- Constants -------------------------------------------------------------

pub const XPC_CONNECTION_MACH_SERVICE_LISTENER: u32 = 1;
pub const XPC_CONNECTION_MACH_SERVICE_PRIVILEGED: u32 = 2;

// ---- Type-identity statics (compared by address: `&_xpc_type_X as *const _`) ----

unsafe extern "C" {
    pub static _xpc_type_array: c_void;
    pub static _xpc_type_bool: c_void;
    pub static _xpc_type_connection: c_void;
    pub static _xpc_type_data: c_void;
    pub static _xpc_type_date: c_void;
    pub static _xpc_type_dictionary: c_void;
    pub static _xpc_type_double: c_void;
    pub static _xpc_type_endpoint: c_void;
    pub static _xpc_type_error: c_void;
    pub static _xpc_type_fd: c_void;
    pub static _xpc_type_int64: c_void;
    pub static _xpc_type_null: c_void;
    pub static _xpc_type_string: c_void;
    pub static _xpc_type_uint64: c_void;
    pub static _xpc_type_uuid: c_void;
}

// Error dictionaries / well-known error keys.
unsafe extern "C" {
    pub static _xpc_error_connection_interrupted: c_void;
    pub static _xpc_error_connection_invalid: c_void;
    pub static _xpc_error_peer_code_signing_requirement: c_void;
    pub static _xpc_error_key_description: *const c_char;
}

// ---- Functions -------------------------------------------------------------

unsafe extern "C" {
    // dispatch
    pub fn dispatch_queue_create(label: *const c_char, attr: *mut c_void) -> dispatch_queue_t;

    // type / refcount
    pub fn xpc_get_type(object: xpc_object_t) -> *mut c_void;
    pub fn xpc_retain(object: xpc_object_t) -> xpc_object_t;
    pub fn xpc_release(object: xpc_object_t);

    // primitives
    pub fn xpc_null_create() -> xpc_object_t;
    pub fn xpc_bool_create(value: bool) -> xpc_object_t;
    pub fn xpc_bool_get_value(object: xpc_object_t) -> bool;
    pub fn xpc_int64_create(value: i64) -> xpc_object_t;
    pub fn xpc_int64_get_value(object: xpc_object_t) -> i64;
    pub fn xpc_uint64_create(value: u64) -> xpc_object_t;
    pub fn xpc_uint64_get_value(object: xpc_object_t) -> u64;
    pub fn xpc_double_create(value: f64) -> xpc_object_t;
    pub fn xpc_double_get_value(object: xpc_object_t) -> f64;
    pub fn xpc_date_create(interval: i64) -> xpc_object_t;
    pub fn xpc_date_get_value(object: xpc_object_t) -> i64;
    pub fn xpc_string_create(string: *const c_char) -> xpc_object_t;
    pub fn xpc_string_get_string_ptr(object: xpc_object_t) -> *const c_char;
    pub fn xpc_data_create(bytes: *const c_void, length: usize) -> xpc_object_t;
    pub fn xpc_data_get_length(object: xpc_object_t) -> usize;
    pub fn xpc_data_get_bytes_ptr(object: xpc_object_t) -> *const c_void;
    pub fn xpc_uuid_create(uuid: *const u8) -> xpc_object_t;
    pub fn xpc_uuid_get_bytes(object: xpc_object_t) -> *const u8;
    pub fn xpc_fd_create(fd: c_int) -> xpc_object_t;
    pub fn xpc_fd_dup(object: xpc_object_t) -> c_int;

    // arrays
    pub fn xpc_array_create(values: *const xpc_object_t, count: usize) -> xpc_object_t;
    pub fn xpc_array_append_value(array: xpc_object_t, value: xpc_object_t);
    pub fn xpc_array_get_count(array: xpc_object_t) -> usize;
    pub fn xpc_array_apply(array: xpc_object_t, applier: *mut c_void) -> bool;

    // dictionaries
    pub fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const xpc_object_t,
        count: usize,
    ) -> xpc_object_t;
    pub fn xpc_dictionary_create_reply(original: xpc_object_t) -> xpc_object_t;
    pub fn xpc_dictionary_get_count(dictionary: xpc_object_t) -> usize;
    pub fn xpc_dictionary_get_string(
        dictionary: xpc_object_t,
        key: *const c_char,
    ) -> *const c_char;
    pub fn xpc_dictionary_set_value(
        dictionary: xpc_object_t,
        key: *const c_char,
        value: xpc_object_t,
    );
    pub fn xpc_dictionary_apply(dictionary: xpc_object_t, applier: *mut c_void) -> bool;

    // endpoints
    pub fn xpc_endpoint_create(connection: xpc_connection_t) -> xpc_object_t;

    // connections
    pub fn xpc_connection_create(name: *const c_char, target: dispatch_queue_t) -> xpc_connection_t;
    pub fn xpc_connection_create_mach_service(
        name: *const c_char,
        target: dispatch_queue_t,
        flags: u64,
    ) -> xpc_connection_t;
    pub fn xpc_connection_create_from_endpoint(endpoint: xpc_object_t) -> xpc_connection_t;
    pub fn xpc_connection_set_event_handler(connection: xpc_connection_t, handler: *mut c_void);
    pub fn xpc_connection_activate(connection: xpc_connection_t);
    pub fn xpc_connection_resume(connection: xpc_connection_t);
    pub fn xpc_connection_suspend(connection: xpc_connection_t);
    pub fn xpc_connection_cancel(connection: xpc_connection_t);
    pub fn xpc_connection_send_message(connection: xpc_connection_t, message: xpc_object_t);
    pub fn xpc_connection_send_message_with_reply(
        connection: xpc_connection_t,
        message: xpc_object_t,
        replyq: dispatch_queue_t,
        handler: *mut c_void,
    );

    // connection peer credentials
    pub fn xpc_connection_get_name(connection: xpc_connection_t) -> *const c_char;
    pub fn xpc_connection_get_pid(connection: xpc_connection_t) -> pid_t;
    pub fn xpc_connection_get_euid(connection: xpc_connection_t) -> uid_t;
    pub fn xpc_connection_get_egid(connection: xpc_connection_t) -> gid_t;
    pub fn xpc_connection_get_asid(connection: xpc_connection_t) -> au_asid_t;
    pub fn xpc_connection_copy_invalidation_reason(connection: xpc_connection_t) -> *mut c_char;

    // connection peer security
    pub fn xpc_connection_set_peer_code_signing_requirement(
        connection: xpc_connection_t,
        requirement: *const c_char,
    ) -> c_int;
    pub fn xpc_connection_set_peer_entitlement_exists_requirement(
        connection: xpc_connection_t,
        entitlement: *const c_char,
    ) -> c_int;
    pub fn xpc_connection_set_peer_entitlement_matches_value_requirement(
        connection: xpc_connection_t,
        entitlement: *const c_char,
        value: xpc_object_t,
    ) -> c_int;
    pub fn xpc_connection_set_peer_lightweight_code_requirement(
        connection: xpc_connection_t,
        requirement: *const c_char,
    ) -> c_int;
    pub fn xpc_connection_set_peer_platform_identity_requirement(
        connection: xpc_connection_t,
        identity: *const c_char,
    ) -> c_int;
    pub fn xpc_connection_set_peer_team_identity_requirement(
        connection: xpc_connection_t,
        team: *const c_char,
    ) -> c_int;
}
