//! System Keychain bindings for macOS.
//!
//! Provides access to the macOS System Keychain at
//! `/Library/Keychains/System.keychain`, which is accessible by
//! root-running processes such as Network Extension System Extensions.
//! The container application (running as a normal user) can write secrets here —
//! macOS may prompt for administrator credentials — and the extension can read
//! them without any user interaction.
//!
//! A sysex uses the legacy file-based System Keychain. Access groups and the
//! Data Protection Keychain are not available in this context.
//!
//! ## Secure Enclave
//!
//! The System Keychain itself cannot protect items with the Secure Enclave.
//! The [`secure_enclave`] submodule provides SE-backed hybrid encryption that
//! you can layer on top: mint a key once, persist its opaque blob via
//! [`store_secret`] (or anywhere else), and use it to encrypt arbitrary
//! bytes. The encryption hardware binds the ciphertext to this Mac.
//!
//! ## Tech Notes
//!
//! - [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

mod ca;
pub mod secure_enclave;

pub use ca::{install_system_ca, uninstall_system_ca};

use std::fmt;

use crate::ffi::{core_foundation::cf_release, sys};

const SYSTEM_KEYCHAIN_PATH: &[u8] = b"/Library/Keychains/System.keychain\0";

// Subset of `<Security/SecBase.h>` OSStatus codes that surface from
// the System.keychain operations this module performs. Named for
// log-readability and to drive `osstatus_hint` so operators get a
// remediation pointer rather than just a number.
//
// The full list lives in Apple's SecBase.h; we name only the codes
// our specific call sites realistically produce.

/// `errSecItemNotFound` (-25300). Find returned no match.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecDuplicateItem` (-25299). Surfaces when two writers race a
/// find→add cycle: both observe NOT_FOUND, both call
/// `SecKeychainAddGenericPassword`, the loser sees this code.
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
/// `errSecAuthFailed` (-25293). The Security framework rejected the
/// caller's authorization — typically a wrong administrator password
/// in the prompt, or expired auth context for a privileged operation.
const ERR_SEC_AUTH_FAILED: i32 = -25293;
/// `errSecInteractionNotAllowed` (-25308). Operation needed a UI
/// prompt but the calling context disallowed it. Highly relevant
/// inside a system extension: sysexts run headless and cannot show
/// the System Keychain admin password dialog. Surfacing this with a
/// hint helps operators distinguish "code bug" from "missing
/// sudo-equivalent context".
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// `errSecMissingEntitlement` (-34018). The calling binary doesn't
/// carry the entitlement Security needs for the operation. For
/// sysexts: usually means the keychain access-group / data-protection
/// entitlement was not signed in correctly.
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// Map the operationally-relevant OSStatus codes to a short
/// remediation hint included in the error's `Display` output. Returns
/// `None` for unknown codes — the bare numeric is left alone.
fn osstatus_hint(code: i32) -> Option<&'static str> {
    match code {
        ERR_SEC_ITEM_NOT_FOUND => {
            Some("errSecItemNotFound: requested keychain item does not exist")
        }
        ERR_SEC_DUPLICATE_ITEM => {
            Some("errSecDuplicateItem: another writer added the same item concurrently")
        }
        ERR_SEC_AUTH_FAILED => Some(
            "errSecAuthFailed: authorization rejected (wrong admin password / expired auth context)",
        ),
        ERR_SEC_INTERACTION_NOT_ALLOWED => Some(
            "errSecInteractionNotAllowed: Security needed a UI prompt; this context (e.g. system extension) cannot show one",
        ),
        ERR_SEC_MISSING_ENTITLEMENT => Some(
            "errSecMissingEntitlement: signing identity lacks the keychain access-group / data-protection entitlement",
        ),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct SystemKeychainError {
    code: i32,
    message: &'static str,
}

impl SystemKeychainError {
    fn new(code: i32, message: &'static str) -> Self {
        Self { code, message }
    }

    /// Return the raw OSStatus error code.
    pub fn code(&self) -> i32 {
        self.code
    }
}

impl fmt::Display for SystemKeychainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match osstatus_hint(self.code) {
            Some(hint) => write!(f, "{} (OSStatus {} — {})", self.message, self.code, hint),
            None => write!(f, "{} (OSStatus {})", self.message, self.code),
        }
    }
}

impl std::error::Error for SystemKeychainError {}

/// RAII wrapper that releases a `SecKeychainRef` on drop.
///
/// Construction invariant: only build a `KeychainGuard` from a
/// non-null pointer that the Security framework wrote on a successful
/// status return (e.g. `SecKeychainOpen` returning `errSecSuccess`).
/// `cf_release` on a NULL pointer is a no-op and on a non-CF pointer
/// is undefined behavior — the constructor is the load-bearing safety
/// gate, not `Drop`.
struct KeychainGuard(sys::SecKeychainRef);

impl Drop for KeychainGuard {
    fn drop(&mut self) {
        // Defensive: skip release on null. Callers should never construct
        // a guard from null (see ctor invariant), but a `cf_release` on
        // a stale non-null pointer is worse than an early return.
        if !self.0.is_null() {
            cf_release(self.0.cast());
        }
    }
}

/// RAII wrapper for a `SecKeychainItemRef`. Same construction
/// invariant as [`KeychainGuard`].
struct ItemGuard(sys::SecKeychainItemRef);

impl Drop for ItemGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            cf_release(self.0.cast());
        }
    }
}

fn open_system_keychain() -> Result<KeychainGuard, SystemKeychainError> {
    let mut keychain: sys::SecKeychainRef = std::ptr::null_mut();
    // SAFETY: the path is a valid NUL-terminated C string and `keychain` points
    // to writable storage for the result.
    let status =
        unsafe { sys::SecKeychainOpen(SYSTEM_KEYCHAIN_PATH.as_ptr().cast(), &mut keychain) };
    if status != 0 {
        return Err(SystemKeychainError::new(status, "SecKeychainOpen failed"));
    }
    Ok(KeychainGuard(keychain))
}

/// Load a generic-password secret from the macOS System Keychain.
///
/// `service` and `account` identify the generic-password item.
/// Returns `Ok(None)` when no matching item exists.
///
/// The plaintext is wrapped in [`zeroize::Zeroizing`] so the caller's
/// drop path zeroes the heap allocation that backed it. macOS's
/// `malloc` does not deterministically zero on free, and a
/// long-lived secret (CA private key, VPN credential) sitting in
/// process heap is unnecessary exposure when a panic, core dump, or
/// memory disclosure bug would expose it.
pub fn load_secret(
    service: &str,
    account: &str,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, SystemKeychainError> {
    let keychain = open_system_keychain()?;

    let service_bytes = service.as_bytes();
    let account_bytes = account.as_bytes();
    let mut password_length: u32 = 0;
    let mut password_data: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut item: sys::SecKeychainItemRef = std::ptr::null_mut();

    // SAFETY: all pointer arguments point to valid storage; the keychain handle
    // is kept alive by `keychain` for the duration of the call.
    let status = unsafe {
        sys::SecKeychainFindGenericPassword(
            keychain.0.cast(),
            service_bytes.len() as u32,
            service_bytes.as_ptr().cast(),
            account_bytes.len() as u32,
            account_bytes.as_ptr().cast(),
            &mut password_length,
            &mut password_data,
            &mut item,
        )
    };

    if status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(SystemKeychainError::new(
            status,
            "SecKeychainFindGenericPassword failed",
        ));
    }

    if !item.is_null() {
        let _item = ItemGuard(item);
    }

    let data = if password_data.is_null() || password_length == 0 {
        // SAFETY: even with null/zero we still call FreeContent as required.
        unsafe { sys::SecKeychainItemFreeContent(std::ptr::null_mut(), password_data) };
        Vec::new()
    } else {
        // SAFETY: `password_data` points to `password_length` bytes returned by
        // `SecKeychainFindGenericPassword`; we copy before freeing.
        let slice = unsafe {
            std::slice::from_raw_parts(password_data.cast::<u8>(), password_length as usize)
        };
        let vec = slice.to_vec();
        // SAFETY: `password_data` was returned by
        // `SecKeychainFindGenericPassword` and has not yet been freed; we
        // copied the bytes into `vec` above so freeing is safe.
        unsafe { sys::SecKeychainItemFreeContent(std::ptr::null_mut(), password_data) };
        vec
    };

    Ok(Some(zeroize::Zeroizing::new(data)))
}

/// Store a generic-password secret in the macOS System Keychain.
///
/// Creates the item when it does not exist; updates the existing item otherwise.
/// Writing to the System Keychain from a user-space process may trigger a
/// macOS authorization dialog requesting administrator credentials.
pub fn store_secret(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), SystemKeychainError> {
    // The naive find→update-or-add cycle has a TOCTOU race across
    // writers: two callers (or two threads) can both observe
    // ERR_SEC_ITEM_NOT_FOUND, both call `SecKeychainAddGenericPassword`,
    // and the loser sees `ERR_SEC_DUPLICATE_ITEM` (-25299) — which is
    // not actually a failure, just "another writer beat us; an item
    // already exists, please update it instead". Loop once on that
    // signal so a contended store still converges.
    //
    // The bound is 2 attempts: at most one race-loss, then a retry.
    // A second loss would mean a *third* writer raced again, which
    // is not a soundness issue — it'd just bubble the second error
    // up to the caller. We log the retry so contention is visible.
    let keychain = open_system_keychain()?;
    for attempt in 0..2u8 {
        match try_store_secret_once(&keychain, service, account, secret)? {
            StoreOutcome::Done => return Ok(()),
            StoreOutcome::DuplicateItemRetryAsUpdate => {
                tracing::debug!(
                    target: "rama_apple_ne::system_keychain",
                    attempt,
                    service,
                    account,
                    "store_secret: lost race to another writer (errSecDuplicateItem); retrying as update",
                );
            }
        }
    }
    Err(SystemKeychainError::new(
        ERR_SEC_DUPLICATE_ITEM,
        "store_secret: keychain remained contended after retry",
    ))
}

enum StoreOutcome {
    Done,
    DuplicateItemRetryAsUpdate,
}

fn try_store_secret_once(
    keychain: &KeychainGuard,
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<StoreOutcome, SystemKeychainError> {
    let service_bytes = service.as_bytes();
    let account_bytes = account.as_bytes();
    let mut password_length: u32 = 0;
    let mut password_data: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut item: sys::SecKeychainItemRef = std::ptr::null_mut();

    // SAFETY: same as `load_secret`.
    let find_status = unsafe {
        sys::SecKeychainFindGenericPassword(
            keychain.0.cast(),
            service_bytes.len() as u32,
            service_bytes.as_ptr().cast(),
            account_bytes.len() as u32,
            account_bytes.as_ptr().cast(),
            &mut password_length,
            &mut password_data,
            &mut item,
        )
    };

    if find_status == 0 {
        // Free the password data — we only needed the item reference.
        if !password_data.is_null() {
            // SAFETY: `password_data` is valid and was returned by the find call.
            unsafe { sys::SecKeychainItemFreeContent(std::ptr::null_mut(), password_data) };
        }
        let _item = ItemGuard(item);

        // Update the existing item's data without modifying attributes.
        // SAFETY: `item` is a valid SecKeychainItemRef; NULL attrList means
        // "change data only".
        let status = unsafe {
            sys::SecKeychainItemModifyAttributesAndData(
                item,
                std::ptr::null(),
                secret.len() as u32,
                secret.as_ptr().cast(),
            )
        };
        if status != 0 {
            return Err(SystemKeychainError::new(
                status,
                "SecKeychainItemModifyAttributesAndData failed",
            ));
        }
        return Ok(StoreOutcome::Done);
    }

    if find_status != ERR_SEC_ITEM_NOT_FOUND {
        return Err(SystemKeychainError::new(
            find_status,
            "SecKeychainFindGenericPassword failed",
        ));
    }

    // Item not found — add it.
    // SAFETY: all pointer arguments are valid for the duration of the call.
    let status = unsafe {
        sys::SecKeychainAddGenericPassword(
            keychain.0,
            service_bytes.len() as u32,
            service_bytes.as_ptr().cast(),
            account_bytes.len() as u32,
            account_bytes.as_ptr().cast(),
            secret.len() as u32,
            secret.as_ptr().cast(),
            std::ptr::null_mut(),
        )
    };
    match status {
        0 => Ok(StoreOutcome::Done),
        ERR_SEC_DUPLICATE_ITEM => Ok(StoreOutcome::DuplicateItemRetryAsUpdate),
        other => Err(SystemKeychainError::new(
            other,
            "SecKeychainAddGenericPassword failed",
        )),
    }
}

/// Delete a generic-password secret from the macOS System Keychain.
///
/// Returns `Ok(())` when no matching item exists (idempotent).
pub fn delete_secret(service: &str, account: &str) -> Result<(), SystemKeychainError> {
    let keychain = open_system_keychain()?;

    let service_bytes = service.as_bytes();
    let account_bytes = account.as_bytes();
    let mut item: sys::SecKeychainItemRef = std::ptr::null_mut();

    // SAFETY: same as `load_secret`; we pass null for password out-params since
    // we only want the item reference.
    let find_status = unsafe {
        sys::SecKeychainFindGenericPassword(
            keychain.0.cast(),
            service_bytes.len() as u32,
            service_bytes.as_ptr().cast(),
            account_bytes.len() as u32,
            account_bytes.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut item,
        )
    };

    if find_status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(());
    }
    if find_status != 0 {
        return Err(SystemKeychainError::new(
            find_status,
            "SecKeychainFindGenericPassword failed",
        ));
    }

    let _item = ItemGuard(item);

    // SAFETY: `item` is a valid SecKeychainItemRef.
    let status = unsafe { sys::SecKeychainItemDelete(item) };
    if status != 0 {
        return Err(SystemKeychainError::new(
            status,
            "SecKeychainItemDelete failed",
        ));
    }

    Ok(())
}
