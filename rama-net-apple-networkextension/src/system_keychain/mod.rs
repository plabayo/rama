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

use zeroize::Zeroize as _;

use crate::ffi::{core_foundation::cf_release, sys};

const SYSTEM_KEYCHAIN_PATH: &[u8] = b"/Library/Keychains/System.keychain\0";

// Subset of `<Security/SecBase.h>` OSStatus codes that surface from
// the System.keychain operations this module performs. Named for
// log-readability and to drive `osstatus_hint` so operators get a
// remediation pointer rather than just a number.
//
// The full list lives in Apple's SecBase.h; we name only the codes
// our specific call sites realistically produce.

/// `errSecParam` (-50). An input was invalid, e.g. too long for a `UInt32`
/// length parameter.
const ERR_SEC_PARAM: i32 = -50;
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

/// Security.framework takes `UInt32` lengths; reject larger inputs instead of truncating them.
fn u32_len(len: usize, message: &'static str) -> Result<u32, SystemKeychainError> {
    u32::try_from(len).map_err(|_overflow| SystemKeychainError::new(ERR_SEC_PARAM, message))
}

/// Owned `SecKeychainRef`, released on drop.
struct KeychainGuard(
    // Safety invariant: a non-null `SecKeychainRef` on which this guard owns one
    // reference (Create/Copy rule), released exactly once by `Drop`.
    sys::SecKeychainRef,
);

impl Drop for KeychainGuard {
    fn drop(&mut self) {
        // SAFETY: `cf_release` needs a CF object with one owned reference,
        // released once: the field invariant (non-null, one owned Create/Copy
        // reference, released only here); `Drop` runs once and nothing follows.
        unsafe { cf_release(self.0.cast()) };
    }
}

/// Owned `SecKeychainItemRef`, released on drop.
struct ItemGuard(
    // Safety invariant: a non-null `SecKeychainItemRef` on which this guard owns
    // one reference (Create/Copy rule), released exactly once by `Drop`.
    sys::SecKeychainItemRef,
);

impl Drop for ItemGuard {
    fn drop(&mut self) {
        // SAFETY: `cf_release` needs a CF object with one owned reference,
        // released once: the field invariant (non-null, one owned Create/Copy
        // reference, released only here); `Drop` runs once and nothing follows.
        unsafe { cf_release(self.0.cast()) };
    }
}

fn open_system_keychain() -> Result<KeychainGuard, SystemKeychainError> {
    let mut keychain: sys::SecKeychainRef = std::ptr::null_mut();
    // SAFETY: `SecKeychainOpen(pathName, keychain)` reads the NUL-terminated
    // `pathName` and stores one owned `SecKeychainRef` (Create rule) in `*keychain`.
    // `SYSTEM_KEYCHAIN_PATH` is a `'static` NUL-terminated byte string and
    // `keychain` is a live, writable local.
    let status =
        unsafe { sys::SecKeychainOpen(SYSTEM_KEYCHAIN_PATH.as_ptr().cast(), &raw mut keychain) };
    if status != 0 {
        return Err(SystemKeychainError::new(status, "SecKeychainOpen failed"));
    }
    if keychain.is_null() {
        return Err(SystemKeychainError::new(
            0,
            "SecKeychainOpen returned no keychain",
        ));
    }
    // Field invariant: non-null and owned by us per the Create rule above.
    Ok(KeychainGuard(keychain))
}

/// Look up the generic-password item for `service`/`account`.
///
/// Returns `Ok(None)` when no matching item exists.
fn find_item(
    keychain: &KeychainGuard,
    service: &str,
    account: &str,
) -> Result<Option<ItemGuard>, SystemKeychainError> {
    let service_len = u32_len(service.len(), "keychain service name too long")?;
    let account_len = u32_len(account.len(), "keychain account name too long")?;
    let mut item: sys::SecKeychainItemRef = std::ptr::null_mut();
    // SAFETY: `SecKeychainFindGenericPassword` reads `serviceNameLength` and
    // `accountNameLength` bytes from the name pointers, skips the password out-params
    // when both are NULL, and stores one owned item ref (Create rule) in `*itemRef`.
    // `keychain.0` is a live keychain ref (field invariant); `service` and `account`
    // are live for the call and exactly `service_len`/`account_len` bytes long;
    // `item` is a live, writable local.
    let status = unsafe {
        sys::SecKeychainFindGenericPassword(
            keychain.0.cast(),
            service_len,
            service.as_ptr().cast(),
            account_len,
            account.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut item,
        )
    };
    match status {
        0 if item.is_null() => Err(SystemKeychainError::new(
            0,
            "SecKeychainFindGenericPassword returned no item",
        )),
        // Field invariant: non-null and owned by us per the Create rule above.
        0 => Ok(Some(ItemGuard(item))),
        ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        other => Err(SystemKeychainError::new(
            other,
            "SecKeychainFindGenericPassword failed",
        )),
    }
}

/// Load a generic-password secret from the macOS System Keychain.
///
/// `service` and `account` identify the generic-password item.
/// Returns `Ok(None)` when no matching item exists.
///
/// The plaintext is wrapped in [`zeroize::Zeroizing`] so the caller's
/// drop path zeroes the heap allocation that backed it, and the buffer
/// Security.framework returned is wiped before it is freed. macOS's
/// `malloc` does not deterministically zero on free, and a
/// long-lived secret (CA private key, VPN credential) sitting in
/// process heap is unnecessary exposure when a panic, core dump, or
/// memory disclosure bug would expose it.
pub fn load_secret(
    service: &str,
    account: &str,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, SystemKeychainError> {
    let keychain = open_system_keychain()?;

    let service_len = u32_len(service.len(), "keychain service name too long")?;
    let account_len = u32_len(account.len(), "keychain account name too long")?;
    let mut password_length: u32 = 0;
    let mut password_data: *mut std::ffi::c_void = std::ptr::null_mut();

    // SAFETY: `SecKeychainFindGenericPassword` reads `serviceNameLength` and
    // `accountNameLength` bytes from the name pointers, skips the item out-param when
    // NULL, and on success stores in `*passwordData` a caller-owned buffer of
    // `*passwordLength` bytes that must be freed with `SecKeychainItemFreeContent`.
    // `keychain.0` is a live keychain ref (field invariant); `service` and `account`
    // are live for the call and exactly `service_len`/`account_len` bytes long; both
    // out-params are live, writable locals.
    let status = unsafe {
        sys::SecKeychainFindGenericPassword(
            keychain.0.cast(),
            service_len,
            service.as_ptr().cast(),
            account_len,
            account.as_ptr().cast(),
            &raw mut password_length,
            &raw mut password_data,
            std::ptr::null_mut(),
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
    if password_data.is_null() {
        return Ok(Some(zeroize::Zeroizing::new(Vec::new())));
    }

    // SAFETY: `slice::from_raw_parts_mut` needs a non-null pointer, aligned for `u8`
    // (always), valid for reads and writes of `len` initialized bytes in one
    // allocation, unaliased for the borrow, and `len <= isize::MAX`. By the find
    // contract above, `password_data` is a caller-owned (non-`const`) buffer of
    // `password_length` bytes that nothing else references until we free it;
    // non-null was checked above; `len <= u32::MAX < isize::MAX` on 64-bit Apple
    // targets. The borrow ends before the buffer is freed below.
    let secret = unsafe {
        std::slice::from_raw_parts_mut(password_data.cast::<u8>(), password_length as usize)
    };
    let copy = zeroize::Zeroizing::new(secret.to_vec());
    secret.zeroize();

    // SAFETY: `SecKeychainItemFreeContent(attrList, data)` frees a `data` buffer
    // returned by a `SecKeychain*` copy/find call; a NULL `attrList` frees nothing
    // else. `password_data` came from the successful find above, its only borrow
    // (`secret`) is no longer used, and it is freed exactly once, here.
    unsafe { sys::SecKeychainItemFreeContent(std::ptr::null_mut(), password_data) };

    Ok(Some(copy))
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
    let secret_len = u32_len(secret.len(), "keychain secret too long")?;

    if let Some(item) = find_item(keychain, service, account)? {
        // SAFETY: `SecKeychainItemModifyAttributesAndData(itemRef, attrList, length,
        // data)` reads `length` bytes from `data`; a NULL `attrList` changes only the
        // data. `item.0` is a live item ref (field invariant) and `secret` is live for
        // the call and exactly `secret_len` bytes long.
        let status = unsafe {
            sys::SecKeychainItemModifyAttributesAndData(
                item.0,
                std::ptr::null(),
                secret_len,
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

    let service_len = u32_len(service.len(), "keychain service name too long")?;
    let account_len = u32_len(account.len(), "keychain account name too long")?;
    // SAFETY: `SecKeychainAddGenericPassword` reads `serviceNameLength`,
    // `accountNameLength` and `passwordLength` bytes from the matching pointers and
    // skips the item out-param when NULL. `keychain.0` is a live keychain ref (field
    // invariant); `service`, `account` and `secret` are live for the call and exactly
    // `service_len`/`account_len`/`secret_len` bytes long.
    let status = unsafe {
        sys::SecKeychainAddGenericPassword(
            keychain.0,
            service_len,
            service.as_ptr().cast(),
            account_len,
            account.as_ptr().cast(),
            secret_len,
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
    let Some(item) = find_item(&keychain, service, account)? else {
        return Ok(());
    };

    // SAFETY: `SecKeychainItemDelete(itemRef)` removes the item from its keychain and
    // does not release `itemRef`. `item.0` is a live item ref (field invariant) and
    // `item` still owns (and later releases) its reference.
    let status = unsafe { sys::SecKeychainItemDelete(item.0) };
    if status != 0 {
        return Err(SystemKeychainError::new(
            status,
            "SecKeychainItemDelete failed",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_len_rejects_lengths_that_would_truncate() {
        assert_eq!(u32_len(5, "x").unwrap(), 5);
        assert_eq!(u32_len(u32::MAX as usize, "x").unwrap(), u32::MAX);
        let err = u32_len(u32::MAX as usize + 1, "too long").unwrap_err();
        assert_eq!(err.code(), ERR_SEC_PARAM);
    }
}
