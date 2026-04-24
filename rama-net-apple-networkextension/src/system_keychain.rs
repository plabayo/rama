//! System Keychain bindings for macOS.
//!
//! Provides access to the macOS System Keychain at
//! `/Library/Keychains/System.keychain`, which is accessible by
//! root-running processes such as Network Extension System Extensions.
//! The host application (running as a normal user) can write secrets here —
//! macOS may prompt for administrator credentials — and the extension can read
//! them without any user interaction.
//!
//! A sysex uses the legacy file-based System Keychain. Access groups and the
//! Data Protection Keychain are not available in this context.
//!
//! ## Tech Notes
//!
//! - [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

use std::fmt;

use crate::ffi::{core_foundation::cf_release, sys};

const SYSTEM_KEYCHAIN_PATH: &[u8] = b"/Library/Keychains/System.keychain\0";

// OSStatus constant for "item not found" (-25300).
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

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
        write!(f, "{} (OSStatus {})", self.message, self.code)
    }
}

impl std::error::Error for SystemKeychainError {}

struct KeychainGuard(sys::SecKeychainRef);

impl Drop for KeychainGuard {
    fn drop(&mut self) {
        cf_release(self.0.cast());
    }
}

struct ItemGuard(sys::SecKeychainItemRef);

impl Drop for ItemGuard {
    fn drop(&mut self) {
        cf_release(self.0.cast());
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
pub fn load_secret(service: &str, account: &str) -> Result<Option<Vec<u8>>, SystemKeychainError> {
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
        unsafe { sys::SecKeychainItemFreeContent(std::ptr::null_mut(), password_data) };
        vec
    };

    Ok(Some(data))
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
    let keychain = open_system_keychain()?;

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
        return Ok(());
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
    if status != 0 {
        return Err(SystemKeychainError::new(
            status,
            "SecKeychainAddGenericPassword failed",
        ));
    }

    Ok(())
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
