//! CA certificate install / uninstall in the macOS System Keychain.
//!
//! These functions manage the **keychain item** for a CA certificate — they
//! do not touch macOS trust settings. Trust changes (e.g. via
//! `SecTrustSettingsSetTrustSettings` in the `admin` domain) go through
//! Authorization Services and require an interactive admin auth dialog,
//! which a non-UI process such as a Network Extension System Extension
//! cannot present (the call returns `errAuthorizationInteractionNotAllowed`
//! / OSStatus -60007). Trust setup is therefore the responsibility of a UI
//! process (typically the container app), which can present the dialog.
//!
//! These functions need write access to `/Library/Keychains/System.keychain`
//! and so should run from a process with root privileges (e.g. inside a
//! Network Extension System Extension).

use crate::ffi::{core_foundation::cf_release, sys};

use super::{ERR_SEC_ITEM_NOT_FOUND, ItemGuard, SystemKeychainError, open_system_keychain};

/// `kSecCertificateItemClass` from `<Security/SecKeychainItem.h>`. Stable
/// since pre-OSX days; bindgen does not surface anonymous-enum members so
/// we hardcode the value.
const SEC_CERTIFICATE_ITEM_CLASS: sys::SecItemClass = 0x8000_1000;

/// `errSecDuplicateItem` (-25299). Non-fatal during install — the cert is
/// already in the keychain.
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;

struct CertGuard(sys::SecCertificateRef);
impl Drop for CertGuard {
    fn drop(&mut self) {
        cf_release(self.0.cast());
    }
}

struct CFDataGuard(sys::CFDataRef);
impl Drop for CFDataGuard {
    fn drop(&mut self) {
        cf_release(self.0.cast());
    }
}

struct SearchGuard(sys::SecKeychainSearchRef);
impl Drop for SearchGuard {
    fn drop(&mut self) {
        cf_release(self.0.cast());
    }
}

fn create_certificate(cert_der: &[u8]) -> Result<CertGuard, SystemKeychainError> {
    if cert_der.is_empty() {
        return Err(SystemKeychainError::new(0, "empty certificate DER"));
    }
    // SAFETY: pointer + length describe valid memory; CFDataCreate copies the bytes.
    let cf_data = unsafe {
        sys::CFDataCreate(
            std::ptr::null_mut(),
            cert_der.as_ptr().cast(),
            cert_der.len() as sys::CFIndex,
        )
    };
    if cf_data.is_null() {
        return Err(SystemKeychainError::new(0, "CFDataCreate failed"));
    }
    let _data_guard = CFDataGuard(cf_data);

    // SAFETY: cf_data is a valid CFDataRef.
    let cert = unsafe { sys::SecCertificateCreateWithData(std::ptr::null_mut(), cf_data) };
    if cert.is_null() {
        return Err(SystemKeychainError::new(
            0,
            "SecCertificateCreateWithData failed (invalid DER?)",
        ));
    }
    Ok(CertGuard(cert))
}

/// Install a CA certificate into the macOS System Keychain.
///
/// This adds the cert as a keychain item under
/// `/Library/Keychains/System.keychain`. It does **not** modify trust
/// settings — see the module-level docs for why that has to happen
/// elsewhere. Idempotent: re-installing an already-present certificate
/// succeeds.
pub fn install_system_ca(cert_der: &[u8]) -> Result<(), SystemKeychainError> {
    let cert = create_certificate(cert_der)?;
    let keychain = open_system_keychain()?;

    // SAFETY: cert.0 and keychain.0 are valid CF objects retained by their guards.
    let add_status = unsafe { sys::SecCertificateAddToKeychain(cert.0, keychain.0) };
    if add_status != 0 && add_status != ERR_SEC_DUPLICATE_ITEM {
        return Err(SystemKeychainError::new(
            add_status,
            "SecCertificateAddToKeychain failed",
        ));
    }
    Ok(())
}

/// Inverse of [`install_system_ca`]: delete every matching certificate item
/// from the System Keychain.
///
/// Idempotent: returns `Ok(())` when no matching cert is present. Does not
/// touch trust settings.
pub fn uninstall_system_ca(cert_der: &[u8]) -> Result<(), SystemKeychainError> {
    // We don't need a SecCertificateRef from the input here — we just need the
    // raw DER for byte-equality matching against the keychain's cert items.
    if cert_der.is_empty() {
        return Err(SystemKeychainError::new(0, "empty certificate DER"));
    }

    let keychain = open_system_keychain()?;
    let mut search: sys::SecKeychainSearchRef = std::ptr::null_mut();
    // SAFETY: `keychain.0` is a valid SecKeychainRef; NULL attrList = no filter.
    let create_status = unsafe {
        sys::SecKeychainSearchCreateFromAttributes(
            keychain.0.cast(),
            SEC_CERTIFICATE_ITEM_CLASS,
            std::ptr::null(),
            &mut search,
        )
    };
    if create_status != 0 {
        return Err(SystemKeychainError::new(
            create_status,
            "SecKeychainSearchCreateFromAttributes failed",
        ));
    }
    let _search_guard = SearchGuard(search);

    loop {
        let mut item: sys::SecKeychainItemRef = std::ptr::null_mut();
        // SAFETY: `search` is valid for the lifetime of `_search_guard`.
        let next_status = unsafe { sys::SecKeychainSearchCopyNext(search, &mut item) };
        if next_status == ERR_SEC_ITEM_NOT_FOUND {
            break;
        }
        if next_status != 0 {
            return Err(SystemKeychainError::new(
                next_status,
                "SecKeychainSearchCopyNext failed",
            ));
        }
        let item_guard = ItemGuard(item);

        // `SecKeychainItemRef` and `SecCertificateRef` are toll-free-bridged
        // when the keychain item's class is certificate.
        // SAFETY: `item` came from a search scoped to the cert item class.
        let cf_data = unsafe { sys::SecCertificateCopyData(item.cast()) };
        if cf_data.is_null() {
            continue;
        }
        let _data_guard = CFDataGuard(cf_data);

        // SAFETY: cf_data is a valid non-null CFDataRef.
        let len = unsafe { sys::CFDataGetLength(cf_data) } as usize;
        let bytes_ptr = unsafe { sys::CFDataGetBytePtr(cf_data) };
        if bytes_ptr.is_null() || len != cert_der.len() {
            continue;
        }
        // SAFETY: bytes_ptr is valid for `len` bytes inside the CFData.
        let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr.cast::<u8>(), len) };
        if bytes != cert_der {
            continue;
        }

        // SAFETY: `item` is a valid SecKeychainItemRef.
        let del_status = unsafe { sys::SecKeychainItemDelete(item) };
        if del_status != 0 && del_status != ERR_SEC_ITEM_NOT_FOUND {
            return Err(SystemKeychainError::new(
                del_status,
                "SecKeychainItemDelete failed for cert item",
            ));
        }
        // Continue scanning in case duplicates exist.
        drop(item_guard);
    }
    Ok(())
}
