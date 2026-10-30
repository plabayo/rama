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

/// Owned `SecCertificateRef`, released on drop.
struct CertGuard(
    // Safety invariant: a non-null `SecCertificateRef` on which this guard owns one
    // reference (Create/Copy rule), released exactly once by `Drop`.
    sys::SecCertificateRef,
);

impl Drop for CertGuard {
    fn drop(&mut self) {
        // SAFETY: `cf_release` needs a CF object with one owned reference,
        // released once: the field invariant (non-null, one owned Create/Copy
        // reference, released only here); `Drop` runs once and nothing follows.
        unsafe { cf_release(self.0.cast()) };
    }
}

/// Owned `CFDataRef`, released on drop.
struct CFDataGuard(
    // Safety invariant: a non-null `CFDataRef` on which this guard owns one
    // reference (Create/Copy rule), released exactly once by `Drop`.
    sys::CFDataRef,
);

impl Drop for CFDataGuard {
    fn drop(&mut self) {
        // SAFETY: `cf_release` needs a CF object with one owned reference,
        // released once: the field invariant (non-null, one owned Create/Copy
        // reference, released only here); `Drop` runs once and nothing follows.
        unsafe { cf_release(self.0.cast()) };
    }
}

/// Owned `SecKeychainSearchRef`, released on drop.
struct SearchGuard(
    // Safety invariant: a non-null `SecKeychainSearchRef` on which this guard owns
    // one reference (Create/Copy rule), released exactly once by `Drop`.
    sys::SecKeychainSearchRef,
);

impl Drop for SearchGuard {
    fn drop(&mut self) {
        // SAFETY: `cf_release` needs a CF object with one owned reference,
        // released once: the field invariant (non-null, one owned Create/Copy
        // reference, released only here); `Drop` runs once and nothing follows.
        unsafe { cf_release(self.0.cast()) };
    }
}

fn create_certificate(cert_der: &[u8]) -> Result<CertGuard, SystemKeychainError> {
    if cert_der.is_empty() {
        return Err(SystemKeychainError::new(0, "empty certificate DER"));
    }
    let len = sys::CFIndex::try_from(cert_der.len())
        .map_err(|_overflow| SystemKeychainError::new(0, "certificate DER too long"))?;
    // SAFETY: `CFDataCreate(allocator, bytes, length)` copies `length` bytes from
    // `bytes` into a new CFData returned under the Create rule (NULL on failure); a
    // NULL allocator selects the default one. `cert_der` is live for the call and
    // exactly `len` bytes long.
    let cf_data = unsafe { sys::CFDataCreate(std::ptr::null(), cert_der.as_ptr(), len) };
    if cf_data.is_null() {
        return Err(SystemKeychainError::new(0, "CFDataCreate failed"));
    }
    // Field invariant: non-null and owned by us per the Create rule above.
    let data = CFDataGuard(cf_data);

    // SAFETY: `SecCertificateCreateWithData(allocator, data)` reads the DER in `data`
    // without consuming the caller's reference and returns a new certificate under
    // the Create rule, or NULL for invalid DER. `data.0` is a live CFData (field
    // invariant) and stays alive until `data` drops after the call.
    let cert = unsafe { sys::SecCertificateCreateWithData(std::ptr::null(), data.0) };
    if cert.is_null() {
        return Err(SystemKeychainError::new(
            0,
            "SecCertificateCreateWithData failed (invalid DER?)",
        ));
    }
    // Field invariant: non-null and owned by us per the Create rule above.
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

    // SAFETY: `SecCertificateAddToKeychain(certificate, keychain)` adds a copy of the
    // certificate to `keychain` and consumes neither reference. `cert.0` and
    // `keychain.0` are live refs per their guards' field invariants.
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
///
/// # Implementation note
///
/// Apple's docs are explicit that mutating the keychain (e.g.
/// `SecKeychainItemDelete`) **invalidates** an in-progress
/// `SecKeychainSearchRef`: subsequent `SecKeychainSearchCopyNext` calls
/// may skip items, revisit deleted items, or return inconsistent
/// results. We therefore split the work in two phases:
///
/// 1. **Gather**: drive `SecKeychainSearchCopyNext` to completion,
///    keeping every item whose DER matches `cert_der`. The search is
///    closed (its `SearchGuard` drops) before any mutation.
/// 2. **Delete**: iterate the gathered items and call
///    `SecKeychainItemDelete` on each. The keychain is no longer being
///    enumerated by an open search at this point, so deletes are safe.
pub fn uninstall_system_ca(cert_der: &[u8]) -> Result<(), SystemKeychainError> {
    // We don't need a SecCertificateRef from the input here — we just need the
    // raw DER for byte-equality matching against the keychain's cert items.
    if cert_der.is_empty() {
        return Err(SystemKeychainError::new(0, "empty certificate DER"));
    }

    let keychain = open_system_keychain()?;

    // ── Phase 1: gather matching items, then drop the search handle ─────
    let matched: Vec<ItemGuard> = {
        let mut search: sys::SecKeychainSearchRef = std::ptr::null_mut();
        // SAFETY: `SecKeychainSearchCreateFromAttributes(keychainOrArray, itemClass,
        // attrList, searchRef)` matches every item of `itemClass` when `attrList` is
        // NULL and stores one owned search ref (Create rule) in `*searchRef`.
        // `keychain.0` is a live keychain ref (field invariant) and `search` is a
        // live, writable local.
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
        if search.is_null() {
            return Err(SystemKeychainError::new(
                0,
                "SecKeychainSearchCreateFromAttributes returned no search",
            ));
        }
        // Field invariant: non-null and owned by us per the Create rule above.
        let search = SearchGuard(search);

        let mut matched = Vec::new();
        loop {
            let mut item: sys::SecKeychainItemRef = std::ptr::null_mut();
            // SAFETY: `SecKeychainSearchCopyNext(searchRef, itemRef)` stores the next
            // match as one owned item ref (Copy rule) in `*itemRef`, or returns
            // `errSecItemNotFound` at the end. `search.0` is a live search ref (field
            // invariant) and `item` is a live, writable local.
            let next_status = unsafe { sys::SecKeychainSearchCopyNext(search.0, &mut item) };
            if next_status == ERR_SEC_ITEM_NOT_FOUND {
                break;
            }
            if next_status != 0 {
                return Err(SystemKeychainError::new(
                    next_status,
                    "SecKeychainSearchCopyNext failed",
                ));
            }
            if item.is_null() {
                return Err(SystemKeychainError::new(
                    0,
                    "SecKeychainSearchCopyNext returned no item",
                ));
            }
            // Field invariant: non-null and owned by us per the Copy rule above.
            let item = ItemGuard(item);

            // SAFETY: `SecCertificateCopyData(certificate)` returns the certificate's
            // DER as a new CFData (Copy rule), or NULL. `item.0` is a live item ref
            // (field invariant) from a search scoped to `kSecCertificateItemClass`;
            // on macOS such keychain items are `SecCertificateRef`s
            // (`SecCertificate.h`), so the cast names the same object.
            let cf_data = unsafe { sys::SecCertificateCopyData(item.0.cast()) };
            if cf_data.is_null() {
                continue;
            }
            // Field invariant: non-null and owned by us per the Copy rule above.
            let data = CFDataGuard(cf_data);

            // SAFETY: `CFDataGetLength(theData)` only reads `theData`, a live CFData
            // per `data`'s field invariant.
            let len = unsafe { sys::CFDataGetLength(data.0) };
            // SAFETY: `CFDataGetBytePtr(theData)` returns a read-only pointer to the
            // bytes of `theData`, valid while it is alive and unmutated; `data.0` is a
            // live, immutable CFData per `data`'s field invariant.
            let bytes_ptr = unsafe { sys::CFDataGetBytePtr(data.0) };
            if bytes_ptr.is_null() || usize::try_from(len) != Ok(cert_der.len()) {
                continue;
            }
            // SAFETY: `slice::from_raw_parts` needs a non-null pointer, aligned for
            // `u8` (always), readable for `len` initialized bytes in one allocation,
            // unmutated for the borrow, and `len <= isize::MAX`. `bytes_ptr` is
            // non-null (checked) and points to the `len` bytes of the immutable CFData
            // that `data` keeps alive past the last use of `bytes`; `len` equals
            // `cert_der.len()`, the length of a live slice, so it is `<= isize::MAX`.
            let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr, cert_der.len()) };
            if bytes != cert_der {
                continue;
            }

            matched.push(item);
        }
        matched
        // `search` drops here, closing the search handle. No
        // mutation has happened yet so the search was driven to a
        // consistent end (ERR_SEC_ITEM_NOT_FOUND).
    };

    // ── Phase 2: delete each matched item; the search is closed ──────────
    for item in &matched {
        // SAFETY: `SecKeychainItemDelete(itemRef)` removes the item from its keychain
        // and does not release `itemRef`. `item.0` is a live item ref (field
        // invariant) and `item` still owns (and later releases) its reference.
        let del_status = unsafe { sys::SecKeychainItemDelete(item.0) };
        if del_status != 0 && del_status != ERR_SEC_ITEM_NOT_FOUND {
            return Err(SystemKeychainError::new(
                del_status,
                "SecKeychainItemDelete failed for cert item",
            ));
        }
    }
    drop(matched);
    Ok(())
}
