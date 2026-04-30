// Doc-only FFI stub `include!`d from `ffi/sys.rs` when this crate is
// documented from a non-Apple host under `--cfg rama_docsrs`. These
// declarations exist solely so that rustdoc can type-check the rest of the
// crate when bindgen-against-the-Apple-SDK is not available. None of the
// symbols are linkable; rustdoc never produces an executable. Keep signatures
// aligned with the real `<CoreFoundation/CoreFoundation.h>` and
// `<Security/Security.h>` declarations — type-check failures here mean a
// `crate::ffi::sys::SYMBOL` reference in src/ introduced a new symbol that
// needs a stub line, or an existing signature changed.
//
// Adding a new symbol:
//   1. Declare it below in the appropriate section (type / static / fn).
//   2. Use opaque pointer types (`*mut __FooStruct`) for handle types.
//   3. Match the real Apple SDK signature.
//
// `dead_code` / `non_*_case` / etc. allows are inherited from `ffi/sys.rs`
// (the host of `include!`); inner attributes are not permitted in `include!`d
// files.

use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_void};

// ---- Apple SDK base scalar types ------------------------------------------

pub type UInt8 = c_uchar;
pub type UInt32 = c_uint;
pub type SInt32 = c_int;
pub type OSStatus = SInt32;
pub type FourCharCode = UInt32;
pub type OSType = FourCharCode;

// ---- CoreFoundation -------------------------------------------------------

pub type CFIndex = c_long;
pub type CFTypeRef = *const c_void;

#[repr(C)]
pub struct __CFAllocator {
    _unused: [u8; 0],
}
pub type CFAllocatorRef = *const __CFAllocator;

#[repr(C)]
pub struct __CFData {
    _unused: [u8; 0],
}
pub type CFDataRef = *const __CFData;

unsafe extern "C" {
    pub static kCFAllocatorDefault: CFAllocatorRef;

    pub fn CFRelease(cf: CFTypeRef);
    pub fn CFDataCreate(
        allocator: CFAllocatorRef,
        bytes: *const UInt8,
        length: CFIndex,
    ) -> CFDataRef;
    pub fn CFDataGetLength(theData: CFDataRef) -> CFIndex;
    pub fn CFDataGetBytePtr(theData: CFDataRef) -> *const UInt8;
}

// ---- Security: Keychain handles -------------------------------------------

#[repr(C)]
pub struct __SecKeychain {
    _unused: [u8; 0],
}
pub type SecKeychainRef = *mut __SecKeychain;

#[repr(C)]
pub struct __SecKeychainItem {
    _unused: [u8; 0],
}
pub type SecKeychainItemRef = *mut __SecKeychainItem;

#[repr(C)]
pub struct __SecKeychainSearch {
    _unused: [u8; 0],
}
pub type SecKeychainSearchRef = *mut __SecKeychainSearch;

#[repr(C)]
pub struct __SecCertificate {
    _unused: [u8; 0],
}
pub type SecCertificateRef = *mut __SecCertificate;

pub type SecKeychainAttrType = OSType;
pub type SecItemClass = FourCharCode;

#[repr(C)]
pub struct SecKeychainAttribute {
    pub tag: SecKeychainAttrType,
    pub length: UInt32,
    pub data: *mut c_void,
}

#[repr(C)]
pub struct SecKeychainAttributeList {
    pub count: UInt32,
    pub attr: *mut SecKeychainAttribute,
}

// ---- Security: Keychain functions -----------------------------------------

unsafe extern "C" {
    pub fn SecKeychainOpen(pathName: *const c_char, keychain: *mut SecKeychainRef) -> OSStatus;

    pub fn SecKeychainAddGenericPassword(
        keychain: SecKeychainRef,
        serviceNameLength: UInt32,
        serviceName: *const c_char,
        accountNameLength: UInt32,
        accountName: *const c_char,
        passwordLength: UInt32,
        passwordData: *const c_void,
        itemRef: *mut SecKeychainItemRef,
    ) -> OSStatus;

    pub fn SecKeychainFindGenericPassword(
        keychainOrArray: CFTypeRef,
        serviceNameLength: UInt32,
        serviceName: *const c_char,
        accountNameLength: UInt32,
        accountName: *const c_char,
        passwordLength: *mut UInt32,
        passwordData: *mut *mut c_void,
        itemRef: *mut SecKeychainItemRef,
    ) -> OSStatus;

    pub fn SecKeychainItemModifyAttributesAndData(
        itemRef: SecKeychainItemRef,
        attrList: *const SecKeychainAttributeList,
        length: UInt32,
        data: *const c_void,
    ) -> OSStatus;

    pub fn SecKeychainItemFreeContent(
        attrList: *mut SecKeychainAttributeList,
        data: *mut c_void,
    ) -> OSStatus;

    pub fn SecKeychainItemDelete(itemRef: SecKeychainItemRef) -> OSStatus;

    pub fn SecKeychainSearchCreateFromAttributes(
        keychainOrArray: CFTypeRef,
        itemClass: SecItemClass,
        attrList: *const SecKeychainAttributeList,
        searchRef: *mut SecKeychainSearchRef,
    ) -> OSStatus;

    pub fn SecKeychainSearchCopyNext(
        searchRef: SecKeychainSearchRef,
        itemRef: *mut SecKeychainItemRef,
    ) -> OSStatus;

    pub fn SecCertificateCreateWithData(
        allocator: CFAllocatorRef,
        data: CFDataRef,
    ) -> SecCertificateRef;
    pub fn SecCertificateCopyData(certificate: SecCertificateRef) -> CFDataRef;
    pub fn SecCertificateAddToKeychain(
        certificate: SecCertificateRef,
        keychain: SecKeychainRef,
    ) -> OSStatus;
}
