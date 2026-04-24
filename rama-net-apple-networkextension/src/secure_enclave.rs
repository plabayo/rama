use std::{ffi::CString, fmt, ptr, sync::Arc};

use libc::c_char;
use rama_utils::str::arcstr::ArcStr;

mod ffi {
    #![allow(
        dead_code,
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        unreachable_pub,
        clippy::all
    )]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Clone)]
pub struct SecureEnclaveKey {
    private_key: ffi::SecKeyRef,
    application_tag: Arc<[u8]>,
    access_group: Option<ArcStr>,
}

unsafe impl Send for SecureEnclaveKey {}
unsafe impl Sync for SecureEnclaveKey {}

impl SecureEnclaveKey {
    pub fn load_or_create(
        application_tag: impl Into<Arc<[u8]>>,
        access_group: Option<impl Into<ArcStr>>,
    ) -> Result<Self, SecureEnclaveKeyError> {
        let access_group = access_group.map(Into::into);
        let application_tag = application_tag.into();

        if let Some(private_key) = find_private_key(&application_tag, access_group.as_deref())? {
            return Ok(Self {
                private_key,
                application_tag,
                access_group,
            });
        }

        let private_key = create_private_key(&application_tag, access_group.as_deref())?;

        Ok(Self {
            private_key,
            application_tag,
            access_group,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecureEnclaveKeyError> {
        let public_key = copy_public_key(self.private_key)?;
        let plaintext = CfData::new(plaintext);
        let encrypted = create_encrypted_data(
            public_key.as_ptr(),
            unsafe { ffi::kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM },
            plaintext.as_ptr(),
        )?;
        Ok(encrypted.to_vec())
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecureEnclaveKeyError> {
        let ciphertext = CfData::new(ciphertext);
        let decrypted = create_decrypted_data(
            self.private_key,
            unsafe { ffi::kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM },
            ciphertext.as_ptr(),
        )?;
        Ok(decrypted.to_vec())
    }

    pub fn application_tag(&self) -> &[u8] {
        &self.application_tag
    }

    pub fn access_group(&self) -> Option<&str> {
        self.access_group.as_deref()
    }
}

impl Drop for SecureEnclaveKey {
    fn drop(&mut self) {
        cf_release(self.private_key.cast());
    }
}

impl fmt::Debug for SecureEnclaveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureEnclaveKey")
            .field("application_tag", &self.application_tag)
            .field("access_group", &self.access_group)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct SecureEnclaveKeyError {
    code: Option<i64>,
    message: ArcStr,
}

impl SecureEnclaveKeyError {
    fn new(code: Option<i64>, message: impl Into<ArcStr>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> Option<i64> {
        self.code
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }
}

impl fmt::Display for SecureEnclaveKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(f, "{} (code {code})", self.message),
            None => f.write_str(self.message.as_str()),
        }
    }
}

impl std::error::Error for SecureEnclaveKeyError {}

fn find_private_key(
    application_tag: &[u8],
    access_group: Option<&str>,
) -> Result<Option<ffi::SecKeyRef>, SecureEnclaveKeyError> {
    let mut query = QueryDictionary::new();
    query.set_ptr(unsafe { ffi::kSecClass.cast() }, unsafe {
        ffi::kSecClassKey.cast()
    });
    query.set_ptr(unsafe { ffi::kSecAttrKeyClass.cast() }, unsafe {
        ffi::kSecAttrKeyClassPrivate.cast()
    });
    query.set_ptr(unsafe { ffi::kSecReturnRef.cast() }, unsafe {
        ffi::kCFBooleanTrue.cast()
    });
    query.set_ptr(
        unsafe { ffi::kSecUseDataProtectionKeychain.cast() },
        unsafe { ffi::kCFBooleanTrue.cast() },
    );
    query.set_owned(
        unsafe { ffi::kSecAttrApplicationTag.cast() },
        CfData::new(application_tag),
    );
    if let Some(access_group) = access_group {
        query.set_owned(
            unsafe { ffi::kSecAttrAccessGroup.cast() },
            CfString::new(access_group)?,
        );
    }

    let mut result = ptr::null();
    let status = unsafe { ffi::SecItemCopyMatching(query.as_ptr(), &mut result) };
    if status == 0 {
        return Ok(Some(result.cast_mut().cast()));
    }
    if status == -25300 {
        return Ok(None);
    }

    Err(SecureEnclaveKeyError::new(
        Some(status.into()),
        "SecItemCopyMatching failed while loading Secure Enclave key",
    ))
}

fn create_private_key(
    application_tag: &[u8],
    access_group: Option<&str>,
) -> Result<ffi::SecKeyRef, SecureEnclaveKeyError> {
    let access_control = create_access_control()?;

    let mut private_attrs = QueryDictionary::new();
    private_attrs.set_ptr(unsafe { ffi::kSecAttrIsPermanent.cast() }, unsafe {
        ffi::kCFBooleanTrue.cast()
    });
    private_attrs.set_owned(
        unsafe { ffi::kSecAttrApplicationTag.cast() },
        CfData::new(application_tag),
    );
    private_attrs.set_ptr(
        unsafe { ffi::kSecAttrAccessControl.cast() },
        access_control.as_ptr().cast(),
    );

    let mut attrs = QueryDictionary::new();
    attrs.set_ptr(unsafe { ffi::kSecAttrKeyType.cast() }, unsafe {
        ffi::kSecAttrKeyTypeECSECPrimeRandom.cast()
    });
    attrs.set_owned(
        unsafe { ffi::kSecAttrKeySizeInBits.cast() },
        CfNumber::sint32(256),
    );
    attrs.set_ptr(unsafe { ffi::kSecAttrTokenID.cast() }, unsafe {
        ffi::kSecAttrTokenIDSecureEnclave.cast()
    });
    attrs.set_ptr(
        unsafe { ffi::kSecUseDataProtectionKeychain.cast() },
        unsafe { ffi::kCFBooleanTrue.cast() },
    );
    attrs.set_ptr(
        unsafe { ffi::kSecPrivateKeyAttrs.cast() },
        private_attrs.as_ptr().cast(),
    );
    if let Some(access_group) = access_group {
        attrs.set_owned(
            unsafe { ffi::kSecAttrAccessGroup.cast() },
            CfString::new(access_group)?,
        );
    }

    let mut error = ptr::null_mut();
    let key = unsafe { ffi::SecKeyCreateRandomKey(attrs.as_ptr(), &mut error) };
    if !error.is_null() {
        return Err(cf_error(error));
    }
    if key.is_null() {
        return Err(SecureEnclaveKeyError::new(
            None,
            "SecKeyCreateRandomKey returned null without CFError",
        ));
    }
    Ok(key)
}

fn create_access_control() -> Result<CfOwned<ffi::__SecAccessControl>, SecureEnclaveKeyError> {
    let mut error = ptr::null_mut();
    let access_control = unsafe {
        ffi::SecAccessControlCreateWithFlags(
            ffi::kCFAllocatorDefault,
            ffi::kSecAttrAccessibleWhenUnlockedThisDeviceOnly.cast(),
            ffi::kSecAccessControlPrivateKeyUsage as _,
            &mut error,
        )
    };
    if !error.is_null() {
        return Err(cf_error(error));
    }
    if access_control.is_null() {
        return Err(SecureEnclaveKeyError::new(
            None,
            "SecAccessControlCreateWithFlags returned null without CFError",
        ));
    }
    Ok(unsafe { CfOwned::from_create_rule(access_control) })
}

fn copy_public_key(
    private_key: ffi::SecKeyRef,
) -> Result<CfOwned<ffi::__SecKey>, SecureEnclaveKeyError> {
    let public_key = unsafe { ffi::SecKeyCopyPublicKey(private_key) };
    if public_key.is_null() {
        return Err(SecureEnclaveKeyError::new(
            None,
            "SecKeyCopyPublicKey returned null",
        ));
    }
    Ok(unsafe { CfOwned::from_create_rule(public_key) })
}

fn create_encrypted_data(
    key: ffi::SecKeyRef,
    algorithm: ffi::SecKeyAlgorithm,
    data: ffi::CFDataRef,
) -> Result<CfOwned<ffi::__CFData>, SecureEnclaveKeyError> {
    let mut error = ptr::null_mut();
    let output = unsafe { ffi::SecKeyCreateEncryptedData(key, algorithm, data, &mut error) };
    if !error.is_null() {
        return Err(cf_error(error));
    }
    if output.is_null() {
        return Err(SecureEnclaveKeyError::new(
            None,
            "SecKeyCreateEncryptedData returned null without CFError",
        ));
    }
    Ok(unsafe { CfOwned::from_create_rule(output) })
}

fn create_decrypted_data(
    key: ffi::SecKeyRef,
    algorithm: ffi::SecKeyAlgorithm,
    data: ffi::CFDataRef,
) -> Result<CfOwned<ffi::__CFData>, SecureEnclaveKeyError> {
    let mut error = ptr::null_mut();
    let output = unsafe { ffi::SecKeyCreateDecryptedData(key, algorithm, data, &mut error) };
    if !error.is_null() {
        return Err(cf_error(error));
    }
    if output.is_null() {
        return Err(SecureEnclaveKeyError::new(
            None,
            "SecKeyCreateDecryptedData returned null without CFError",
        ));
    }
    Ok(unsafe { CfOwned::from_create_rule(output) })
}

fn cf_error(error: ffi::CFErrorRef) -> SecureEnclaveKeyError {
    let description = unsafe { ffi::CFErrorCopyDescription(error) };
    let message = if description.is_null() {
        ArcStr::from("Security framework operation failed")
    } else {
        let description = unsafe { CfOwned::from_create_rule(description) };
        match cf_string_to_string(description.as_ptr()) {
            Ok(value) => ArcStr::from(value),
            Err(_) => ArcStr::from("Security framework operation failed"),
        }
    };
    let code = Some(unsafe { ffi::CFErrorGetCode(error) as i64 });
    cf_release(error.cast());
    SecureEnclaveKeyError::new(code, message)
}

fn cf_string_to_string(value: ffi::CFStringRef) -> Result<String, SecureEnclaveKeyError> {
    let max_len = unsafe {
        ffi::CFStringGetMaximumSizeForEncoding(
            ffi::CFStringGetLength(value),
            ffi::kCFStringEncodingUTF8,
        )
    };
    if max_len < 0 {
        return Err(SecureEnclaveKeyError::new(
            None,
            "CFStringGetMaximumSizeForEncoding returned a negative length",
        ));
    }
    let mut buffer = vec![0_u8; max_len as usize + 1];
    let ok = unsafe {
        ffi::CFStringGetCString(
            value,
            buffer.as_mut_ptr().cast::<c_char>(),
            buffer.len() as i64,
            ffi::kCFStringEncodingUTF8,
        )
    };
    if ok == 0 {
        return Err(SecureEnclaveKeyError::new(
            None,
            "CFStringGetCString failed",
        ));
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec()).map_err(|_| {
        SecureEnclaveKeyError::new(None, "Security framework string was not valid UTF-8")
    })
}

fn cf_release(value: *const std::ffi::c_void) {
    if !value.is_null() {
        unsafe { ffi::CFRelease(value) };
    }
}

struct QueryDictionary {
    raw: ffi::CFMutableDictionaryRef,
    owned: Vec<Box<dyn CfOwnedValue>>,
}

impl QueryDictionary {
    fn new() -> Self {
        let raw = unsafe {
            ffi::CFDictionaryCreateMutable(
                ffi::kCFAllocatorDefault,
                0,
                &ffi::kCFTypeDictionaryKeyCallBacks,
                &ffi::kCFTypeDictionaryValueCallBacks,
            )
        };
        Self {
            raw,
            owned: Vec::new(),
        }
    }

    fn set_ptr(&mut self, key: *const std::ffi::c_void, value: *const std::ffi::c_void) {
        unsafe { ffi::CFDictionarySetValue(self.raw, key, value) };
    }

    fn set_owned<T>(&mut self, key: *const std::ffi::c_void, value: T)
    where
        T: CfOwnedValue + 'static,
    {
        let value_ptr = value.as_void_ptr();
        unsafe { ffi::CFDictionarySetValue(self.raw, key, value_ptr) };
        self.owned.push(Box::new(value));
    }

    fn as_ptr(&self) -> ffi::CFDictionaryRef {
        self.raw
    }
}

impl Drop for QueryDictionary {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

trait CfOwnedValue {
    fn as_void_ptr(&self) -> *const std::ffi::c_void;
}

struct CfOwned<T> {
    raw: *mut T,
}

impl<T> CfOwned<T> {
    unsafe fn from_create_rule(raw: *const T) -> Self {
        Self {
            raw: raw.cast_mut(),
        }
    }

    fn as_ptr(&self) -> *mut T {
        self.raw
    }
}

impl CfOwned<ffi::__CFData> {
    fn to_vec(&self) -> Vec<u8> {
        let len = unsafe { ffi::CFDataGetLength(self.raw) as usize };
        let ptr = unsafe { ffi::CFDataGetBytePtr(self.raw) };
        if ptr.is_null() || len == 0 {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    }
}

impl<T> Drop for CfOwned<T> {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

impl<T> CfOwnedValue for CfOwned<T> {
    fn as_void_ptr(&self) -> *const std::ffi::c_void {
        self.raw.cast()
    }
}

struct CfString {
    raw: ffi::CFStringRef,
}

impl CfString {
    fn new(value: &str) -> Result<Self, SecureEnclaveKeyError> {
        let value = CString::new(value).map_err(|_| {
            SecureEnclaveKeyError::new(None, "string input contained an interior NUL byte")
        })?;
        let raw = unsafe {
            ffi::CFStringCreateWithCString(
                ffi::kCFAllocatorDefault,
                value.as_ptr(),
                ffi::kCFStringEncodingUTF8,
            )
        };
        if raw.is_null() {
            return Err(SecureEnclaveKeyError::new(
                None,
                "CFStringCreateWithCString returned null",
            ));
        }
        Ok(Self { raw })
    }
}

impl Drop for CfString {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

impl CfOwnedValue for CfString {
    fn as_void_ptr(&self) -> *const std::ffi::c_void {
        self.raw.cast()
    }
}

struct CfData {
    raw: ffi::CFDataRef,
}

impl CfData {
    fn new(value: &[u8]) -> Self {
        let raw = unsafe {
            ffi::CFDataCreate(ffi::kCFAllocatorDefault, value.as_ptr(), value.len() as i64)
        };
        Self { raw }
    }

    fn as_ptr(&self) -> ffi::CFDataRef {
        self.raw
    }
}

impl Drop for CfData {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

impl CfOwnedValue for CfData {
    fn as_void_ptr(&self) -> *const std::ffi::c_void {
        self.raw.cast()
    }
}

struct CfNumber {
    raw: ffi::CFNumberRef,
}

impl CfNumber {
    fn sint32(value: i32) -> Self {
        let raw = unsafe {
            ffi::CFNumberCreate(
                ffi::kCFAllocatorDefault,
                ffi::kCFNumberSInt32Type as i64,
                (&value as *const i32).cast(),
            )
        };
        Self { raw }
    }
}

impl Drop for CfNumber {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

impl CfOwnedValue for CfNumber {
    fn as_void_ptr(&self) -> *const std::ffi::c_void {
        self.raw.cast()
    }
}
