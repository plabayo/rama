//! Secure Enclave-backed key handling for Apple Network Extensions.
//!
//! This module exposes a small Rust-native wrapper around a permanent
//! Secure Enclave private key stored through Apple Security / Keychain
//! Services APIs. The key can be scoped to an optional access group and is
//! intended for local cryptographic operations such as encrypting data that is
//! later stored elsewhere.

use std::fmt;

use rama_utils::str::arcstr::ArcStr;

use crate::ffi::core_foundation::{
    CfData, CfNumber, CfOwned, CfString, QueryDictionary, cf_error, cf_release,
};
use crate::ffi::sys;

#[derive(Clone)]
pub struct SecureEnclaveKey {
    private_key: sys::SecKeyRef,
    application_tag: Vec<u8>,
    access_group: Option<ArcStr>,
}

unsafe impl Send for SecureEnclaveKey {}
unsafe impl Sync for SecureEnclaveKey {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureEnclaveKeyLoadStatus {
    /// An existing Secure Enclave key was found and opened.
    Loaded,
    /// No matching key existed, so a new one was created.
    Created,
}

impl SecureEnclaveKey {
    /// Load an existing Secure Enclave key by application tag or create it if it
    /// does not exist yet.
    pub fn load_or_create(
        application_tag: &[u8],
        access_group: Option<impl Into<ArcStr>>,
    ) -> Result<Self, SecureEnclaveKeyError> {
        let (key, _) = Self::load_or_create_with_status(application_tag, access_group)?;
        Ok(key)
    }

    /// Same as [`Self::load_or_create`], but also returns whether the key was
    /// opened from storage or freshly created.
    pub fn load_or_create_with_status(
        application_tag: &[u8],
        access_group: Option<impl Into<ArcStr>>,
    ) -> Result<(Self, SecureEnclaveKeyLoadStatus), SecureEnclaveKeyError> {
        let access_group = access_group.map(Into::into);

        if let Some(private_key) = find_private_key(application_tag, access_group.as_deref())? {
            return Ok((
                Self {
                    private_key,
                    application_tag: application_tag.to_vec(),
                    access_group,
                },
                SecureEnclaveKeyLoadStatus::Loaded,
            ));
        }

        let private_key = create_private_key(application_tag, access_group.as_deref())?;

        Ok((
            Self {
                private_key,
                application_tag: application_tag.to_vec(),
                access_group,
            },
            SecureEnclaveKeyLoadStatus::Created,
        ))
    }

    /// Encrypt `plaintext` using the public key corresponding to this Secure
    /// Enclave private key.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecureEnclaveKeyError> {
        let public_key = copy_public_key(self.private_key)?;
        let plaintext = CfData::new(plaintext);
        // SAFETY: this is a constant algorithm identifier from Apple Security.
        let encrypted = create_encrypted_data(
            public_key.as_ptr(),
            unsafe { sys::kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM },
            plaintext.as_ptr(),
        )?;
        Ok(encrypted.to_vec())
    }

    /// Decrypt `ciphertext` using this Secure Enclave private key.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecureEnclaveKeyError> {
        let ciphertext = CfData::new(ciphertext);
        // SAFETY: this is a constant algorithm identifier from Apple Security.
        let decrypted = create_decrypted_data(
            self.private_key,
            unsafe { sys::kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM },
            ciphertext.as_ptr(),
        )?;
        Ok(decrypted.to_vec())
    }

    /// Return the application tag used to locate this key.
    pub fn application_tag(&self) -> &[u8] {
        &self.application_tag
    }

    /// Return the optional access group used when locating or creating this key.
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
    pub(crate) fn new(code: Option<i64>, message: impl Into<ArcStr>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Return the raw Apple Security/CoreFoundation error code when available.
    pub fn code(&self) -> Option<i64> {
        self.code
    }

    /// Return the human-readable error message.
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
) -> Result<Option<sys::SecKeyRef>, SecureEnclaveKeyError> {
    let mut query = QueryDictionary::new();
    // SAFETY: these are constant CFTypeRef keys/values provided by Apple Security.
    query.set_ptr(unsafe { sys::kSecClass.cast() }, unsafe {
        sys::kSecClassKey.cast()
    });
    // SAFETY: these are constant CFTypeRef keys/values provided by Apple Security.
    query.set_ptr(unsafe { sys::kSecAttrKeyClass.cast() }, unsafe {
        sys::kSecAttrKeyClassPrivate.cast()
    });
    // SAFETY: these are constant CFTypeRef keys/values provided by Apple Security.
    query.set_ptr(unsafe { sys::kSecReturnRef.cast() }, unsafe {
        sys::kCFBooleanTrue.cast()
    });
    // SAFETY: these are constant CFTypeRef keys/values provided by Apple Security.
    query.set_ptr(
        unsafe { sys::kSecUseDataProtectionKeychain.cast() },
        unsafe { sys::kCFBooleanTrue.cast() },
    );
    query.set_owned(
        unsafe { sys::kSecAttrApplicationTag.cast() },
        CfData::new(application_tag),
    );
    if let Some(access_group) = access_group {
        query.set_owned(
            unsafe { sys::kSecAttrAccessGroup.cast() },
            CfString::new(access_group)?,
        );
    }

    let mut result = std::ptr::null();
    // SAFETY: `query` is a valid CFDictionary for the duration of this call and
    // `result` points to writable storage for the returned object reference.
    let status = unsafe { sys::SecItemCopyMatching(query.as_ptr(), &mut result) };
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
) -> Result<sys::SecKeyRef, SecureEnclaveKeyError> {
    let access_control = create_access_control()?;

    let mut private_attrs = QueryDictionary::new();
    // SAFETY: these are constant CFTypeRef keys/values provided by Apple Security.
    private_attrs.set_ptr(unsafe { sys::kSecAttrIsPermanent.cast() }, unsafe {
        sys::kCFBooleanTrue.cast()
    });
    private_attrs.set_owned(
        unsafe { sys::kSecAttrApplicationTag.cast() },
        CfData::new(application_tag),
    );
    private_attrs.set_ptr(
        unsafe { sys::kSecAttrAccessControl.cast() },
        access_control.as_ptr().cast(),
    );

    let mut attrs = QueryDictionary::new();
    // SAFETY: these are constant CFTypeRef keys/values provided by Apple Security.
    attrs.set_ptr(unsafe { sys::kSecAttrKeyType.cast() }, unsafe {
        sys::kSecAttrKeyTypeECSECPrimeRandom.cast()
    });
    attrs.set_owned(
        unsafe { sys::kSecAttrKeySizeInBits.cast() },
        CfNumber::sint32(256),
    );
    // SAFETY: these are constant CFTypeRef keys/values provided by Apple Security.
    attrs.set_ptr(unsafe { sys::kSecAttrTokenID.cast() }, unsafe {
        sys::kSecAttrTokenIDSecureEnclave.cast()
    });
    // SAFETY: these are constant CFTypeRef keys/values provided by Apple Security.
    attrs.set_ptr(
        unsafe { sys::kSecUseDataProtectionKeychain.cast() },
        unsafe { sys::kCFBooleanTrue.cast() },
    );
    attrs.set_ptr(
        unsafe { sys::kSecPrivateKeyAttrs.cast() },
        private_attrs.as_ptr().cast(),
    );
    if let Some(access_group) = access_group {
        attrs.set_owned(
            unsafe { sys::kSecAttrAccessGroup.cast() },
            CfString::new(access_group)?,
        );
    }

    let mut error = std::ptr::null_mut();
    // SAFETY: `attrs` is a valid CFDictionary for the duration of this call and
    // `error` points to writable storage for an optional CFErrorRef.
    let key = unsafe { sys::SecKeyCreateRandomKey(attrs.as_ptr(), &mut error) };
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

fn create_access_control() -> Result<CfOwned<sys::__SecAccessControl>, SecureEnclaveKeyError> {
    let mut error = std::ptr::null_mut();
    // SAFETY: the accessibility class and flag are constant identifiers from
    // Apple Security, and `error` points to writable storage.
    let access_control = unsafe {
        sys::SecAccessControlCreateWithFlags(
            sys::kCFAllocatorDefault,
            sys::kSecAttrAccessibleWhenUnlockedThisDeviceOnly.cast(),
            sys::kSecAccessControlPrivateKeyUsage as _,
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
    private_key: sys::SecKeyRef,
) -> Result<CfOwned<sys::__SecKey>, SecureEnclaveKeyError> {
    // SAFETY: `private_key` is a valid SecKeyRef owned by `SecureEnclaveKey`.
    let public_key = unsafe { sys::SecKeyCopyPublicKey(private_key) };
    if public_key.is_null() {
        return Err(SecureEnclaveKeyError::new(
            None,
            "SecKeyCopyPublicKey returned null",
        ));
    }
    Ok(unsafe { CfOwned::from_create_rule(public_key) })
}

fn create_encrypted_data(
    key: sys::SecKeyRef,
    algorithm: sys::SecKeyAlgorithm,
    data: sys::CFDataRef,
) -> Result<CfOwned<sys::__CFData>, SecureEnclaveKeyError> {
    let mut error = std::ptr::null_mut();
    // SAFETY: `key` and `data` are valid Security/CoreFoundation references and
    // `error` points to writable storage.
    let output = unsafe { sys::SecKeyCreateEncryptedData(key, algorithm, data, &mut error) };
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
    key: sys::SecKeyRef,
    algorithm: sys::SecKeyAlgorithm,
    data: sys::CFDataRef,
) -> Result<CfOwned<sys::__CFData>, SecureEnclaveKeyError> {
    let mut error = std::ptr::null_mut();
    // SAFETY: `key` and `data` are valid Security/CoreFoundation references and
    // `error` points to writable storage.
    let output = unsafe { sys::SecKeyCreateDecryptedData(key, algorithm, data, &mut error) };
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
