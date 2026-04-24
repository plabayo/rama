use std::fmt;

use rama_utils::str::arcstr::ArcStr;

use crate::security_ffi as secffi;

mod ffi;

use self::ffi::{CfData, CfNumber, CfOwned, CfString, QueryDictionary, cf_error, cf_release};

#[derive(Clone)]
pub struct SecureEnclaveKey {
    private_key: secffi::SecKeyRef,
    application_tag: Vec<u8>,
    access_group: Option<ArcStr>,
}

unsafe impl Send for SecureEnclaveKey {}
unsafe impl Sync for SecureEnclaveKey {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureEnclaveKeyLoadStatus {
    Loaded,
    Created,
}

impl SecureEnclaveKey {
    pub fn load_or_create(
        application_tag: &[u8],
        access_group: Option<impl Into<ArcStr>>,
    ) -> Result<Self, SecureEnclaveKeyError> {
        let (key, _) = Self::load_or_create_with_status(application_tag, access_group)?;
        Ok(key)
    }

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

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecureEnclaveKeyError> {
        let public_key = copy_public_key(self.private_key)?;
        let plaintext = CfData::new(plaintext);
        let encrypted = create_encrypted_data(
            public_key.as_ptr(),
            unsafe { secffi::kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM },
            plaintext.as_ptr(),
        )?;
        Ok(encrypted.to_vec())
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecureEnclaveKeyError> {
        let ciphertext = CfData::new(ciphertext);
        let decrypted = create_decrypted_data(
            self.private_key,
            unsafe { secffi::kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM },
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
) -> Result<Option<secffi::SecKeyRef>, SecureEnclaveKeyError> {
    let mut query = QueryDictionary::new();
    query.set_ptr(unsafe { secffi::kSecClass.cast() }, unsafe {
        secffi::kSecClassKey.cast()
    });
    query.set_ptr(unsafe { secffi::kSecAttrKeyClass.cast() }, unsafe {
        secffi::kSecAttrKeyClassPrivate.cast()
    });
    query.set_ptr(unsafe { secffi::kSecReturnRef.cast() }, unsafe {
        secffi::kCFBooleanTrue.cast()
    });
    query.set_ptr(
        unsafe { secffi::kSecUseDataProtectionKeychain.cast() },
        unsafe { secffi::kCFBooleanTrue.cast() },
    );
    query.set_owned(
        unsafe { secffi::kSecAttrApplicationTag.cast() },
        CfData::new(application_tag),
    );
    if let Some(access_group) = access_group {
        query.set_owned(
            unsafe { secffi::kSecAttrAccessGroup.cast() },
            CfString::new(access_group)?,
        );
    }

    let mut result = std::ptr::null();
    let status = unsafe { secffi::SecItemCopyMatching(query.as_ptr(), &mut result) };
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
) -> Result<secffi::SecKeyRef, SecureEnclaveKeyError> {
    let access_control = create_access_control()?;

    let mut private_attrs = QueryDictionary::new();
    private_attrs.set_ptr(unsafe { secffi::kSecAttrIsPermanent.cast() }, unsafe {
        secffi::kCFBooleanTrue.cast()
    });
    private_attrs.set_owned(
        unsafe { secffi::kSecAttrApplicationTag.cast() },
        CfData::new(application_tag),
    );
    private_attrs.set_ptr(
        unsafe { secffi::kSecAttrAccessControl.cast() },
        access_control.as_ptr().cast(),
    );

    let mut attrs = QueryDictionary::new();
    attrs.set_ptr(unsafe { secffi::kSecAttrKeyType.cast() }, unsafe {
        secffi::kSecAttrKeyTypeECSECPrimeRandom.cast()
    });
    attrs.set_owned(
        unsafe { secffi::kSecAttrKeySizeInBits.cast() },
        CfNumber::sint32(256),
    );
    attrs.set_ptr(unsafe { secffi::kSecAttrTokenID.cast() }, unsafe {
        secffi::kSecAttrTokenIDSecureEnclave.cast()
    });
    attrs.set_ptr(
        unsafe { secffi::kSecUseDataProtectionKeychain.cast() },
        unsafe { secffi::kCFBooleanTrue.cast() },
    );
    attrs.set_ptr(
        unsafe { secffi::kSecPrivateKeyAttrs.cast() },
        private_attrs.as_ptr().cast(),
    );
    if let Some(access_group) = access_group {
        attrs.set_owned(
            unsafe { secffi::kSecAttrAccessGroup.cast() },
            CfString::new(access_group)?,
        );
    }

    let mut error = std::ptr::null_mut();
    let key = unsafe { secffi::SecKeyCreateRandomKey(attrs.as_ptr(), &mut error) };
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

fn create_access_control() -> Result<CfOwned<secffi::__SecAccessControl>, SecureEnclaveKeyError> {
    let mut error = std::ptr::null_mut();
    let access_control = unsafe {
        secffi::SecAccessControlCreateWithFlags(
            secffi::kCFAllocatorDefault,
            secffi::kSecAttrAccessibleWhenUnlockedThisDeviceOnly.cast(),
            secffi::kSecAccessControlPrivateKeyUsage as _,
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
    private_key: secffi::SecKeyRef,
) -> Result<CfOwned<secffi::__SecKey>, SecureEnclaveKeyError> {
    let public_key = unsafe { secffi::SecKeyCopyPublicKey(private_key) };
    if public_key.is_null() {
        return Err(SecureEnclaveKeyError::new(
            None,
            "SecKeyCopyPublicKey returned null",
        ));
    }
    Ok(unsafe { CfOwned::from_create_rule(public_key) })
}

fn create_encrypted_data(
    key: secffi::SecKeyRef,
    algorithm: secffi::SecKeyAlgorithm,
    data: secffi::CFDataRef,
) -> Result<CfOwned<secffi::__CFData>, SecureEnclaveKeyError> {
    let mut error = std::ptr::null_mut();
    let output = unsafe { secffi::SecKeyCreateEncryptedData(key, algorithm, data, &mut error) };
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
    key: secffi::SecKeyRef,
    algorithm: secffi::SecKeyAlgorithm,
    data: secffi::CFDataRef,
) -> Result<CfOwned<secffi::__CFData>, SecureEnclaveKeyError> {
    let mut error = std::ptr::null_mut();
    let output = unsafe { secffi::SecKeyCreateDecryptedData(key, algorithm, data, &mut error) };
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
