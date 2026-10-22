//! Verification through CryptoAPI's certificate chain engine.

use std::{
    ffi::c_void,
    mem,
    ptr::{self, NonNull},
    slice,
    time::{SystemTime, UNIX_EPOCH},
};

use rama_core::error::BoxError;
use windows_sys::Win32::{
    Foundation::{
        CERT_E_CN_NO_MATCH, CERT_E_EXPIRED, CERT_E_INVALID_NAME, CERT_E_UNTRUSTEDROOT,
        CERT_E_WRONG_USAGE, CRYPT_E_REVOKED, FILETIME, TRUE,
    },
    Security::Cryptography::{
        AUTHTYPE_SERVER, CERT_CHAIN_CACHE_END_CERT, CERT_CHAIN_CONTEXT,
        CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS, CERT_CHAIN_POLICY_PARA,
        CERT_CHAIN_POLICY_SSL, CERT_CHAIN_POLICY_STATUS,
        CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT, CERT_CHAIN_REVOCATION_CHECK_END_CERT,
        CERT_CONTEXT, CERT_OCSP_RESPONSE_PROP_ID, CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG,
        CERT_STORE_ADD_ALWAYS, CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, CERT_STORE_PROV_MEMORY,
        CERT_STRONG_SIGN_PARA, CERT_TRUST_IS_PARTIAL_CHAIN, CERT_TRUST_IS_UNTRUSTED_ROOT,
        CERT_USAGE_MATCH, CRYPT_INTEGER_BLOB, CTL_USAGE, CertAddEncodedCertificateToStore,
        CertCloseStore, CertCreateCertificateChainEngine, CertFreeCertificateChain,
        CertFreeCertificateChainEngine, CertFreeCertificateContext, CertGetCertificateChain,
        CertOpenStore, CertSetCertificateContextProperty, CertVerifyCertificateChainPolicy,
        HCERTCHAINENGINE, HCERTSTORE, HTTPSPolicyCallbackData, USAGE_MATCH_TYPE_AND,
        X509_ASN_ENCODING, szOID_PKIX_KP_SERVER_AUTH,
    },
};

use super::{PlatformVerifyError, PlatformVerifyErrorKind};
use crate::pki_types::CertificateDer;

/// Extended key usages of which the leaf must carry at least one.
const ALLOWED_EKUS: &[windows_sys::core::PCSTR] = &[szOID_PKIX_KP_SERVER_AUTH];

/// Seconds between 1601-01-01 (the `FILETIME` epoch) and the Unix epoch.
const FILETIME_UNIX_OFFSET_SECS: u64 = 11_644_473_600;

// `windows-sys` declares the Windows 8+ layout of `CERT_CHAIN_PARA`. The
// engine reads `cbSize`, so the declaration below also covers older releases.
#[expect(non_snake_case, reason = "mirrors the CryptoAPI declaration")]
#[repr(C)]
struct CERT_CHAIN_PARA {
    cbSize: u32,
    RequestedUsage: CERT_USAGE_MATCH,
    RequestedIssuancePolicy: CERT_USAGE_MATCH,
    dwUrlRetrievalTimeout: u32,
    fCheckRevocationFreshnessTime: i32,
    dwRevocationFreshnessTime: u32,
    pftCacheResync: *mut FILETIME,
    pStrongSignPara: *const CERT_STRONG_SIGN_PARA,
    dwStrongSignFlags: u32,
}

// Same compatibility concern as `CERT_CHAIN_PARA`.
#[expect(non_snake_case, reason = "mirrors the CryptoAPI declaration")]
#[repr(C)]
struct CERT_CHAIN_ENGINE_CONFIG {
    cbSize: u32,
    hRestrictedRoot: HCERTSTORE,
    hRestrictedTrust: HCERTSTORE,
    hRestrictedOther: HCERTSTORE,
    cAdditionalStore: u32,
    rghAdditionalStore: *mut HCERTSTORE,
    dwFlags: u32,
    dwUrlRetrievalTimeout: u32,
    MaximumCachedCertificates: u32,
    CycleDetectionModulus: u32,
    hExclusiveRoot: HCERTSTORE,
    hExclusiveTrustedPeople: HCERTSTORE,
    dwExclusiveFlags: u32,
}

/// A structure that is valid when zeroed, apart from its `cbSize` field.
///
/// # Safety
///
/// Same requirements as [`mem::zeroed`].
unsafe trait ZeroedWithSize: Sized {
    const SIZE: u32 = {
        let size = mem::size_of::<Self>();
        assert!(
            size <= u32::MAX as usize,
            "structure is larger than a DWORD"
        );
        size as u32
    };

    fn zeroed_with_size() -> Self;
}

// SAFETY: only integers and pointers; MSDN requires unused fields to be zero.
unsafe impl ZeroedWithSize for CERT_CHAIN_PARA {
    fn zeroed_with_size() -> Self {
        // SAFETY: see the impl.
        let mut value: Self = unsafe { mem::zeroed() };
        value.cbSize = Self::SIZE;
        value
    }
}

// SAFETY: integers, pointers and a union of integers.
unsafe impl ZeroedWithSize for HTTPSPolicyCallbackData {
    fn zeroed_with_size() -> Self {
        // SAFETY: see the impl.
        let mut value: Self = unsafe { mem::zeroed() };
        value.Anonymous.cbSize = Self::SIZE;
        value
    }
}

// SAFETY: only integers and pointers.
unsafe impl ZeroedWithSize for CERT_CHAIN_POLICY_PARA {
    fn zeroed_with_size() -> Self {
        // SAFETY: see the impl.
        let mut value: Self = unsafe { mem::zeroed() };
        value.cbSize = Self::SIZE;
        value
    }
}

// SAFETY: only integers and a pointer, which stays null.
unsafe impl ZeroedWithSize for CERT_CHAIN_POLICY_STATUS {
    fn zeroed_with_size() -> Self {
        // SAFETY: see the impl.
        let mut value: Self = unsafe { mem::zeroed() };
        value.cbSize = Self::SIZE;
        value
    }
}

// SAFETY: only integers and pointers.
unsafe impl ZeroedWithSize for CERT_CHAIN_ENGINE_CONFIG {
    fn zeroed_with_size() -> Self {
        // SAFETY: see the impl.
        let mut value: Self = unsafe { mem::zeroed() };
        value.cbSize = Self::SIZE;
        value
    }
}

fn last_os_error(kind: PlatformVerifyErrorKind) -> PlatformVerifyError {
    PlatformVerifyError::with_source(kind, std::io::Error::last_os_error())
}

struct CertChain(NonNull<CERT_CHAIN_CONTEXT>);

impl CertChain {
    fn trust_error_status(&self) -> u32 {
        // SAFETY: the chain context is valid for the lifetime of `self`.
        unsafe { self.0.as_ref() }.TrustStatus.dwErrorStatus
    }

    fn verify_ssl_policy(
        &self,
        server_name: &str,
    ) -> Result<CERT_CHAIN_POLICY_STATUS, PlatformVerifyError> {
        let mut server_name: Vec<u16> = server_name.encode_utf16().chain(Some(0)).collect();

        let mut extra = HTTPSPolicyCallbackData::zeroed_with_size();
        extra.dwAuthType = AUTHTYPE_SERVER;
        extra.pwszServerName = server_name.as_mut_ptr();

        let mut params = CERT_CHAIN_POLICY_PARA::zeroed_with_size();
        // Missing revocation information is not an error, as with other
        // platform verifiers.
        params.dwFlags = CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS;
        params.pvExtraPolicyPara = NonNull::from(&mut extra).cast::<c_void>().as_ptr();

        // An input/output structure: the caller sets its size.
        let mut status = CERT_CHAIN_POLICY_STATUS::zeroed_with_size();
        // SAFETY: the chain is valid, `params` and `extra` (and the name it
        // points to) outlive the call, and `status` is valid for writes.
        let res = unsafe {
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_SSL,
                self.0.as_ptr(),
                &params,
                &mut status,
            )
        };
        if res != TRUE {
            return Err(PlatformVerifyError::new(
                PlatformVerifyErrorKind::Unavailable,
            ));
        }
        Ok(status)
    }

    /// The built path of the first simple chain, leaf first.
    fn certificates(&self) -> Vec<CertificateDer<'static>> {
        // SAFETY: the chain context stays valid for the lifetime of `self`.
        let context = unsafe { self.0.as_ref() };
        if context.cChain == 0 || context.rgpChain.is_null() {
            return Vec::new();
        }
        // SAFETY: `rgpChain` holds `cChain` (> 0) simple chain pointers.
        let first = unsafe { *context.rgpChain };
        // SAFETY: simple chain pointers are null or valid for the chain's lifetime.
        let Some(simple) = (unsafe { first.as_ref() }) else {
            return Vec::new();
        };
        if simple.rgpElement.is_null() {
            return Vec::new();
        }
        // SAFETY: `rgpElement` holds `cElement` element pointers.
        let elements =
            unsafe { slice::from_raw_parts(simple.rgpElement, simple.cElement as usize) };
        elements
            .iter()
            // SAFETY: element pointers are null or valid for the chain's lifetime.
            .filter_map(|element| unsafe { element.as_ref() })
            // SAFETY: certificate contexts are null or valid for the chain's lifetime.
            .filter_map(|element| unsafe { element.pCertContext.as_ref() })
            .filter(|certificate| !certificate.pbCertEncoded.is_null())
            .map(|certificate| {
                // SAFETY: `pbCertEncoded` holds `cbCertEncoded` bytes.
                let der = unsafe {
                    slice::from_raw_parts(
                        certificate.pbCertEncoded,
                        certificate.cbCertEncoded as usize,
                    )
                };
                CertificateDer::from(der.to_vec())
            })
            .collect()
    }
}

impl Drop for CertChain {
    fn drop(&mut self) {
        // SAFETY: the chain is owned by `self`.
        unsafe { CertFreeCertificateChain(self.0.as_ptr()) }
    }
}

/// A certificate context inside a [`CertificateStore`].
struct Certificate(NonNull<CERT_CONTEXT>);

impl Certificate {
    fn set_ocsp_response(&mut self, response: &[u8]) -> Result<(), PlatformVerifyError> {
        let blob = CRYPT_INTEGER_BLOB {
            cbData: response.len().try_into().map_err(|err| {
                PlatformVerifyError::with_source(PlatformVerifyErrorKind::BadEncoding, err)
            })?,
            pbData: response.as_ptr().cast_mut(),
        };
        // SAFETY: the context is valid and the blob matches the property type;
        // CryptoAPI copies the data.
        let res = unsafe {
            CertSetCertificateContextProperty(
                self.0.as_ptr(),
                CERT_OCSP_RESPONSE_PROP_ID,
                CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG,
                NonNull::from(&blob).cast::<c_void>().as_ptr(),
            )
        };
        if res == TRUE {
            Ok(())
        } else {
            Err(last_os_error(PlatformVerifyErrorKind::Other))
        }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: the context is owned by `self`.
        unsafe { CertFreeCertificateContext(self.0.as_ptr()) };
    }
}

/// An in-memory certificate store.
///
/// Opened with `CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG`, so certificate
/// contexts created from it may outlive it.
struct CertificateStore(NonNull<c_void>);

impl CertificateStore {
    fn new() -> Result<Self, PlatformVerifyError> {
        // SAFETY: constant arguments; the result is checked for null.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                0,
                0,
                CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
                ptr::null(),
            )
        };
        NonNull::new(store)
            .map(Self)
            .ok_or_else(|| last_os_error(PlatformVerifyErrorKind::Other))
    }

    fn add_cert(&mut self, der: &[u8]) -> Result<Certificate, PlatformVerifyError> {
        let mut context: *mut CERT_CONTEXT = ptr::null_mut();
        let len = der.len().try_into().map_err(|err| {
            PlatformVerifyError::with_source(PlatformVerifyErrorKind::BadEncoding, err)
        })?;
        // SAFETY: the store is valid, `der` is readable for `len` bytes and
        // `context` is valid for writes.
        let res = unsafe {
            CertAddEncodedCertificateToStore(
                self.0.as_ptr(),
                X509_ASN_ENCODING,
                der.as_ptr(),
                len,
                CERT_STORE_ADD_ALWAYS,
                &mut context,
            )
        };
        match (res, NonNull::new(context)) {
            (TRUE, Some(context)) => Ok(Certificate(context)),
            _ => Err(PlatformVerifyError::new(
                PlatformVerifyErrorKind::BadEncoding,
            )),
        }
    }

    fn build_chain(
        &self,
        leaf: &Certificate,
        now: SystemTime,
        engine: Option<&CertEngine>,
    ) -> Result<CertChain, PlatformVerifyError> {
        let mut parameters = CERT_CHAIN_PARA::zeroed_with_size();
        parameters.RequestedUsage = CERT_USAGE_MATCH {
            dwType: USAGE_MATCH_TYPE_AND,
            Usage: CTL_USAGE {
                cUsageIdentifier: ALLOWED_EKUS.len() as u32,
                rgpszUsageIdentifier: ALLOWED_EKUS.as_ptr().cast_mut().cast(),
            },
        };
        // Below the 15s default: fetches are for revocation and intermediates.
        parameters.dwUrlRetrievalTimeout = 10_000;

        // Revocation is checked for the leaf only, network time is bounded
        // across all fetches, and repeated connections reuse the cached leaf.
        const FLAGS: u32 = CERT_CHAIN_REVOCATION_CHECK_END_CERT
            | CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT
            | CERT_CHAIN_CACHE_END_CERT;

        let time = filetime(now)?;
        let mut chain = ptr::null_mut();
        // SAFETY: all pointers are valid for the duration of the call; the
        // engine reads `cbSize` to interpret the parameter layout.
        let res = unsafe {
            CertGetCertificateChain(
                engine.map_or(ptr::null_mut(), |engine| engine.0.as_ptr()),
                leaf.0.as_ptr(),
                &time,
                self.0.as_ptr(),
                NonNull::from(&parameters).cast().as_ptr(),
                FLAGS,
                ptr::null_mut(),
                &mut chain,
            )
        };
        match NonNull::new(chain) {
            Some(chain) if res == TRUE => Ok(CertChain(chain)),
            _ => Err(last_os_error(PlatformVerifyErrorKind::Other)),
        }
    }
}

impl Drop for CertificateStore {
    fn drop(&mut self) {
        // SAFETY: the store is owned by `self`.
        unsafe { CertCloseStore(self.0.as_ptr(), 0) };
    }
}

/// A chain engine that trusts additional roots.
struct CertEngine(NonNull<c_void>);

impl CertEngine {
    fn try_with_extra_roots(roots: &[CertificateDer<'static>]) -> Result<Self, BoxError> {
        let mut roots_store = CertificateStore::new()?;
        for root in roots {
            roots_store.add_cert(root)?;
        }

        let mut config = CERT_CHAIN_ENGINE_CONFIG::zeroed_with_size();
        config.hExclusiveRoot = roots_store.0.as_ptr();

        let mut engine: HCERTCHAINENGINE = ptr::null_mut();
        // SAFETY: `config` is valid for reads (the engine reads `cbSize`) and
        // `engine` is valid for writes. The engine references the root store,
        // which CryptoAPI keeps alive.
        let res = unsafe {
            CertCreateCertificateChainEngine(NonNull::from(&config).cast().as_ptr(), &mut engine)
        };
        match NonNull::new(engine) {
            Some(engine) if res == TRUE => Ok(Self(engine)),
            _ => Err(last_os_error(PlatformVerifyErrorKind::Other).into()),
        }
    }
}

impl Drop for CertEngine {
    fn drop(&mut self) {
        // SAFETY: the engine is owned by `self`.
        unsafe { CertFreeCertificateChainEngine(self.0.as_ptr()) };
    }
}

// SAFETY: CryptoAPI engines are reference counted, not mutated by
// `CertGetCertificateChain`, and may be used and freed from any thread.
unsafe impl Send for CertEngine {}
// SAFETY: see `Send`.
unsafe impl Sync for CertEngine {}

pub(super) struct Verifier {
    extra_roots: Option<CertEngine>,
}

impl Verifier {
    pub(super) fn new() -> Self {
        Self { extra_roots: None }
    }

    pub(super) fn try_with_extra_roots(
        roots: &[CertificateDer<'static>],
    ) -> Result<Self, BoxError> {
        Ok(Self {
            extra_roots: Some(CertEngine::try_with_extra_roots(roots)?),
        })
    }

    pub(super) fn verify_server_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &str,
        ocsp_response: Option<&[u8]>,
        now: SystemTime,
    ) -> Result<Vec<CertificateDer<'static>>, PlatformVerifyError> {
        let mut store = CertificateStore::new()?;
        let mut leaf = store.add_cert(end_entity)?;
        for intermediate in intermediates {
            store.add_cert(intermediate)?;
        }
        if let Some(response) = ocsp_response {
            leaf.set_ocsp_response(response)?;
        }

        let mut chain = store.build_chain(&leaf, now, None)?;
        // The system roots come first; additional roots only rescue a chain
        // the system could not complete.
        if let Some(engine) = &self.extra_roots
            && chain.trust_error_status()
                & (CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_UNTRUSTED_ROOT)
                != 0
        {
            chain = store.build_chain(&leaf, now, Some(engine))?;
        }

        let status = chain.verify_ssl_policy(server_name)?;
        if status.dwError == 0 {
            return Ok(chain.certificates());
        }

        let kind = match status.dwError as i32 {
            CERT_E_CN_NO_MATCH | CERT_E_INVALID_NAME => PlatformVerifyErrorKind::NotValidForName,
            CRYPT_E_REVOKED => PlatformVerifyErrorKind::Revoked,
            CERT_E_EXPIRED => PlatformVerifyErrorKind::Expired,
            CERT_E_UNTRUSTEDROOT => PlatformVerifyErrorKind::UnknownIssuer,
            CERT_E_WRONG_USAGE => PlatformVerifyErrorKind::InvalidPurpose,
            _ => PlatformVerifyErrorKind::Other,
        };
        Err(PlatformVerifyError::with_source(
            kind,
            std::io::Error::from_raw_os_error(status.dwError as i32),
        ))
    }
}

fn filetime(now: SystemTime) -> Result<FILETIME, PlatformVerifyError> {
    let since_unix = now
        .duration_since(UNIX_EPOCH)
        .map_err(|err| PlatformVerifyError::with_source(PlatformVerifyErrorKind::Other, err))?;
    // `FILETIME` counts 100ns intervals.
    let intervals = (since_unix.as_secs() + FILETIME_UNIX_OFFSET_SECS) * 10_000_000
        + u64::from(since_unix.subsec_nanos() / 100);
    Ok(FILETIME {
        dwLowDateTime: intervals as u32,
        dwHighDateTime: (intervals >> 32) as u32,
    })
}
