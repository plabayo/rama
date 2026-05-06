//! Secure Enclave (SE) backed encryption for sysext use.
//!
//! The macOS Data Protection Keychain — and therefore the standard
//! `kSecAttrTokenIDSecureEnclave` keychain integration — is not available to
//! Network Extension System Extensions (see [TN3137]). [Apple CryptoKit][cryptokit]'s
//! `SecureEnclave.P256.KeyAgreement.PrivateKey` reaches the SE directly,
//! without going through the Data Protection Keychain, and so is the only way
//! a sysext can use SE-protected keys.
//!
//! This module wraps that path via a small Swift bridge
//! (`RamaAppleSecureEnclave`). The Rust side declares the bridge symbols as
//! `extern "C"`; the final binary must link the Swift bridge for these symbols
//! to resolve at link time. Within a Swift Package Manager / Xcode setup the
//! bridge is consumed as the `RamaAppleSecureEnclave` product.
//!
//! # Sysext accessibility
//!
//! The default [CryptoKit][cryptokit] accessibility is
//! `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, which makes the key
//! unusable before any user has logged in. A sysext daemon may run before that
//! point, so for sysext use pick [`SecureEnclaveAccessibility::Always`], which
//! maps to the (deprecated but still functional) `kSecAttrAccessibleAlways`.
//! Apple acknowledges this exact pattern in
//! <https://developer.apple.com/forums/thread/804612>.
//!
//! [cryptokit]: https://developer.apple.com/documentation/cryptokit
//!
//! # Encryption scheme
//!
//! SE keys can perform ECDH key agreement but not bulk encryption. We layer a
//! standard hybrid scheme on top:
//!
//! 1. Generate an ephemeral P-256 key pair.
//! 2. ECDH(ephemeral_priv, recipient_se_pub) → shared secret.
//! 3. HKDF-SHA256(shared, salt = ephemeral_pub || recipient_pub, info =
//!    `"rama-apple-se-p256-ecies-v1"`) → 32-byte key.
//! 4. AES-GCM seal with that key.
//!
//! Envelope layout (returned from [`SecureEnclaveKey::encrypt`]):
//!
//! ```text
//! | 1 byte version=1 | 65 byte ephemeral pubkey (X9.63) | 12 byte nonce | N byte ct | 16 byte tag |
//! ```
//!
//! [TN3137]: https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
//!
//! # Example
//!
//! ```no_run
//! use rama_net_apple_networkextension::system_keychain::{
//!     self, secure_enclave::{SecureEnclaveAccessibility, SecureEnclaveKey},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Mint and persist once.
//! let key = SecureEnclaveKey::create(SecureEnclaveAccessibility::Always)?;
//! system_keychain::store_secret("rama", "se-key-v1", key.data_representation())?;
//!
//! // Reload on next boot.
//! let blob = system_keychain::load_secret("rama", "se-key-v1")?
//!     .expect("key was stored at install time");
//! let key = SecureEnclaveKey::from_data_representation(blob);
//!
//! let envelope = key.encrypt(b"my secret")?;
//! let plaintext = key.decrypt(&envelope)?;
//! assert_eq!(plaintext, b"my secret");
//! # Ok(())
//! # }
//! ```
//!
//! # Linking
//!
//! The Rust crate alone cannot resolve the bridge symbols; it relies on the
//! consumer's final binary linking the Swift product. `cargo build` produces
//! an rlib and does not link, so this is fine for development; unused extern
//! references are dead-code-eliminated when building test binaries that do
//! not exercise this module. End-to-end testing should run from a Swift host
//! that links `RamaAppleSecureEnclave`.

use std::fmt;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RamaSeBytes {
    ptr: *mut u8,
    len: usize,
}

impl RamaSeBytes {
    const EMPTY: Self = Self {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
}

unsafe extern "C" {
    fn rama_apple_se_is_available() -> bool;

    fn rama_apple_se_p256_create(accessibility: i32, out_blob: *mut RamaSeBytes) -> i32;

    fn rama_apple_se_p256_encrypt(
        blob: *const u8,
        blob_len: usize,
        pt: *const u8,
        pt_len: usize,
        out_ct: *mut RamaSeBytes,
    ) -> i32;

    fn rama_apple_se_p256_decrypt(
        blob: *const u8,
        blob_len: usize,
        ct: *const u8,
        ct_len: usize,
        out_pt: *mut RamaSeBytes,
    ) -> i32;

    fn rama_apple_se_bytes_free(bytes: RamaSeBytes);
}

const RAMA_SE_OK: i32 = 0;
const RAMA_SE_ERR_UNAVAILABLE: i32 = -1;
const RAMA_SE_ERR_BAD_INPUT: i32 = -2;
const RAMA_SE_ERR_CRYPTO: i32 = -3;
const RAMA_SE_ERR_SYSTEM: i32 = -4;

/// Accessibility class applied to the SE key's access control.
///
/// Mirrors a subset of `kSecAttrAccessible*` constants. Pick
/// [`SecureEnclaveAccessibility::Always`] for sysext daemons that must work
/// before any user has logged in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureEnclaveAccessibility {
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. The CryptoKit
    /// default. Key is unusable before the first user login.
    AfterFirstUnlock,
    /// `kSecAttrAccessibleAlways`. The only accessibility class that lets a
    /// sysext use the SE before a user has logged in.
    Always,
}

impl SecureEnclaveAccessibility {
    fn as_raw(self) -> i32 {
        match self {
            Self::AfterFirstUnlock => 0,
            Self::Always => 1,
        }
    }
}

/// Errors surfaced by the SE bridge.
#[derive(Debug, Clone)]
pub enum SecureEnclaveError {
    /// This Mac does not have a usable Secure Enclave (e.g. Intel without T2).
    Unavailable,
    /// Caller passed empty/malformed input.
    BadInput,
    /// Cryptographic operation failed (decrypt tag mismatch, malformed envelope, etc.).
    Crypto,
    /// SE / Security framework returned an unexpected error. Check the system log.
    System,
    /// Unknown bridge return code.
    Unknown(i32),
}

impl SecureEnclaveError {
    fn from_code(code: i32) -> Self {
        match code {
            RAMA_SE_ERR_UNAVAILABLE => Self::Unavailable,
            RAMA_SE_ERR_BAD_INPUT => Self::BadInput,
            RAMA_SE_ERR_CRYPTO => Self::Crypto,
            RAMA_SE_ERR_SYSTEM => Self::System,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for SecureEnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("Secure Enclave unavailable on this Mac"),
            Self::BadInput => f.write_str("invalid input to Secure Enclave bridge"),
            Self::Crypto => f.write_str("Secure Enclave cryptographic operation failed"),
            Self::System => f.write_str("Secure Enclave system error (see system log)"),
            Self::Unknown(code) => write!(f, "unknown Secure Enclave bridge code {code}"),
        }
    }
}

impl std::error::Error for SecureEnclaveError {}

/// Returns `true` when this Mac has a usable Secure Enclave.
///
/// Useful for graceful fallback on Intel Macs without a T2 chip.
pub fn is_available() -> bool {
    // SAFETY: the bridge function takes no arguments and returns a primitive.
    unsafe { rama_apple_se_is_available() }
}

/// Handle to an SE-protected P-256 key.
///
/// Construction does not validate the blob — bad blobs surface as
/// [`SecureEnclaveError::BadInput`] from [`Self::encrypt`] / [`Self::decrypt`].
///
/// The opaque `dataRepresentation` blob is wrapped in
/// [`zeroize::Zeroizing`] so it's wiped from heap on drop. The blob is
/// SE-encrypted and would not directly expose the private key on its
/// own (the SE silicon retains the actual key material), but defence
/// in depth — a long-lived plaintext copy of an SE-encrypted blob in
/// process heap is unnecessary exposure when a panic / core-dump /
/// memory-disclosure bug would surface it.
#[derive(Debug, Clone)]
pub struct SecureEnclaveKey {
    blob: zeroize::Zeroizing<Vec<u8>>,
}

impl SecureEnclaveKey {
    /// Mint a new SE-protected P-256 key with the given accessibility class.
    ///
    /// The returned key holds the opaque `dataRepresentation` returned by
    /// CryptoKit. The actual private key bits never leave the SE silicon; the
    /// blob is encrypted to the SE and is the only way to reload the key.
    pub fn create(acc: SecureEnclaveAccessibility) -> Result<Self, SecureEnclaveError> {
        let mut out = RamaSeBytes::EMPTY;
        // SAFETY: `out` is a valid pointer to writable storage; the bridge writes
        // a fresh malloc'd buffer (taken below) or zeroes the struct on error.
        let code = unsafe { rama_apple_se_p256_create(acc.as_raw(), &mut out) };
        if code != RAMA_SE_OK {
            return Err(SecureEnclaveError::from_code(code));
        }
        Ok(Self {
            blob: zeroize::Zeroizing::new(take_bytes(out)),
        })
    }

    /// Wrap a previously persisted blob.
    ///
    /// The blob is the bytes returned by [`Self::data_representation`] (or by
    /// CryptoKit's `dataRepresentation`). No validation happens here.
    ///
    /// Accepts anything that derefs to a byte slice — both `Vec<u8>`
    /// and `zeroize::Zeroizing<Vec<u8>>` work, so callers reading
    /// from [`super::load_secret`] can pass the wrapped form directly.
    pub fn from_data_representation(blob: impl AsRef<[u8]>) -> Self {
        Self {
            blob: zeroize::Zeroizing::new(blob.as_ref().to_vec()),
        }
    }

    /// Borrow the opaque `dataRepresentation` so the caller can persist it.
    pub fn data_representation(&self) -> &[u8] {
        &self.blob
    }

    /// Encrypt arbitrary bytes; produces an envelope decryptable only by this
    /// SE on this Mac (see module docs for the layout).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecureEnclaveError> {
        let mut out = RamaSeBytes::EMPTY;
        // SAFETY: blob/plaintext pointers are valid for their stated lengths,
        // and `out` points to writable storage.
        let code = unsafe {
            rama_apple_se_p256_encrypt(
                self.blob.as_ptr(),
                self.blob.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                &mut out,
            )
        };
        if code != RAMA_SE_OK {
            return Err(SecureEnclaveError::from_code(code));
        }
        Ok(take_bytes(out))
    }

    /// Inverse of [`Self::encrypt`].
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecureEnclaveError> {
        let mut out = RamaSeBytes::EMPTY;
        // SAFETY: blob/ciphertext pointers are valid for their stated lengths,
        // and `out` points to writable storage.
        let code = unsafe {
            rama_apple_se_p256_decrypt(
                self.blob.as_ptr(),
                self.blob.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                &mut out,
            )
        };
        if code != RAMA_SE_OK {
            return Err(SecureEnclaveError::from_code(code));
        }
        Ok(take_bytes(out))
    }
}

/// Copy bytes out of a bridge-allocated `RamaSeBytes` and free the original.
fn take_bytes(bytes: RamaSeBytes) -> Vec<u8> {
    let copied = if bytes.ptr.is_null() || bytes.len == 0 {
        Vec::new()
    } else {
        // SAFETY: bridge contract guarantees `ptr` is valid for `len` bytes
        // until we hand the struct back to `rama_apple_se_bytes_free`.
        let slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
        slice.to_vec()
    };
    // SAFETY: `bytes` was returned by the bridge; freeing a (NULL, 0) struct is
    // explicitly defined as a no-op on the Swift side.
    unsafe { rama_apple_se_bytes_free(bytes) };
    copied
}
