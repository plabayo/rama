#[cfg(feature = "http")]
mod http;

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub use http::{Ja4H, Ja4HComputeError};

#[cfg(feature = "tls")]
mod tls;

#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub use tls::{Ja4, Ja4ComputeError};

/// Hash a string into the 12-hex-char truncated SHA-256 digest used by the
/// JA4 family. Empty input maps to the all-zero sentinel per the spec.
#[cfg(any(feature = "http", feature = "tls"))]
fn hash12(s: impl AsRef<str>) -> std::borrow::Cow<'static, str> {
    use sha2::{Digest as _, Sha256};

    let s = s.as_ref();
    if s.is_empty() {
        "000000000000".into()
    } else {
        let sha256 = Sha256::digest(s);
        hex::encode(&sha256.as_slice()[..6]).into()
    }
}
