//! Constant-time byte-slice comparison.
//!
//! `==` on `&[u8]` short-circuits on the first mismatching byte, which lets
//! an attacker who can observe comparison latency probe a secret byte by
//! byte. The helpers below always inspect the full shorter slice and then
//! fold the length check into the result, so the time taken depends only on
//! the lengths of the inputs (not on where they differ).
//!
//! Primary use is comparing credential blobs (HTTP Basic, Bearer tokens,
//! API keys); see `rama-net::user::credentials` for the consumers.

/// Constant-time equality for two byte slices.
///
/// Compares every byte of the shorter slice — the time taken depends only on
/// `min(a.len(), b.len())` and on whether the lengths match, never on the
/// position of the first mismatching byte.
///
/// Leaking the *length* of the secret is unavoidable in HTTP Basic Auth
/// (the credentials live in a fixed-length header), and any attempt to hide
/// the length would either dilate runtime for legitimate requests or still
/// be observable. What this protects against is the byte-wise prefix
/// oracle.
#[inline]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // `black_box` discourages the optimizer from turning the OR-reduction
    // back into a short-circuiting compare.
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_inputs_are_equal() {
        assert!(ct_eq_bytes(b"", b""));
    }

    #[test]
    fn equal_bytes_compare_equal() {
        assert!(ct_eq_bytes(b"secret", b"secret"));
    }

    #[test]
    fn different_bytes_compare_unequal() {
        assert!(!ct_eq_bytes(b"secret", b"sxcret"));
        assert!(!ct_eq_bytes(b"secret", b"secrex"));
    }

    #[test]
    fn different_lengths_compare_unequal() {
        assert!(!ct_eq_bytes(b"secret", b"secrets"));
        assert!(!ct_eq_bytes(b"", b"x"));
    }
}
