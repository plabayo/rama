//! Application protocol agreement and ALPN wire validation.

/// How peers agree on their application protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AlpnPolicy {
    /// Require a nonempty ALPN offer and an agreed protocol.
    #[default]
    Require,
    /// The application explicitly agrees the protocol through another mechanism.
    OutOfBandAgreement,
}

/// Invalid or missing ALPN configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlpnError {
    /// The policy requires an ALPN offer.
    Required,
    /// An entry or the complete extension exceeds the TLS wire limits.
    Invalid,
}

impl std::fmt::Display for AlpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Required => "an application protocol is required",
            Self::Invalid => "invalid ALPN protocol list",
        })
    }
}

impl std::error::Error for AlpnError {}

/// Validate the protocol entries and the complete TLS extension body length.
pub fn validate_alpn<'a>(
    protocols: impl IntoIterator<Item = &'a [u8]>,
    policy: AlpnPolicy,
) -> Result<(), AlpnError> {
    let mut total = 0usize;
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > 255 {
            return Err(AlpnError::Invalid);
        }
        total = total
            .checked_add(protocol.len() + 1)
            .ok_or(AlpnError::Invalid)?;
        if total > usize::from(u16::MAX) - 2 {
            return Err(AlpnError::Invalid);
        }
    }
    if total == 0 && policy == AlpnPolicy::Require {
        return Err(AlpnError::Required);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The extension body is a 16-bit vector holding a 16-bit-length list, leaving 65533
    /// bytes for the entries themselves.
    const BODY_LIMIT: usize = 65533;

    fn validate(protocols: &[Vec<u8>], policy: AlpnPolicy) -> Result<(), AlpnError> {
        validate_alpn(protocols.iter().map(Vec::as_slice), policy)
    }

    /// Only an empty offer distinguishes the policies; a protocol is accepted under both.
    #[test]
    fn a_protocol_is_required_only_when_the_policy_says_so() {
        assert_eq!(validate(&[], AlpnPolicy::Require), Err(AlpnError::Required));
        assert_eq!(validate(&[], AlpnPolicy::OutOfBandAgreement), Ok(()));
        for policy in [AlpnPolicy::Require, AlpnPolicy::OutOfBandAgreement] {
            assert_eq!(validate(&[b"h3".to_vec()], policy), Ok(()));
            // A one-byte name still counts as an offer once its length prefix is added.
            assert_eq!(validate(&[b"x".to_vec()], policy), Ok(()));
        }
    }

    /// Each entry is a 8-bit-length vector, so it carries 1 to 255 bytes.
    #[test]
    fn an_entry_holds_between_one_and_255_bytes() {
        for policy in [AlpnPolicy::Require, AlpnPolicy::OutOfBandAgreement] {
            assert_eq!(validate(&[Vec::new()], policy), Err(AlpnError::Invalid));
            assert_eq!(validate(&[vec![0; 255]], policy), Ok(()));
            assert_eq!(validate(&[vec![0; 256]], policy), Err(AlpnError::Invalid));
            // A valid entry does not excuse an invalid one later in the list.
            assert_eq!(
                validate(&[b"h3".to_vec(), Vec::new()], policy),
                Err(AlpnError::Invalid)
            );
        }
    }

    /// Entries are measured with their length prefix, against the extension body limit.
    #[test]
    fn the_entries_and_their_length_prefixes_fill_the_extension_body() {
        let filling = |total: usize| {
            let mut protocols = vec![vec![0; 255]; total / 256];
            let remainder = total % 256;
            if remainder > 0 {
                protocols.push(vec![0; remainder - 1]);
            }
            assert_eq!(
                protocols.iter().map(|entry| entry.len() + 1).sum::<usize>(),
                total
            );
            protocols
        };
        assert_eq!(validate(&filling(BODY_LIMIT), AlpnPolicy::Require), Ok(()));
        assert_eq!(
            validate(&filling(BODY_LIMIT + 1), AlpnPolicy::Require),
            Err(AlpnError::Invalid)
        );
    }

    #[test]
    fn each_error_states_its_cause() {
        assert_eq!(
            AlpnError::Required.to_string(),
            "an application protocol is required"
        );
        assert_eq!(AlpnError::Invalid.to_string(), "invalid ALPN protocol list");
    }
}
