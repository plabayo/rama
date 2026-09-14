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
