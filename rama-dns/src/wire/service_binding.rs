use core::{
    fmt,
    iter::FusedIterator,
    net::{Ipv4Addr, Ipv6Addr},
};

use rama_core::bytes::Bytes;
use rama_net::tls::ApplicationProtocol;
use rama_utils::macros::enums::enum_builder;

use super::{Name, NameParseError};

enum_builder! {
    /// Numeric key for a service binding parameter.
    ///
    /// The values defined for this implementation are the parameters used by
    /// RFC 9460 and RFC 9848. Other registry values are retained by
    /// [`SvcParamKey::Unknown`].
    /// Registry keys from other protocols remain unknown until Rama supports
    /// the protocol that defines their semantics.
    #[non_exhaustive]
    @U16
    pub enum SvcParamKey {
        /// Lists parameters that a client must understand.
        Mandatory => 0,
        /// Lists supported application protocols.
        Alpn => 1,
        /// Suppresses the protocol mapping's default ALPN set.
        NoDefaultAlpn => 2,
        /// Overrides the authority endpoint's port.
        Port => 3,
        /// Carries IPv4 address hints.
        Ipv4Hint => 4,
        /// Carries a TLS Encrypted ClientHello configuration list.
        Ech => 5,
        /// Carries IPv6 address hints.
        Ipv6Hint => 6,
        /// Reserved by RFC 9460 as the invalid service parameter key.
        Invalid => 65535,
    }
}

/// A validated ALPN protocol-name list backed by one shared wire buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpnList {
    wire: Bytes,
    protocol_count: u16,
}

impl AlpnList {
    fn from_wire(wire: Bytes) -> Option<Self> {
        if wire.is_empty() {
            return None;
        }

        let mut remaining = wire.as_ref();
        let mut protocol_count = 0_u16;
        while let Some((&length, encoded_protocols)) = remaining.split_first() {
            let length = usize::from(length);
            if length == 0 {
                return None;
            }
            remaining = encoded_protocols.get(length..)?;
            protocol_count = protocol_count.checked_add(1)?;
        }

        Some(Self {
            wire,
            protocol_count,
        })
    }

    /// Return the number of protocol identifiers.
    #[expect(
        clippy::len_without_is_empty,
        reason = "validated ALPN lists always contain at least one identifier"
    )]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.protocol_count as usize
    }

    /// Return the length-prefixed ALPN wire value.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Iterate over borrowed ALPN protocol identifiers.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> + FusedIterator + Clone {
        AlpnIter {
            remaining: &self.wire,
            remaining_protocols: self.len(),
        }
    }

    /// Iterate over owned application-protocol identifiers.
    ///
    /// Known identifiers do not allocate. Unknown identifiers copy their bytes;
    /// use [`Self::iter`] when a borrowed zero-copy view is sufficient.
    pub fn application_protocols(
        &self,
    ) -> impl ExactSizeIterator<Item = ApplicationProtocol> + FusedIterator + Clone {
        self.iter().map(ApplicationProtocol::from)
    }
}

#[derive(Clone)]
struct AlpnIter<'a> {
    remaining: &'a [u8],
    remaining_protocols: usize,
}

impl<'a> Iterator for AlpnIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_protocols == 0 {
            return None;
        }

        let (&length, encoded_protocols) = self.remaining.split_first()?;
        let length = usize::from(length);
        let protocol = encoded_protocols.get(..length)?;
        self.remaining = encoded_protocols.get(length..)?;
        self.remaining_protocols -= 1;
        Some(protocol)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_protocols, Some(self.remaining_protocols))
    }
}

impl ExactSizeIterator for AlpnIter<'_> {}
impl FusedIterator for AlpnIter<'_> {}

/// A decoded service binding parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SvcParam {
    /// Keys that a client must understand in order to use this record.
    Mandatory(Box<[SvcParamKey]>),
    /// ALPN protocol identifiers, each containing between 1 and 255 octets.
    Alpn(AlpnList),
    /// Indicates that the protocol mapping's default ALPN set is unsupported.
    NoDefaultAlpn,
    /// TCP or UDP port for the alternative endpoint.
    Port(u16),
    /// IPv4 address hints.
    Ipv4Hint(Box<[Ipv4Addr]>),
    /// An RFC 9848 ECHConfigList, including its redundant length prefix.
    ///
    /// DNS validates the list framing but leaves version-specific ECHConfig
    /// interpretation to TLS.
    Ech(Bytes),
    /// IPv6 address hints.
    Ipv6Hint(Box<[Ipv6Addr]>),
    /// A parameter whose key or wire format Rama does not yet understand.
    Unknown {
        /// Numeric service parameter key.
        key: SvcParamKey,
        /// Uninterpreted wire-format value.
        value: Bytes,
    },
}

impl SvcParam {
    /// Return this parameter's numeric key.
    #[must_use]
    pub const fn key(&self) -> SvcParamKey {
        match self {
            Self::Mandatory(_) => SvcParamKey::Mandatory,
            Self::Alpn(_) => SvcParamKey::Alpn,
            Self::NoDefaultAlpn => SvcParamKey::NoDefaultAlpn,
            Self::Port(_) => SvcParamKey::Port,
            Self::Ipv4Hint(_) => SvcParamKey::Ipv4Hint,
            Self::Ech(_) => SvcParamKey::Ech,
            Self::Ipv6Hint(_) => SvcParamKey::Ipv6Hint,
            Self::Unknown { key, .. } => *key,
        }
    }
}

/// Decoded RDATA shared by SVCB and HTTPS resource records.
///
/// This client-side wire model is intentionally parse-only. DNS record
/// construction and authoritative-server encoding are outside its scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBinding {
    priority: u16,
    target: Name,
    params: Box<[SvcParam]>,
}

impl ServiceBinding {
    /// Parse one complete borrowed SVCB-compatible RDATA value.
    ///
    /// The RDATA is copied once into shared immutable storage. Use
    /// [`ServiceBinding::parse_rdata_bytes`] when the caller already owns
    /// [`Bytes`] to avoid that copy.
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, ServiceBindingParseError> {
        if rdata.len() > usize::from(u16::MAX) {
            return Err(ServiceBindingParseError(
                ServiceBindingParseErrorKind::RdataTooLong,
            ));
        }
        Self::parse_rdata_bytes(&Bytes::copy_from_slice(rdata))
    }

    /// Parse one complete, owned SVCB-compatible RDATA value without copying
    /// opaque parameter bytes.
    ///
    /// This enforces the wire-format and self-consistency requirements in RFC
    /// 9460 Sections 2.2, 2.4.3, 7, and 8. RFC 9848 ECHConfigList framing is
    /// also checked, without interpreting version-specific TLS contents.
    pub fn parse_rdata_bytes(rdata: &Bytes) -> Result<Self, ServiceBindingParseError> {
        if rdata.len() > usize::from(u16::MAX) {
            return Err(ServiceBindingParseError(
                ServiceBindingParseErrorKind::RdataTooLong,
            ));
        }
        let Some(priority_bytes) = rdata.get(..2) else {
            return Err(ServiceBindingParseError(
                ServiceBindingParseErrorKind::MissingPriority,
            ));
        };
        let priority = u16::from_be_bytes([priority_bytes[0], priority_bytes[1]]);
        let target_wire = rdata.slice(2..);
        let (target, target_len) = Name::parse_prefix(&target_wire).map_err(|error| {
            ServiceBindingParseError(ServiceBindingParseErrorKind::InvalidTarget(error))
        })?;

        let mut offset = 2 + target_len;
        let mut previous_key = None;
        let mut params = Vec::new();
        while offset < rdata.len() {
            let Some(header) = rdata.get(offset..offset.saturating_add(4)) else {
                return Err(ServiceBindingParseError(
                    ServiceBindingParseErrorKind::TruncatedParamHeader,
                ));
            };
            let key_number = u16::from_be_bytes([header[0], header[1]]);
            let key = SvcParamKey::from(key_number);
            let value_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
            if key == SvcParamKey::Invalid {
                return Err(ServiceBindingParseError(
                    ServiceBindingParseErrorKind::InvalidParamKey,
                ));
            }
            if previous_key.is_some_and(|previous| key_number <= previous) {
                return Err(ServiceBindingParseError(
                    ServiceBindingParseErrorKind::ParamKeyOrder,
                ));
            }
            offset += 4;
            let value_end = offset.checked_add(value_len).ok_or({
                ServiceBindingParseError(ServiceBindingParseErrorKind::TruncatedParamValue(key))
            })?;
            if value_end > rdata.len() {
                return Err(ServiceBindingParseError(
                    ServiceBindingParseErrorKind::TruncatedParamValue(key),
                ));
            }
            params.push(parse_param(key, rdata.slice(offset..value_end))?);
            previous_key = Some(key_number);
            offset = value_end;
        }

        let binding = Self {
            priority,
            target,
            params: params.into_boxed_slice(),
        };
        // AliasMode ignores parameter semantics, but malformed wire values
        // were already rejected above as required by RFC 9460 Section 2.2.
        if binding.is_service_mode() {
            binding.validate_self_consistency()?;
        }
        Ok(binding)
    }

    /// Return the record's SvcPriority.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// Return the record's TargetName.
    #[must_use]
    pub const fn target(&self) -> &Name {
        &self.target
    }

    /// Return the record's service parameters in numeric key order.
    #[must_use]
    pub const fn params(&self) -> &[SvcParam] {
        &self.params
    }

    /// Return whether this record is in AliasMode.
    #[must_use]
    pub const fn is_alias_mode(&self) -> bool {
        self.priority == 0
    }

    /// Return whether this record is in ServiceMode.
    #[must_use]
    pub const fn is_service_mode(&self) -> bool {
        self.priority != 0
    }

    /// Look up a parameter by numeric key.
    #[must_use]
    pub fn param(&self, key: SvcParamKey) -> Option<&SvcParam> {
        self.params
            .binary_search_by_key(&u16::from(key), |param| u16::from(param.key()))
            .ok()
            .map(|index| &self.params[index])
    }

    /// Return the explicitly mandatory keys, if present.
    #[must_use]
    pub fn mandatory_keys(&self) -> Option<&[SvcParamKey]> {
        match self.param(SvcParamKey::Mandatory) {
            Some(SvcParam::Mandatory(keys)) => Some(keys),
            _ => None,
        }
    }

    /// Return the advertised ALPN protocol identifiers, if present.
    #[must_use]
    pub fn alpn_protocols(&self) -> Option<&AlpnList> {
        match self.param(SvcParamKey::Alpn) {
            Some(SvcParam::Alpn(protocols)) => Some(protocols),
            _ => None,
        }
    }

    /// Return whether the protocol mapping's default ALPN set is suppressed.
    #[must_use]
    pub fn has_no_default_alpn(&self) -> bool {
        self.param(SvcParamKey::NoDefaultAlpn).is_some()
    }

    /// Return the alternative endpoint port, if present.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        match self.param(SvcParamKey::Port) {
            Some(SvcParam::Port(port)) => Some(*port),
            _ => None,
        }
    }

    /// Return the advertised IPv4 address hints, if present.
    #[must_use]
    pub fn ipv4_hints(&self) -> Option<&[Ipv4Addr]> {
        match self.param(SvcParamKey::Ipv4Hint) {
            Some(SvcParam::Ipv4Hint(addresses)) => Some(addresses),
            _ => None,
        }
    }

    /// Return the framed ECHConfigList, if present.
    #[must_use]
    pub fn ech_config_list(&self) -> Option<&Bytes> {
        match self.param(SvcParamKey::Ech) {
            Some(SvcParam::Ech(config)) => Some(config),
            _ => None,
        }
    }

    /// Return the advertised IPv6 address hints, if present.
    #[must_use]
    pub fn ipv6_hints(&self) -> Option<&[Ipv6Addr]> {
        match self.param(SvcParamKey::Ipv6Hint) {
            Some(SvcParam::Ipv6Hint(addresses)) => Some(addresses),
            _ => None,
        }
    }

    fn validate_self_consistency(&self) -> Result<(), ServiceBindingParseError> {
        if self.param(SvcParamKey::NoDefaultAlpn).is_some()
            && self.param(SvcParamKey::Alpn).is_none()
        {
            return Err(ServiceBindingParseError(
                ServiceBindingParseErrorKind::NoDefaultAlpnWithoutAlpn,
            ));
        }

        if let Some(keys) = self.mandatory_keys()
            && keys.iter().any(|&key| self.param(key).is_none())
        {
            return Err(ServiceBindingParseError(
                ServiceBindingParseErrorKind::MissingMandatoryParam,
            ));
        }
        Ok(())
    }
}

fn parse_param(key: SvcParamKey, value: Bytes) -> Result<SvcParam, ServiceBindingParseError> {
    let invalid_value =
        || ServiceBindingParseError(ServiceBindingParseErrorKind::InvalidParamValue(key));
    match key {
        SvcParamKey::Mandatory => {
            if value.is_empty() || !value.len().is_multiple_of(2) {
                return Err(invalid_value());
            }
            let mut keys = Vec::with_capacity(value.len() / 2);
            let mut previous = None;
            for pair in value.chunks_exact(2) {
                let key_number = u16::from_be_bytes([pair[0], pair[1]]);
                let key = SvcParamKey::from(key_number);
                if key == SvcParamKey::Mandatory
                    || key == SvcParamKey::Invalid
                    || previous.is_some_and(|previous| key_number <= previous)
                {
                    return Err(if key == SvcParamKey::Mandatory {
                        ServiceBindingParseError(
                            ServiceBindingParseErrorKind::MandatoryIncludesItself,
                        )
                    } else {
                        invalid_value()
                    });
                }
                keys.push(key);
                previous = Some(key_number);
            }
            Ok(SvcParam::Mandatory(keys.into_boxed_slice()))
        }
        SvcParamKey::Alpn => {
            let protocols = AlpnList::from_wire(value).ok_or_else(invalid_value)?;
            Ok(SvcParam::Alpn(protocols))
        }
        SvcParamKey::NoDefaultAlpn => {
            if value.is_empty() {
                Ok(SvcParam::NoDefaultAlpn)
            } else {
                Err(invalid_value())
            }
        }
        SvcParamKey::Port => {
            let [high, low] = value.as_ref() else {
                return Err(invalid_value());
            };
            Ok(SvcParam::Port(u16::from_be_bytes([*high, *low])))
        }
        SvcParamKey::Ipv4Hint => {
            if value.is_empty() || !value.len().is_multiple_of(4) {
                return Err(invalid_value());
            }
            Ok(SvcParam::Ipv4Hint(
                value
                    .chunks_exact(4)
                    .map(|octets| Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ))
        }
        SvcParamKey::Ech => {
            if !valid_ech_config_list(&value) {
                return Err(invalid_value());
            }
            Ok(SvcParam::Ech(value))
        }
        SvcParamKey::Ipv6Hint => {
            if value.is_empty() || !value.len().is_multiple_of(16) {
                return Err(invalid_value());
            }
            Ok(SvcParam::Ipv6Hint(
                value
                    .chunks_exact(16)
                    .map(|octets| {
                        let mut address = [0; 16];
                        address.copy_from_slice(octets);
                        Ipv6Addr::from(address)
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ))
        }
        SvcParamKey::Invalid | SvcParamKey::Unknown(_) => Ok(SvcParam::Unknown { key, value }),
    }
}

fn valid_ech_config_list(value: &[u8]) -> bool {
    let Some(length_bytes) = value.get(..2) else {
        return false;
    };
    let list_len = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    if list_len < 4 || list_len != value.len() - 2 {
        return false;
    }

    let mut offset = 2;
    while offset < value.len() {
        let Some(header) = value.get(offset..offset.saturating_add(4)) else {
            return false;
        };
        let contents_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let Some(contents_offset) = offset.checked_add(4) else {
            return false;
        };
        let Some(end) = contents_offset.checked_add(contents_len) else {
            return false;
        };
        if end > value.len() {
            return false;
        }
        offset = end;
    }
    true
}

/// Error returned when SVCB-compatible RDATA is malformed or inconsistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBindingParseError(ServiceBindingParseErrorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum ServiceBindingParseErrorKind {
    RdataTooLong,
    MissingPriority,
    InvalidTarget(NameParseError),
    TruncatedParamHeader,
    TruncatedParamValue(SvcParamKey),
    InvalidParamKey,
    ParamKeyOrder,
    InvalidParamValue(SvcParamKey),
    NoDefaultAlpnWithoutAlpn,
    MandatoryIncludesItself,
    MissingMandatoryParam,
}

impl fmt::Display for ServiceBindingParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ServiceBindingParseErrorKind::RdataTooLong => {
                f.write_str("service binding RDATA exceeds the DNS record size limit")
            }
            ServiceBindingParseErrorKind::MissingPriority => {
                f.write_str("service binding RDATA has no complete priority")
            }
            ServiceBindingParseErrorKind::InvalidTarget(error) => {
                write!(f, "invalid service binding target name: {error}")
            }
            ServiceBindingParseErrorKind::TruncatedParamHeader => {
                f.write_str("service parameter header is truncated")
            }
            ServiceBindingParseErrorKind::TruncatedParamValue(key) => {
                write!(f, "service parameter {key} is truncated")
            }
            ServiceBindingParseErrorKind::InvalidParamKey => {
                f.write_str("service parameter uses the reserved invalid key")
            }
            ServiceBindingParseErrorKind::ParamKeyOrder => {
                f.write_str("service parameter keys are not strictly increasing")
            }
            ServiceBindingParseErrorKind::InvalidParamValue(key) => {
                write!(f, "service parameter {key} has an invalid wire value")
            }
            ServiceBindingParseErrorKind::NoDefaultAlpnWithoutAlpn => {
                f.write_str("no-default-alpn requires alpn")
            }
            ServiceBindingParseErrorKind::MandatoryIncludesItself => {
                f.write_str("mandatory must not list itself")
            }
            ServiceBindingParseErrorKind::MissingMandatoryParam => {
                f.write_str("mandatory lists a parameter absent from the record")
            }
        }
    }
}

impl core::error::Error for ServiceBindingParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.0 {
            ServiceBindingParseErrorKind::InvalidTarget(error) => Some(error),
            _ => None,
        }
    }
}
