use core::{fmt, time::Duration};

use rama_core::{
    bytes::{Bytes, BytesMut},
    extensions::Extension,
};
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::str::cmp_ignore_ascii_case;

use crate::{
    codec::{DEFAULT_MAX_HEADERS, Header, HeaderSlot, HeaderValue},
    message::Response,
    proto::{MethodKind, Preview, header, is_token},
};

use super::OptionsValidation;

/// Error decoding typed capabilities from an OPTIONS response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CapabilitiesError {
    /// The response did not belong to a successful OPTIONS transaction.
    InvalidResponse,
    /// The response failed capability validation.
    InvalidCapabilities(&'static str),
}

impl fmt::Display for CapabilitiesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResponse => "capability discovery requires a successful OPTIONS response",
            Self::InvalidCapabilities(message) => message,
        })
    }
}

impl core::error::Error for CapabilitiesError {}

/// Whether an OPTIONS response advertises an ICAP method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodSupport {
    /// The response did not provide usable method metadata.
    Unknown,
    /// The method is advertised.
    Supported,
    /// A usable method list did not contain the method.
    Unsupported,
}

/// A transfer action advertised for an HTTP file extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDisposition {
    /// Send at most the advertised Preview size first.
    Preview,
    /// Do not send the message to this ICAP service.
    Ignore,
    /// Send the complete message without Preview.
    Complete,
}

/// Parsed feature tokens from OPTIONS `Allow` fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowedFeatures {
    valid: bool,
    tokens: SmallVec<[Bytes; 3]>,
}

impl Default for AllowedFeatures {
    fn default() -> Self {
        Self {
            valid: true,
            tokens: SmallVec::new(),
        }
    }
}

impl AllowedFeatures {
    /// Return whether every supplied list member was a valid token.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// Return whether a feature token was advertised.
    #[must_use]
    pub fn contains(&self, feature: &str) -> bool {
        self.valid
            && self
                .tokens
                .binary_search_by(|token| cmp_ignore_ascii_case(token, feature.as_bytes()))
                .is_ok()
    }

    /// Iterate over the advertised feature tokens.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Bytes> {
        self.tokens.iter()
    }
}

/// Parsed `Methods` capability metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SupportedMethods {
    available: bool,
    reqmod: bool,
    respmod: bool,
    extensions: SmallVec<[Bytes; 1]>,
}

impl SupportedMethods {
    /// Return support for a standard ICAP method.
    #[must_use]
    pub const fn support(&self, method: MethodKind) -> MethodSupport {
        if !self.available {
            return MethodSupport::Unknown;
        }
        let supported = match method {
            MethodKind::Reqmod => self.reqmod,
            MethodKind::Respmod => self.respmod,
            MethodKind::Options => true,
            MethodKind::Extension => return MethodSupport::Unknown,
        };
        if supported {
            MethodSupport::Supported
        } else {
            MethodSupport::Unsupported
        }
    }

    /// Return support for an extension method token.
    #[must_use]
    pub fn supports_extension(&self, method: &str) -> MethodSupport {
        if !self.available {
            return MethodSupport::Unknown;
        }
        if self
            .extensions
            .binary_search_by(|value| value.as_ref().cmp(method.as_bytes()))
            .is_ok()
        {
            MethodSupport::Supported
        } else {
            MethodSupport::Unsupported
        }
    }

    /// Iterate over advertised extension method tokens.
    pub fn extensions(&self) -> impl ExactSizeIterator<Item = &Bytes> {
        self.extensions.iter()
    }
}

/// Parsed `Transfer-*` selection rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRules {
    valid: bool,
    preview: SmallVec<[Bytes; 2]>,
    ignore: SmallVec<[Bytes; 2]>,
    complete: SmallVec<[Bytes; 2]>,
    fallback: TransferDisposition,
}

impl Default for TransferRules {
    fn default() -> Self {
        Self {
            valid: true,
            preview: SmallVec::new(),
            ignore: SmallVec::new(),
            complete: SmallVec::new(),
            fallback: TransferDisposition::Complete,
        }
    }
}

impl TransferRules {
    /// Return whether the peer supplied a deterministic rule set.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// Iterate over extensions explicitly assigned to Preview.
    pub fn preview_extensions(&self) -> impl ExactSizeIterator<Item = &Bytes> {
        self.preview.iter()
    }

    /// Iterate over extensions explicitly excluded from adaptation.
    pub fn ignored_extensions(&self) -> impl ExactSizeIterator<Item = &Bytes> {
        self.ignore.iter()
    }

    /// Iterate over extensions explicitly assigned to complete transfer.
    pub fn complete_extensions(&self) -> impl ExactSizeIterator<Item = &Bytes> {
        self.complete.iter()
    }

    /// Return the wildcard disposition for unmatched extensions.
    #[must_use]
    pub const fn fallback(&self) -> TransferDisposition {
        self.fallback
    }

    /// Classify one file extension.
    ///
    /// The caller decides how an HTTP target maps to an extension. Invalid or
    /// absent rules conservatively select complete transfer.
    #[must_use]
    pub fn classify(&self, extension: &str) -> TransferDisposition {
        if !self.valid {
            return TransferDisposition::Complete;
        }
        let extension = extension.as_bytes();
        if contains_ascii_case_insensitive(&self.preview, extension) {
            TransferDisposition::Preview
        } else if contains_ascii_case_insensitive(&self.ignore, extension) {
            TransferDisposition::Ignore
        } else if contains_ascii_case_insensitive(&self.complete, extension) {
            TransferDisposition::Complete
        } else {
            self.fallback
        }
    }
}

/// Immutable capabilities discovered with one successful OPTIONS exchange.
#[derive(Clone)]
pub struct ServiceCapabilities {
    response: Response,
    methods: SupportedMethods,
    service_tag: Option<Bytes>,
    service: Option<Bytes>,
    service_id: Option<Bytes>,
    preview: Option<Preview>,
    allowed_features: AllowedFeatures,
    allow_206: bool,
    transfer: TransferRules,
    options_ttl: Option<Duration>,
    cache_lifetime: Option<Duration>,
    max_connections: Option<u64>,
    date: Option<Bytes>,
    opt_body_type: Option<Bytes>,
    opt_body: Option<Bytes>,
}

impl Extension for ServiceCapabilities {}

impl fmt::Debug for ServiceCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceCapabilities")
            .field("methods", &self.methods)
            .field("has_service_tag", &self.service_tag.is_some())
            .field("preview", &self.preview)
            .field("allowed_features", &self.allowed_features)
            .field("allow_206", &self.allow_206)
            .field("transfer", &self.transfer)
            .field("options_ttl", &self.options_ttl)
            .field("max_connections", &self.max_connections)
            .field("opt_body_len", &self.opt_body.as_ref().map(Bytes::len))
            .finish_non_exhaustive()
    }
}

impl ServiceCapabilities {
    /// Parse a completed OPTIONS response into a capability snapshot.
    ///
    /// `max_headers` bounds temporary header slots. `allow_206_offered` must
    /// reflect the corresponding OPTIONS request; an unsolicited response
    /// token is retained in the raw response but does not negotiate 206.
    pub fn from_options_response(
        response: Response,
        opt_body: Option<Bytes>,
        max_headers: usize,
        allow_206_offered: bool,
        validation: OptionsValidation,
    ) -> Result<Self, CapabilitiesError> {
        if response.method() != MethodKind::Options
            || response.status() != crate::proto::StatusCode::OK
        {
            return Err(CapabilitiesError::InvalidResponse);
        }
        Self::parse(
            response,
            opt_body,
            max_headers,
            allow_206_offered,
            validation,
        )
        .map_err(CapabilitiesError::InvalidCapabilities)
    }

    pub(crate) fn parse(
        response: Response,
        opt_body: Option<Bytes>,
        max_headers: usize,
        allow_206_offered: bool,
        validation: OptionsValidation,
    ) -> Result<Self, &'static str> {
        let mut slots = SmallVec::<[HeaderSlot; DEFAULT_MAX_HEADERS]>::new();
        slots.resize(max_headers, HeaderSlot::EMPTY);
        let head = response
            .parse_head(&mut slots)
            .map_err(|_error| "decode accepted OPTIONS response")?;
        let mut parsed = ParsedCapabilities::default();
        for field in head.headers() {
            let value = normalized_value(response.head_bytes(), field.value());
            parsed.observe(field.name(), value);
        }
        parsed.finish(response, opt_body, allow_206_offered, validation)
    }

    /// Return the accepted raw OPTIONS response metadata.
    #[must_use]
    pub const fn response(&self) -> &Response {
        &self.response
    }

    /// Return parsed method support.
    #[must_use]
    pub const fn methods(&self) -> &SupportedMethods {
        &self.methods
    }

    /// Return the service generation tag, including its wire quoting.
    #[must_use]
    pub const fn service_tag(&self) -> Option<&Bytes> {
        self.service_tag.as_ref()
    }

    /// Return the human-readable service description.
    #[must_use]
    pub const fn service(&self) -> Option<&Bytes> {
        self.service.as_ref()
    }

    /// Return the opaque service identifier.
    #[must_use]
    pub const fn service_id(&self) -> Option<&Bytes> {
        self.service_id.as_ref()
    }

    /// Return the maximum Preview size advertised by the service.
    #[must_use]
    pub const fn preview(&self) -> Option<Preview> {
        self.preview
    }

    /// Return whether the service advertises 204 support.
    #[must_use]
    pub fn allows_204(&self) -> bool {
        self.allowed_features.contains("204")
    }

    /// Return whether the service negotiated 206 support.
    ///
    /// A response token alone is insufficient: this is true only when the
    /// corresponding OPTIONS request offered the extension.
    #[must_use]
    pub const fn allows_206(&self) -> bool {
        self.allow_206
    }

    /// Return every valid feature token advertised in `Allow`.
    #[must_use]
    pub const fn allowed_features(&self) -> &AllowedFeatures {
        &self.allowed_features
    }

    /// Return deterministic transfer selection rules.
    #[must_use]
    pub const fn transfer_rules(&self) -> &TransferRules {
        &self.transfer
    }

    /// Return the valid peer-supplied OPTIONS lifetime.
    ///
    /// `None` means the RFC's non-expiring default or an invalid field. Cache
    /// policy distinguishes those cases internally and never treats an
    /// invalid value as non-expiring.
    #[must_use]
    pub const fn options_ttl(&self) -> Option<Duration> {
        self.options_ttl
    }

    /// Return the advertised connection limit.
    #[must_use]
    pub const fn max_connections(&self) -> Option<u64> {
        self.max_connections
    }

    /// Return the opaque server date value.
    #[must_use]
    pub const fn date(&self) -> Option<&Bytes> {
        self.date.as_ref()
    }

    /// Return the declared type of the optional OPTIONS body.
    #[must_use]
    pub const fn opt_body_type(&self) -> Option<&Bytes> {
        self.opt_body_type.as_ref()
    }

    /// Return the bounded, opaque OPTIONS body.
    #[must_use]
    pub const fn opt_body(&self) -> Option<&Bytes> {
        self.opt_body.as_ref()
    }

    pub(super) const fn cache_lifetime(&self) -> Option<Duration> {
        self.cache_lifetime
    }
}

/// Raw OPTIONS fields collected before semantic capability validation.
///
/// List-valued fields may be split across multiple header lines. Each
/// occurrence is retained as a zero-copy slice of the accepted response head
/// and combined during `finish`. Single-valued fields use [`Singleton`] to
/// remember repeated and conflicting occurrences for strict validation.
#[derive(Default)]
struct ParsedCapabilities {
    method_values: SmallVec<[Bytes; 1]>,
    service_tag: Singleton,
    service: Singleton,
    service_id: Singleton,
    preview: Singleton,
    allow_values: SmallVec<[Bytes; 1]>,
    transfer_preview_values: SmallVec<[Bytes; 1]>,
    transfer_ignore_values: SmallVec<[Bytes; 1]>,
    transfer_complete_values: SmallVec<[Bytes; 1]>,
    options_ttl: Singleton,
    max_connections: Singleton,
    date: Singleton,
    opt_body_type: Singleton,
    saw_encapsulated: bool,
}

impl ParsedCapabilities {
    fn observe(&mut self, name: &str, value: Bytes) {
        if name.eq_ignore_ascii_case(header::METHODS) {
            self.method_values.push(value);
        } else if name.eq_ignore_ascii_case(header::ISTAG) {
            self.service_tag.observe(value);
        } else if name.eq_ignore_ascii_case(header::SERVICE) {
            self.service.observe(value);
        } else if name.eq_ignore_ascii_case(header::SERVICE_ID) {
            self.service_id.observe(value);
        } else if name.eq_ignore_ascii_case(header::PREVIEW) {
            self.preview.observe(value);
        } else if name.eq_ignore_ascii_case(header::ALLOW) {
            self.allow_values.push(value);
        } else if name.eq_ignore_ascii_case(header::TRANSFER_PREVIEW) {
            self.transfer_preview_values.push(value);
        } else if name.eq_ignore_ascii_case(header::TRANSFER_IGNORE) {
            self.transfer_ignore_values.push(value);
        } else if name.eq_ignore_ascii_case(header::TRANSFER_COMPLETE) {
            self.transfer_complete_values.push(value);
        } else if name.eq_ignore_ascii_case(header::OPTIONS_TTL) {
            self.options_ttl.observe(value);
        } else if name.eq_ignore_ascii_case(header::MAX_CONNECTIONS) {
            self.max_connections.observe(value);
        } else if name.eq_ignore_ascii_case(header::DATE) {
            self.date.observe(value);
        } else if name.eq_ignore_ascii_case(header::OPT_BODY_TYPE) {
            self.opt_body_type.observe(value);
        } else if name.eq_ignore_ascii_case(header::ENCAPSULATED) {
            self.saw_encapsulated = true;
        }
    }

    fn finish(
        self,
        response: Response,
        opt_body: Option<Bytes>,
        allow_206_offered: bool,
        validation: OptionsValidation,
    ) -> Result<ServiceCapabilities, &'static str> {
        let (methods, methods_valid) = parse_methods(&self.method_values);
        let service_tag = self
            .service_tag
            .valid_value()
            .filter(|value| valid_service_tag(value, validation));
        let preview = self
            .preview
            .valid_value()
            .and_then(|value| Preview::from_bytes(value).ok());
        let allowed_features = parse_allow(&self.allow_values);
        let transfer = parse_transfer(
            &self.transfer_preview_values,
            &self.transfer_ignore_values,
            &self.transfer_complete_values,
            preview.is_some(),
        );
        let ttl_value = self.options_ttl.valid_value();
        let options_ttl = ttl_value.and_then(parse_duration);
        let ttl_valid =
            !self.options_ttl.conflicted && ttl_value.is_none_or(|_value| options_ttl.is_some());
        let max_value = self.max_connections.valid_value();
        let max_connections = max_value.and_then(parse_decimal);
        let max_valid = !self.max_connections.conflicted
            && max_value.is_none_or(|_value| max_connections.is_some());
        let opt_body_type = self
            .opt_body_type
            .valid_value()
            .filter(|value| is_token(value));
        let opt_body_type_valid = self
            .opt_body_type
            .valid_value()
            .is_none_or(|value| is_token(value));
        let opt_body_pair_valid =
            opt_body.is_some() == opt_body_type.is_some() && opt_body_type_valid;
        let singleton_cardinality_valid = [
            &self.service_tag,
            &self.service,
            &self.service_id,
            &self.preview,
            &self.options_ttl,
            &self.max_connections,
            &self.date,
            &self.opt_body_type,
        ]
        .into_iter()
        .all(Singleton::is_single);

        if validation == OptionsValidation::Strict
            && (!methods_valid
                || !methods.available
                || service_tag.is_none()
                || !self.saw_encapsulated
                || self.preview.conflicted
                || (self.preview.value.is_some() && preview.is_none())
                || !allowed_features.valid
                || !transfer.valid
                || !ttl_valid
                || !max_valid
                || !singleton_cardinality_valid
                || !opt_body_pair_valid)
        {
            return Err("OPTIONS response failed strict capability validation");
        }
        let cache_lifetime = if !methods.available || service_tag.is_none() || !ttl_valid {
            Some(Duration::ZERO)
        } else {
            options_ttl
        };

        let (opt_body_type, opt_body) = if opt_body_pair_valid {
            (opt_body_type.cloned(), opt_body)
        } else {
            (None, None)
        };
        Ok(ServiceCapabilities {
            response,
            methods,
            service_tag: service_tag.cloned(),
            service: self.service.valid_value().cloned(),
            service_id: self.service_id.valid_value().cloned(),
            preview,
            allow_206: allow_206_offered && allowed_features.contains("206"),
            allowed_features,
            transfer,
            options_ttl,
            cache_lifetime,
            max_connections: max_valid.then_some(max_connections).flatten(),
            date: self.date.valid_value().cloned(),
            opt_body_type,
            opt_body,
        })
    }
}

#[derive(Default)]
struct Singleton {
    value: Option<Bytes>,
    conflicted: bool,
    repeated: bool,
}

impl Singleton {
    fn observe(&mut self, value: Bytes) {
        if let Some(current) = &self.value {
            self.repeated = true;
            self.conflicted |= current != &value;
        } else {
            self.value = Some(value)
        }
    }

    fn valid_value(&self) -> Option<&Bytes> {
        (!self.conflicted).then_some(self.value.as_ref()).flatten()
    }

    fn is_single(&self) -> bool {
        !self.repeated
    }
}

fn normalized_value(head: &Bytes, value: HeaderValue<'_>) -> Bytes {
    if let Some(value) = value.as_bytes() {
        return shared_slice(head, value);
    }
    let mut output = BytesMut::with_capacity(value.encoded_len());
    for (index, segment) in value.segments().enumerate() {
        if index > 0 {
            output.extend_from_slice(b" ");
        }
        output.extend_from_slice(segment);
    }
    output.freeze()
}

fn parse_methods(values: &[Bytes]) -> (SupportedMethods, bool) {
    let mut methods = SupportedMethods::default();
    let mut valid = !values.is_empty();
    let mut syntax_valid = true;
    for value in values {
        for token in comma_tokens(value) {
            if token.is_empty() {
                valid = false;
                syntax_valid = false;
                continue;
            }
            if token == b"REQMOD" {
                methods.reqmod = true;
                methods.available = true;
            } else if token == b"RESPMOD" {
                methods.respmod = true;
                methods.available = true;
            } else if token == b"OPTIONS" {
                // RFC 3507 excludes OPTIONS from this list. Compatible
                // parsing retains other usable methods; strict validation
                // still rejects the illegal member.
                valid = false;
            } else if is_token(token) {
                methods.available = true;
                methods.extensions.push(shared_slice(value, token));
            } else {
                valid = false;
                syntax_valid = false;
            }
        }
    }
    if !syntax_valid {
        methods = SupportedMethods::default();
    } else {
        methods
            .extensions
            .sort_unstable_by(|left, right| left.as_ref().cmp(right.as_ref()));
        methods.extensions.dedup();
    }
    (methods, valid)
}

fn parse_allow(values: &[Bytes]) -> AllowedFeatures {
    let mut features = AllowedFeatures::default();
    for value in values {
        for token in comma_tokens(value) {
            if token.is_empty() {
                features.valid = false;
                continue;
            }
            if !is_token(token) {
                features.valid = false;
            } else {
                features.tokens.push(shared_slice(value, token));
            }
        }
    }
    if !features.valid {
        features.tokens.clear();
    } else {
        sort_dedup_ignore_ascii_case(&mut features.tokens);
    }
    features
}

fn parse_transfer(
    preview_values: &[Bytes],
    ignore_values: &[Bytes],
    complete_values: &[Bytes],
    has_preview: bool,
) -> TransferRules {
    if preview_values.is_empty() && ignore_values.is_empty() && complete_values.is_empty() {
        return TransferRules::default();
    }
    let mut rules = TransferRules::default();
    let mut wildcard = None;
    for (values, disposition, output) in [
        (
            preview_values,
            TransferDisposition::Preview,
            &mut rules.preview,
        ),
        (
            ignore_values,
            TransferDisposition::Ignore,
            &mut rules.ignore,
        ),
        (
            complete_values,
            TransferDisposition::Complete,
            &mut rules.complete,
        ),
    ] {
        for value in values {
            let mut list_valid = true;
            for token in comma_tokens(value) {
                if token.is_empty() {
                    list_valid = false;
                    continue;
                }
                if token == b"*" {
                    if wildcard.replace(disposition).is_some() {
                        rules.valid = false;
                    }
                } else if is_token(token) {
                    if disposition == TransferDisposition::Preview && !has_preview {
                        rules.valid = false;
                    }
                    output.push(shared_slice(value, token));
                } else {
                    rules.valid = false;
                }
            }
            rules.valid &= list_valid;
        }
    }
    rules.fallback = wildcard.unwrap_or(TransferDisposition::Complete);
    if rules.fallback == TransferDisposition::Preview && !has_preview {
        rules.valid = false;
    }
    sort_dedup_ignore_ascii_case(&mut rules.preview);
    sort_dedup_ignore_ascii_case(&mut rules.ignore);
    sort_dedup_ignore_ascii_case(&mut rules.complete);
    rules.valid &= wildcard.is_some() && transfer_rules_are_disjoint(&rules);
    if rules.valid {
        rules
    } else {
        TransferRules {
            valid: false,
            ..TransferRules::default()
        }
    }
}

fn transfer_rules_are_disjoint(rules: &TransferRules) -> bool {
    !sorted_lists_overlap(&rules.preview, &rules.ignore)
        && !sorted_lists_overlap(&rules.preview, &rules.complete)
        && !sorted_lists_overlap(&rules.ignore, &rules.complete)
}

fn contains_ascii_case_insensitive(values: &[Bytes], needle: &[u8]) -> bool {
    values
        .binary_search_by(|value| cmp_ignore_ascii_case(value, needle))
        .is_ok()
}

fn sort_dedup_ignore_ascii_case<const N: usize>(values: &mut SmallVec<[Bytes; N]>) {
    values.sort_unstable_by(|left, right| {
        cmp_ignore_ascii_case(left, right).then_with(|| left.cmp(right))
    });
    values.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
}

fn sorted_lists_overlap(left: &[Bytes], right: &[Bytes]) -> bool {
    let (mut left_index, mut right_index) = (0, 0);
    while let (Some(left), Some(right)) = (left.get(left_index), right.get(right_index)) {
        match cmp_ignore_ascii_case(left, right) {
            core::cmp::Ordering::Less => left_index += 1,
            core::cmp::Ordering::Greater => right_index += 1,
            core::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn shared_slice(source: &Bytes, value: &[u8]) -> Bytes {
    let base = source.as_ptr() as usize;
    let start = value.as_ptr() as usize;
    if let Some(offset) = start.checked_sub(base)
        && offset
            .checked_add(value.len())
            .is_some_and(|end| end <= source.len())
    {
        return source.slice(offset..offset + value.len());
    }
    Bytes::copy_from_slice(value)
}

fn comma_tokens(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value.split(|byte| *byte == b',').map(trim_ascii)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn parse_duration(value: &Bytes) -> Option<Duration> {
    parse_decimal(value).map(Duration::from_secs)
}

fn parse_decimal(value: &Bytes) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value.iter().try_fold(0_u64, |number, byte| {
        number.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
    })
}

fn valid_service_tag(value: &Bytes, validation: OptionsValidation) -> bool {
    Header::new(header::ISTAG, value).is_ok()
        || (validation == OptionsValidation::Compatible
            && !value.is_empty()
            && value.len() <= 32
            && is_token(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        codec::{HeadParserConfig, HeaderFolding, ResponseLine},
        message::EncapsulatedParts,
        proto::{StatusCode, header},
    };

    fn response(headers: &[Header<'_>]) -> Response {
        Response::new(
            MethodKind::Options,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            headers,
            Some(EncapsulatedParts::null()),
        )
        .unwrap()
    }

    #[test]
    fn parses_rfc_and_c_icap_capabilities() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD, REQMOD, X-TRACE").unwrap(),
            Header::new(header::SERVICE, b"C-ICAP/0.6 echo service").unwrap(),
            Header::new(header::SERVICE_ID, b"echo").unwrap(),
            Header::new(header::ISTAG, b"\"CI0001\"").unwrap(),
            Header::new(header::PREVIEW, b"1024").unwrap(),
            Header::new(header::ALLOW, b"204, 206, trailers").unwrap(),
            Header::new(header::TRANSFER_PREVIEW, b"jpg, *").unwrap(),
            Header::new(header::OPTIONS_TTL, b"3600").unwrap(),
            Header::new(header::MAX_CONNECTIONS, b"64").unwrap(),
            Header::new(header::DATE, b"Wed, 20 Aug 2026 12:00:00 GMT").unwrap(),
        ]);
        let head_start = response.head_bytes().as_ptr() as usize;
        let head_end = head_start + response.head_bytes().len();
        let capabilities =
            ServiceCapabilities::parse(response, None, 32, true, OptionsValidation::Compatible)
                .unwrap();

        assert_eq!(
            capabilities.methods().support(MethodKind::Reqmod),
            MethodSupport::Supported
        );
        assert_eq!(
            capabilities.methods().support(MethodKind::Respmod),
            MethodSupport::Supported
        );
        assert_eq!(
            capabilities.methods().supports_extension("X-TRACE"),
            MethodSupport::Supported
        );
        assert_eq!(capabilities.preview(), Some(Preview::new(1024)));
        assert!(capabilities.allows_204());
        assert!(capabilities.allows_206());
        assert!(capabilities.allowed_features().contains("TRAILERS"));
        assert_eq!(capabilities.options_ttl(), Some(Duration::from_secs(3600)));
        assert_eq!(capabilities.max_connections(), Some(64));
        assert_eq!(
            capabilities.service().map(Bytes::as_ref),
            Some(b"C-ICAP/0.6 echo service".as_slice()),
        );
        assert_eq!(
            capabilities.service_id().map(Bytes::as_ref),
            Some(b"echo".as_slice()),
        );
        assert_eq!(
            capabilities.date().map(Bytes::as_ref),
            Some(b"Wed, 20 Aug 2026 12:00:00 GMT".as_slice()),
        );
        assert_eq!(
            capabilities.transfer_rules().classify("unknown"),
            TransferDisposition::Preview
        );
        let tag = capabilities.service_tag().unwrap();
        let tag_start = tag.as_ptr() as usize;
        assert!(tag_start >= head_start && tag_start + tag.len() <= head_end);
        let extension = capabilities.methods().extensions().next().unwrap();
        let extension_start = extension.as_ptr() as usize;
        assert!(extension_start >= head_start && extension_start + extension.len() <= head_end);
        let transfer = capabilities
            .transfer_rules()
            .preview_extensions()
            .next()
            .unwrap();
        let transfer_start = transfer.as_ptr() as usize;
        assert!(transfer_start >= head_start && transfer_start + transfer.len() <= head_end);
        let feature = capabilities
            .allowed_features()
            .iter()
            .find(|feature| feature.eq_ignore_ascii_case(b"trailers"))
            .unwrap();
        let feature_start = feature.as_ptr() as usize;
        assert!(feature_start >= head_start && feature_start + feature.len() <= head_end);
    }

    #[test]
    fn public_parser_requires_a_successful_options_response() {
        let fields = [Header::new(header::ISTAG, b"\"tag\"").unwrap()];
        let wrong_method = Response::new(
            MethodKind::Respmod,
            ResponseLine::new(StatusCode::NO_MODIFICATION_NEEDED, b"No Content").unwrap(),
            &fields,
            None,
        )
        .unwrap();
        let error = ServiceCapabilities::from_options_response(
            wrong_method,
            None,
            4,
            false,
            OptionsValidation::Compatible,
        )
        .unwrap_err();
        assert_eq!(error, CapabilitiesError::InvalidResponse);
        assert_eq!(
            error.to_string(),
            "capability discovery requires a successful OPTIONS response"
        );

        let wrong_status = Response::new(
            MethodKind::Options,
            ResponseLine::new(StatusCode::NOT_FOUND, b"Not Found").unwrap(),
            &fields,
            None,
        )
        .unwrap();
        ServiceCapabilities::from_options_response(
            wrong_status,
            None,
            4,
            false,
            OptionsValidation::Compatible,
        )
        .unwrap_err();
    }

    #[test]
    fn combines_repeated_list_valued_fields() {
        let response = response(&[
            Header::new(header::METHODS, b"REQMOD").unwrap(),
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
            Header::new(header::PREVIEW, b"1024").unwrap(),
            Header::new(header::ALLOW, b"204").unwrap(),
            Header::new(header::ALLOW, b"trailers").unwrap(),
            Header::new(header::TRANSFER_PREVIEW, b"html").unwrap(),
            Header::new(header::TRANSFER_PREVIEW, b"*").unwrap(),
        ]);
        let capabilities =
            ServiceCapabilities::parse(response, None, 16, false, OptionsValidation::Strict)
                .unwrap();

        assert_eq!(
            capabilities.methods().support(MethodKind::Reqmod),
            MethodSupport::Supported
        );
        assert_eq!(
            capabilities.methods().support(MethodKind::Respmod),
            MethodSupport::Supported
        );
        assert!(capabilities.allows_204());
        assert!(capabilities.allowed_features().contains("trailers"));
        assert_eq!(
            capabilities.transfer_rules().classify("html"),
            TransferDisposition::Preview
        );
    }

    #[test]
    fn invalid_optional_metadata_only_disables_its_capability() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
        ]);
        let mut parsed = ParsedCapabilities::default();
        parsed.observe(header::METHODS, Bytes::from_static(b"RESPMOD"));
        parsed.observe(header::ISTAG, Bytes::from_static(b"\"tag\""));
        parsed.observe(header::PREVIEW, Bytes::from_static(b"bogus"));
        parsed.observe(
            header::OPTIONS_TTL,
            Bytes::from_static(b"18446744073709551616"),
        );
        parsed.observe(header::ALLOW, Bytes::from_static(b"204,,206"));
        parsed.observe(header::MAX_CONNECTIONS, Bytes::from_static(b"many"));
        parsed.observe(header::TRANSFER_PREVIEW, Bytes::from_static(b"*"));
        parsed.saw_encapsulated = true;
        let capabilities = parsed
            .finish(response.clone(), None, false, OptionsValidation::Compatible)
            .unwrap();

        assert_eq!(
            capabilities.methods().support(MethodKind::Respmod),
            MethodSupport::Supported
        );
        assert_eq!(capabilities.preview(), None);
        assert_eq!(capabilities.options_ttl(), None);
        assert_eq!(capabilities.cache_lifetime(), Some(Duration::ZERO));
        assert_eq!(capabilities.max_connections(), None);
        assert!(!capabilities.allowed_features().is_valid());
        assert!(!capabilities.allows_204());
        assert!(!capabilities.transfer_rules().is_valid());

        let mut strict = ParsedCapabilities::default();
        strict.observe(header::METHODS, Bytes::from_static(b"RESPMOD"));
        strict.observe(header::ISTAG, Bytes::from_static(b"\"tag\""));
        strict.observe(header::PREVIEW, Bytes::from_static(b"bogus"));
        strict.saw_encapsulated = true;
        strict
            .finish(response, None, false, OptionsValidation::Strict)
            .unwrap_err();
    }

    #[test]
    fn invalid_feature_lists_never_advertise_retained_tokens() {
        let mut features = AllowedFeatures::default();
        features.tokens.push(Bytes::from_static(b"204"));
        features.valid = false;

        assert!(!features.contains("204"));
        assert!(!features.contains("trailers"));
    }

    #[test]
    fn token_whitespace_is_trimmed_on_both_sides() {
        assert_eq!(trim_ascii(b" \tvalue \t"), b"value");
        assert_eq!(trim_ascii(b"value"), b"value");
    }

    #[test]
    fn strict_validation_rejects_each_invalid_capability_independently() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
        ]);
        let base = || {
            let mut parsed = ParsedCapabilities::default();
            parsed.observe(header::METHODS, Bytes::from_static(b"RESPMOD"));
            parsed.observe(header::ISTAG, Bytes::from_static(b"\"tag\""));
            parsed.saw_encapsulated = true;
            parsed
        };
        let assert_rejected = |parsed: ParsedCapabilities| {
            parsed
                .finish(response.clone(), None, false, OptionsValidation::Strict)
                .unwrap_err();
        };

        let mut parsed = ParsedCapabilities::default();
        parsed.observe(header::METHODS, Bytes::from_static(b"RESPMOD"));
        parsed.saw_encapsulated = true;
        assert_rejected(parsed);

        let mut parsed = base();
        parsed.saw_encapsulated = false;
        assert_rejected(parsed);

        let mut parsed = base();
        parsed.observe(header::PREVIEW, Bytes::from_static(b"bogus"));
        assert_rejected(parsed);

        let mut parsed = base();
        parsed.observe(header::ALLOW, Bytes::from_static(b"204,,206"));
        assert_rejected(parsed);

        let mut parsed = base();
        parsed.observe(header::TRANSFER_PREVIEW, Bytes::from_static(b"*"));
        parsed.observe(header::TRANSFER_IGNORE, Bytes::from_static(b"*"));
        assert_rejected(parsed);

        let mut parsed = base();
        parsed.observe(header::OPTIONS_TTL, Bytes::from_static(b"bogus"));
        assert_rejected(parsed);

        let mut parsed = base();
        parsed.observe(header::MAX_CONNECTIONS, Bytes::from_static(b"bogus"));
        assert_rejected(parsed);

        let mut parsed = base();
        parsed.observe(header::SERVICE, Bytes::from_static(b"same"));
        parsed.observe(header::SERVICE, Bytes::from_static(b"same"));
        assert_rejected(parsed);
    }

    #[test]
    fn folded_capability_values_are_normalized_with_single_spaces() {
        let bytes = Bytes::from_static(
            b"ICAP/1.0 200 OK\r\n\
              Methods: RESPMOD\r\n\
              ISTag: \"tag\"\r\n\
              Service: first\r\n second\r\n\
              Encapsulated: null-body=0\r\n\r\n",
        );
        let mut slots = [HeaderSlot::EMPTY; 8];
        let parser = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let response = Response::from_head_bytes(
            MethodKind::Options,
            bytes,
            &mut slots,
            parser,
            Some(crate::message::EncapsulatedParts::null()),
        )
        .unwrap();
        let capabilities =
            ServiceCapabilities::parse(response, None, 8, false, OptionsValidation::Compatible)
                .unwrap();

        assert_eq!(
            capabilities.service().map(Bytes::as_ref),
            Some(b"first second".as_slice())
        );
    }

    #[test]
    fn missing_methods_is_retained_but_never_cached() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
        ]);
        let mut parsed = ParsedCapabilities::default();
        parsed.observe(header::ISTAG, Bytes::from_static(b"\"tag\""));
        parsed.saw_encapsulated = true;

        let capabilities = parsed
            .finish(response, None, false, OptionsValidation::Compatible)
            .unwrap();
        assert_eq!(
            capabilities.methods().support(MethodKind::Respmod),
            MethodSupport::Unknown
        );
        assert_eq!(capabilities.cache_lifetime(), Some(Duration::ZERO));
    }

    #[test]
    fn partial_content_requires_the_client_offer() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
            Header::new(header::ALLOW, b"204, 206").unwrap(),
        ]);
        let capabilities =
            ServiceCapabilities::parse(response, None, 16, false, OptionsValidation::Compatible)
                .unwrap();

        assert!(capabilities.allows_204());
        assert!(!capabilities.allows_206());
    }

    #[test]
    fn compatible_methods_discard_illegal_options_member() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD, X-TRACE").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
        ]);
        let parsed = || {
            let mut parsed = ParsedCapabilities::default();
            parsed.observe(
                header::METHODS,
                Bytes::from_static(b"OPTIONS, RESPMOD, X-TRACE"),
            );
            parsed.observe(header::ISTAG, Bytes::from_static(b"\"tag\""));
            parsed.saw_encapsulated = true;
            parsed
        };
        let compatible = parsed()
            .finish(response.clone(), None, false, OptionsValidation::Compatible)
            .unwrap();

        assert_eq!(
            compatible.methods().support(MethodKind::Respmod),
            MethodSupport::Supported
        );
        assert_eq!(
            compatible.methods().supports_extension("X-TRACE"),
            MethodSupport::Supported
        );
        parsed()
            .finish(response, None, false, OptionsValidation::Strict)
            .unwrap_err();
    }

    #[test]
    fn strict_validation_requires_matching_optional_body_metadata() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
            Header::new(header::OPT_BODY_TYPE, b"opaque").unwrap(),
        ]);

        ServiceCapabilities::parse(response, None, 16, false, OptionsValidation::Strict)
            .unwrap_err();
    }

    #[test]
    fn valid_optional_body_metadata_and_debug_summary_are_retained() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
            Header::new(header::OPT_BODY_TYPE, b"opaque").unwrap(),
        ]);
        let body = Bytes::from_static(b"options-body");
        let capabilities = ServiceCapabilities::parse(
            response,
            Some(body.clone()),
            16,
            false,
            OptionsValidation::Strict,
        )
        .unwrap();

        assert_eq!(
            capabilities.opt_body_type().map(Bytes::as_ref),
            Some(b"opaque".as_slice())
        );
        assert_eq!(capabilities.opt_body(), Some(&body));
        assert!(format!("{capabilities:?}").contains("ServiceCapabilities"));
    }

    #[test]
    fn invalid_optional_body_type_is_rejected_or_quarantined() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
            Header::new(header::OPT_BODY_TYPE, b"not a token").unwrap(),
        ]);
        let body = Bytes::from_static(b"opaque");

        let compatible = ServiceCapabilities::parse(
            response.clone(),
            Some(body.clone()),
            16,
            false,
            OptionsValidation::Compatible,
        )
        .unwrap();
        assert_eq!(compatible.opt_body_type(), None);
        assert_eq!(compatible.opt_body(), None);
        ServiceCapabilities::parse(response, Some(body), 16, false, OptionsValidation::Strict)
            .unwrap_err();
    }

    #[test]
    fn strict_validation_rejects_repeated_singletons() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
        ]);
        let mut parsed = ParsedCapabilities::default();
        parsed.observe(header::METHODS, Bytes::from_static(b"RESPMOD"));
        parsed.observe(header::ISTAG, Bytes::from_static(b"\"tag\""));
        parsed.observe(header::SERVICE, Bytes::from_static(b"same"));
        parsed.observe(header::SERVICE, Bytes::from_static(b"same"));
        parsed.saw_encapsulated = true;

        parsed
            .finish(response, None, false, OptionsValidation::Strict)
            .unwrap_err();
    }

    #[test]
    fn strict_validation_accepts_a_complete_options_response() {
        let response = response(&[
            Header::new(header::METHODS, b"RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"tag\"").unwrap(),
        ]);

        ServiceCapabilities::parse(response, None, 16, false, OptionsValidation::Strict).unwrap();
    }

    #[test]
    fn singleton_and_method_cardinality_are_explicit() {
        let mut singleton = Singleton::default();
        assert!(singleton.is_single());
        singleton.observe(Bytes::from_static(b"first"));
        assert!(singleton.is_single());
        singleton.observe(Bytes::from_static(b"first"));
        assert!(!singleton.is_single());

        let (methods, valid) = parse_methods(&[]);
        assert!(!valid);
        assert!(!methods.available);

        let (methods, valid) = parse_methods(&[Bytes::from_static(b"X-TRACE, X-TRACE")]);
        assert!(valid);
        assert_eq!(methods.extensions().len(), 1);
        assert_eq!(methods.extensions().next().unwrap().as_ref(), b"X-TRACE");
    }

    #[test]
    fn large_capability_lists_are_sorted_and_deduplicated() {
        let list = (0..4_000)
            .map(|index| format!("X-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let methods_value = Bytes::from(list.clone());
        let (methods, valid) = parse_methods(&[methods_value]);
        assert!(valid);
        assert_eq!(methods.extensions().len(), 4_000);
        assert_eq!(
            methods.supports_extension("X-3999"),
            MethodSupport::Supported
        );

        let allow_value = Bytes::from(list);
        let allow = parse_allow(&[allow_value]);
        assert!(allow.is_valid());
        assert_eq!(allow.iter().len(), 4_000);
        assert!(allow.contains("x-3999"));

        let rules = parse_transfer(
            &[Bytes::from_static(b"*")],
            &[Bytes::from_static(b"gif, GIF")],
            &[Bytes::from_static(b"zip, ZIP")],
            true,
        );
        assert!(rules.is_valid());
        assert_eq!(rules.ignored_extensions().len(), 1);
        assert_eq!(rules.complete_extensions().len(), 1);
    }

    #[test]
    fn compatible_unquoted_service_tags_keep_the_rfc_length_bound() {
        assert!(valid_service_tag(
            &Bytes::from_static(b"12345678901234567890123456789012"),
            OptionsValidation::Compatible,
        ));
        assert!(!valid_service_tag(
            &Bytes::from_static(b"123456789012345678901234567890123"),
            OptionsValidation::Compatible,
        ));
    }

    #[test]
    fn invalid_or_conflicting_service_tags_disable_caching() {
        for tags in [
            [Some(b"invalid service tag".as_slice()), None],
            [
                Some(b"\"first\"".as_slice()),
                Some(b"\"second\"".as_slice()),
            ],
        ] {
            let response = response(&[
                Header::new(header::METHODS, b"RESPMOD").unwrap(),
                Header::new(header::ISTAG, b"\"wire-tag\"").unwrap(),
            ]);
            let mut parsed = ParsedCapabilities::default();
            parsed.observe(header::METHODS, Bytes::from_static(b"RESPMOD"));
            for tag in tags.into_iter().flatten() {
                parsed.observe(header::ISTAG, Bytes::copy_from_slice(tag));
            }
            parsed.saw_encapsulated = true;

            let capabilities = parsed
                .finish(response, None, false, OptionsValidation::Compatible)
                .unwrap();
            assert_eq!(capabilities.service_tag(), None);
            assert_eq!(capabilities.cache_lifetime(), Some(Duration::ZERO));
        }
    }

    #[test]
    fn conflicting_and_overlapping_rules_degrade_conservatively() {
        let rules = parse_transfer(
            &[Bytes::from_static(b"jpg, *")],
            &[Bytes::from_static(b"JPG")],
            &[],
            true,
        );
        assert!(!rules.is_valid());
        assert_eq!(rules.classify("jpg"), TransferDisposition::Complete);
    }

    #[test]
    fn transfer_rules_validate_wildcards_preview_and_empty_members() {
        let rules = parse_transfer(
            &[Bytes::from_static(b"jpg, *")],
            &[Bytes::from_static(b"gif")],
            &[Bytes::from_static(b"zip")],
            true,
        );
        assert!(rules.is_valid());
        assert_eq!(
            rules.preview_extensions().collect::<Vec<_>>(),
            [b"jpg".as_slice()]
        );
        assert_eq!(rules.classify("unknown"), TransferDisposition::Preview);
        assert_eq!(rules.classify("gif"), TransferDisposition::Ignore);
        assert_eq!(rules.classify("zip"), TransferDisposition::Complete);

        let missing_preview = parse_transfer(&[Bytes::from_static(b"jpg, *")], &[], &[], false);
        assert!(!missing_preview.is_valid());
        let preview_member_without_preview = parse_transfer(
            &[Bytes::from_static(b"jpg")],
            &[],
            &[Bytes::from_static(b"*")],
            false,
        );
        assert!(!preview_member_without_preview.is_valid());

        let empty_member = parse_transfer(&[Bytes::from_static(b"jpg,, *")], &[], &[], true);
        assert!(!empty_member.is_valid());
    }
}
