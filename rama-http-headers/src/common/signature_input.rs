//! `Signature-Input` typed header (RFC 9421 §4.1).
//!
//! A Structured Fields Dictionary of label → Inner List of covered components
//! plus signature parameters (`created`, `expires`, `keyid`, `alg`, …).

use rama_http_types::{HeaderName, HeaderValue};

use crate::util::structured_fields::{
    BareItem, Dictionary, DictionaryMember, InnerList, Item, ParameterValue, Parameters,
    parse_dictionary, serialize_dictionary,
};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// A single signature's metadata from `Signature-Input`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureParams {
    /// Ordered covered component identifiers (as SF strings, e.g. `"@method"`).
    pub components: Vec<ComponentIdentifier>,
    /// Signature parameters (`created`, `keyid`, `alg`, …).
    pub parameters: SignatureParameters,
}

/// A covered component identifier with optional component parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentIdentifier {
    /// Component name, e.g. `@method` or `content-digest`.
    pub name: String,
    /// Component-level parameters (`sf`, `bs`, `tr`, `key`, `req`, `name`, …).
    pub parameters: Parameters,
}

impl ComponentIdentifier {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parameters: Parameters::default(),
        }
    }

    #[must_use]
    pub fn with_parameters(mut self, parameters: Parameters) -> Self {
        self.parameters = parameters;
        self
    }

    /// Serialize as used in the signature base / Signature-Input (quoted name + params).
    #[must_use]
    pub fn serialize_identifier(&self) -> String {
        let item = Item {
            bare: BareItem::String(self.name.clone()),
            parameters: self.parameters.clone(),
        };
        let mut out = String::new();
        // Reuse dictionary item serialization via a tiny helper path:
        // build a one-item inner list serialization manually
        serialize_component_item(&mut out, &item);
        out
    }
}

fn serialize_component_item(out: &mut String, item: &Item) {
    match &item.bare {
        BareItem::String(s) => {
            out.push('"');
            for c in s.chars() {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
        other => {
            // Component identifiers must be strings per RFC 9421
            let _ = other;
            out.push_str("\"\"");
        }
    }
    for p in &item.parameters.params {
        out.push(';');
        out.push_str(&p.name);
        match &p.value {
            ParameterValue::Boolean(true) => {}
            ParameterValue::Boolean(false) => out.push_str("=?0"),
            ParameterValue::String(s) => {
                out.push_str("=\"");
                for c in s.chars() {
                    if c == '"' || c == '\\' {
                        out.push('\\');
                    }
                    out.push(c);
                }
                out.push('"');
            }
            ParameterValue::Token(t) => {
                out.push('=');
                out.push_str(t);
            }
            ParameterValue::Integer(n) => {
                out.push('=');
                out.push_str(&n.to_string());
            }
            ParameterValue::Decimal {
                negative,
                integer,
                fraction,
                fraction_digits,
            } => {
                out.push('=');
                if *negative {
                    out.push('-');
                }
                out.push_str(&integer.to_string());
                out.push('.');
                let width = usize::from(*fraction_digits);
                out.push_str(&format!("{fraction:0width$}"));
            }
            ParameterValue::ByteSequence(bytes) => {
                use base64::Engine as _;
                out.push_str("=:");
                out.push_str(&base64::engine::general_purpose::STANDARD.encode(bytes));
                out.push(':');
            }
            ParameterValue::Date(n) => {
                out.push('=');
                out.push('@');
                out.push_str(&n.to_string());
            }
            ParameterValue::DisplayString(s) => {
                out.push_str("=%\"");
                // RFC 9651 §4.1.11: encode %x22 / %x25 / non-ldash-char with lc-hexdig.
                for b in s.as_bytes() {
                    match *b {
                        0x20..=0x21 | 0x23..=0x24 | 0x26..=0x5b | 0x5d..=0x7e => {
                            out.push(*b as char);
                        }
                        _ => {
                            const LC_HEX: &[u8; 16] = b"0123456789abcdef";
                            out.push('%');
                            out.push(char::from(LC_HEX[(b >> 4) as usize]));
                            out.push(char::from(LC_HEX[(b & 0xf) as usize]));
                        }
                    }
                }
                out.push('"');
            }
        }
    }
}

/// Signature-level parameters from the Inner List.
#[derive(Debug, Clone, Default)]
pub struct SignatureParameters {
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
    pub alg: Option<String>,
    pub keyid: Option<String>,
    pub tag: Option<String>,
    /// Any additional / unrecognized parameters, preserved for round-trip.
    pub extra: Parameters,
    /// Exact SF parameter order from the wire. When set, serialization uses this
    /// instead of reconstructing from the typed fields (RFC 9421 verification
    /// requires `@signature-params` to match the received `Signature-Input` member).
    wire_order: Option<Parameters>,
}

impl PartialEq for SignatureParameters {
    fn eq(&self, other: &Self) -> bool {
        self.created == other.created
            && self.expires == other.expires
            && self.nonce == other.nonce
            && self.alg == other.alg
            && self.keyid == other.keyid
            && self.tag == other.tag
            && self.extra == other.extra
    }
}

impl Eq for SignatureParameters {}

impl SignatureParameters {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn from_sf(params: &Parameters) -> Result<Self, Error> {
        let mut out = Self {
            wire_order: Some(params.clone()),
            ..Self::default()
        };
        for p in &params.params {
            match p.name.as_str() {
                "created" => match &p.value {
                    ParameterValue::Integer(n) => out.created = Some(*n),
                    _ => return Err(Error::invalid()),
                },
                "expires" => match &p.value {
                    ParameterValue::Integer(n) => out.expires = Some(*n),
                    _ => return Err(Error::invalid()),
                },
                "nonce" => match &p.value {
                    ParameterValue::String(s) => out.nonce = Some(s.clone()),
                    _ => return Err(Error::invalid()),
                },
                "alg" => match &p.value {
                    ParameterValue::String(s) => out.alg = Some(s.clone()),
                    _ => return Err(Error::invalid()),
                },
                "keyid" => match &p.value {
                    ParameterValue::String(s) => out.keyid = Some(s.clone()),
                    _ => return Err(Error::invalid()),
                },
                "tag" => match &p.value {
                    ParameterValue::String(s) => out.tag = Some(s.clone()),
                    _ => return Err(Error::invalid()),
                },
                _ => out.extra.params.push(p.clone()),
            }
        }
        Ok(out)
    }

    fn to_sf(&self) -> Parameters {
        if let Some(ref ordered) = self.wire_order {
            return ordered.clone();
        }
        let mut params = Parameters::new();
        // Stable order for freshly constructed parameters (signing path).
        if let Some(n) = self.created {
            params.insert("created", ParameterValue::Integer(n));
        }
        if let Some(n) = self.expires {
            params.insert("expires", ParameterValue::Integer(n));
        }
        if let Some(ref s) = self.nonce {
            params.insert("nonce", ParameterValue::String(s.clone()));
        }
        if let Some(ref s) = self.alg {
            params.insert("alg", ParameterValue::String(s.clone()));
        }
        if let Some(ref s) = self.keyid {
            params.insert("keyid", ParameterValue::String(s.clone()));
        }
        if let Some(ref s) = self.tag {
            params.insert("tag", ParameterValue::String(s.clone()));
        }
        for p in &self.extra.params {
            params.params.push(p.clone());
        }
        params
    }
}

/// The `Signature-Input` header field (RFC 9421).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignatureInput {
    /// Ordered (label, params) entries.
    entries: Vec<(String, SignatureParams)>,
}

impl SignatureInput {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, label: impl Into<String>, params: SignatureParams) {
        let label = label.into();
        if let Some((_, existing)) = self.entries.iter_mut().find(|(k, _)| *k == label) {
            *existing = params;
        } else {
            self.entries.push((label, params));
        }
    }

    pub fn get(&self, label: &str) -> Option<&SignatureParams> {
        self.entries
            .iter()
            .find(|(k, _)| k == label)
            .map(|(_, v)| v)
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &SignatureParams)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize the Signature-Input member value for a label (used as `@signature-params`).
    ///
    /// This is the Inner List serialization *without* the label key, matching RFC 9421 §2.3.
    pub fn serialize_signature_params(&self, label: &str) -> Option<String> {
        let params = self.get(label)?;
        Some(serialize_signature_params_value(params))
    }
}

/// Serialize a [`SignatureParams`] value as it appears in `Signature-Input` / `@signature-params`.
#[must_use]
pub fn serialize_signature_params_value(params: &SignatureParams) -> String {
    let items: Vec<Item> = params
        .components
        .iter()
        .map(|c| Item {
            bare: BareItem::String(c.name.clone()),
            parameters: c.parameters.clone(),
        })
        .collect();
    let list = InnerList {
        items,
        parameters: params.parameters.to_sf(),
    };
    let mut dict = Dictionary::new();
    // Use a throwaway key then strip it — serialize just the value part
    dict.insert("_", DictionaryMember::InnerList(list));
    let full = serialize_dictionary(&dict);
    // full is `_=(...);...` — strip the `_=` prefix
    full.strip_prefix("_=").unwrap_or(&full).to_owned()
}

fn params_from_inner_list(list: &InnerList) -> Result<SignatureParams, Error> {
    let mut components = Vec::with_capacity(list.items.len());
    for item in &list.items {
        let BareItem::String(name) = &item.bare else {
            return Err(Error::invalid());
        };
        components.push(ComponentIdentifier {
            name: name.clone(),
            parameters: item.parameters.clone(),
        });
    }
    Ok(SignatureParams {
        components,
        parameters: SignatureParameters::from_sf(&list.parameters)?,
    })
}

impl TypedHeader for SignatureInput {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::SIGNATURE_INPUT
    }
}

impl HeaderDecode for SignatureInput {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let mut entries = Vec::new();
        let mut any = false;
        for value in values {
            any = true;
            let s = value.to_str().map_err(|_err| Error::invalid())?;
            let dict = parse_dictionary(s).map_err(|_err| Error::invalid())?;
            for (key, member) in dict.members {
                let DictionaryMember::InnerList(list) = member else {
                    return Err(Error::invalid());
                };
                if entries.iter().any(|(k, _)| k == &key) {
                    return Err(Error::invalid());
                }
                entries.push((key, params_from_inner_list(&list)?));
            }
        }
        if !any {
            return Err(Error::invalid());
        }
        Ok(Self { entries })
    }
}

impl HeaderEncode for SignatureInput {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let mut dict = Dictionary::new();
        for (label, params) in &self.entries {
            let items: Vec<Item> = params
                .components
                .iter()
                .map(|c| Item {
                    bare: BareItem::String(c.name.clone()),
                    parameters: c.parameters.clone(),
                })
                .collect();
            dict.insert(
                label.clone(),
                DictionaryMember::InnerList(InnerList {
                    items,
                    parameters: params.parameters.to_sf(),
                }),
            );
        }
        let s = serialize_dictionary(&dict);
        if let Ok(value) = HeaderValue::from_str(&s) {
            values.extend(std::iter::once(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn decode_rfc_example() {
        let input = r#"sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256""#;
        let hdr = test_decode::<SignatureInput>(&[input]).unwrap();
        let params = hdr.get("sig1").unwrap();
        assert_eq!(params.components.len(), 6);
        assert_eq!(params.components[0].name, "@method");
        assert_eq!(params.components[3].name, "content-digest");
        assert_eq!(params.parameters.created, Some(1618884475));
        assert_eq!(
            params.parameters.keyid.as_deref(),
            Some("test-key-ecc-p256")
        );
    }

    #[test]
    fn round_trip() {
        let mut hdr = SignatureInput::new();
        hdr.insert(
            "sig1",
            SignatureParams {
                components: vec![
                    ComponentIdentifier::new("@method"),
                    ComponentIdentifier::new("@path"),
                ],
                parameters: SignatureParameters {
                    created: Some(1618884475),
                    keyid: Some("test-key".into()),
                    alg: Some("ed25519".into()),
                    expires: None,
                    nonce: None,
                    tag: None,
                    extra: Parameters::default(),
                    wire_order: None,
                },
            },
        );
        let map = test_encode(hdr.clone());
        let value = map.get(SignatureInput::name()).unwrap().to_str().unwrap();
        let decoded = test_decode::<SignatureInput>(&[value]).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn serialize_signature_params_preserves_wire_order() {
        let input = r#"sig1=("@method" "@path");keyid="test-key";created=1618884475;alg="ed25519""#;
        let hdr = test_decode::<SignatureInput>(&[input]).unwrap();
        let serialized = hdr.serialize_signature_params("sig1").unwrap();
        assert_eq!(
            serialized,
            r#"("@method" "@path");keyid="test-key";created=1618884475;alg="ed25519""#
        );
    }

    #[test]
    fn serialize_signature_params_matches_member_value() {
        let input =
            r#"sig1=("@method" "@authority" "@path");created=1618884475;keyid="test-key-ecc-p256""#;
        let hdr = test_decode::<SignatureInput>(&[input]).unwrap();
        let serialized = hdr.serialize_signature_params("sig1").unwrap();
        assert_eq!(
            serialized,
            r#"("@method" "@authority" "@path");created=1618884475;keyid="test-key-ecc-p256""#
        );
    }

    #[test]
    fn reject_alg_as_token_and_wrong_created_type() {
        assert!(test_decode::<SignatureInput>(&[r#"sig1=("@method");alg=ed25519"#]).is_none());
        assert!(
            test_decode::<SignatureInput>(&[r#"sig1=("@method");created="1618884475""#]).is_none()
        );
    }

    #[test]
    fn multi_label() {
        let input =
            r#"sig1=("@method");created=1, proxy_sig=("@method" "forwarded");created=2;keyid="p""#;
        let hdr = test_decode::<SignatureInput>(&[input]).unwrap();
        assert_eq!(hdr.len(), 2);
        assert!(hdr.get("sig1").is_some());
        assert!(hdr.get("proxy_sig").is_some());
    }
}
