//! Structured field value types (RFC 9651 subset).

use std::fmt;

/// A Structured Fields Dictionary (ordered members).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dictionary {
    pub members: Vec<(String, DictionaryMember)>,
}

impl Dictionary {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&DictionaryMember> {
        self.members.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn insert(&mut self, key: impl Into<String>, value: DictionaryMember) {
        let key = key.into();
        if let Some((_, existing)) = self.members.iter_mut().find(|(k, _)| *k == key) {
            *existing = value;
        } else {
            self.members.push((key, value));
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|(k, _)| k.as_str())
    }
}

/// A Dictionary member value: either an Item or an Inner List.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictionaryMember {
    Item(Item),
    InnerList(InnerList),
}

/// An Inner List: ordered Items plus list-level Parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InnerList {
    pub items: Vec<Item>,
    pub parameters: Parameters,
}

impl InnerList {
    #[must_use]
    pub fn new(items: Vec<Item>) -> Self {
        Self {
            items,
            parameters: Parameters::default(),
        }
    }

    #[must_use]
    pub fn with_parameters(mut self, parameters: Parameters) -> Self {
        self.parameters = parameters;
        self
    }
}

/// An Item: bare item plus parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub bare: BareItem,
    pub parameters: Parameters,
}

impl Item {
    #[must_use]
    pub fn new(bare: BareItem) -> Self {
        Self {
            bare,
            parameters: Parameters::default(),
        }
    }

    #[must_use]
    pub fn with_parameters(mut self, parameters: Parameters) -> Self {
        self.parameters = parameters;
        self
    }

    #[must_use]
    pub fn string(s: impl Into<String>) -> Self {
        Self::new(BareItem::String(s.into()))
    }

    #[must_use]
    pub fn token(s: impl Into<String>) -> Self {
        Self::new(BareItem::Token(s.into()))
    }

    #[must_use]
    pub fn byte_sequence(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(BareItem::ByteSequence(bytes.into()))
    }

    #[must_use]
    pub fn integer(n: i64) -> Self {
        Self::new(BareItem::Integer(n))
    }

    #[must_use]
    pub fn boolean(b: bool) -> Self {
        Self::new(BareItem::Boolean(b))
    }
}

/// Bare item kinds used by this subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareItem {
    String(String),
    Token(String),
    ByteSequence(Vec<u8>),
    Integer(i64),
    Boolean(bool),
}

/// Ordered parameters attached to an Item or Inner List.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Parameters {
    pub params: Vec<Parameter>,
}

impl Parameters {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&ParameterValue> {
        self.params
            .iter()
            .find(|p| p.name == name)
            .map(|p| &p.value)
    }

    pub fn insert(&mut self, name: impl Into<String>, value: ParameterValue) {
        let name = name.into();
        if let Some(existing) = self.params.iter_mut().find(|p| p.name == name) {
            existing.value = value;
        } else {
            self.params.push(Parameter { name, value });
        }
    }

    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: ParameterValue) -> Self {
        self.insert(name, value);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }
}

/// A single parameter (`name` or `name=value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    pub name: String,
    pub value: ParameterValue,
}

/// Parameter values (boolean true when bare flag with no `=`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterValue {
    Boolean(bool),
    String(String),
    Token(String),
    Integer(i64),
    ByteSequence(Vec<u8>),
}

impl fmt::Display for BareItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Token(t) => write!(f, "{t}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Boolean(true) => write!(f, "?1"),
            Self::Boolean(false) => write!(f, "?0"),
            Self::ByteSequence(_) => write!(f, ":…:"),
        }
    }
}
