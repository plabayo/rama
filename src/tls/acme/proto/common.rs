use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
/// Represent an identifier in an ACME order
pub enum Identifier {
    Dns(String),
}

impl From<Identifier> for String {
    fn from(identifier: Identifier) -> Self {
        match identifier {
            Identifier::Dns(value) => value,
        }
    }
}
