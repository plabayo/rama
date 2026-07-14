use std::ops::{Deref, DerefMut};

use ahash::HashMap;

use crate::types::protos::KeyValue;

#[derive(Default, Clone, Debug)]
pub struct Metadata(HashMap<String, Vec<String>>);

impl Deref for Metadata {
    type Target = HashMap<String, Vec<String>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Metadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K: ToString, V: ToString> From<&(K, V)> for KeyValue {
    fn from(value: &(K, V)) -> Self {
        Self {
            key: value.0.to_string(),
            value: value.1.to_string(),
        }
    }
}

impl From<&Self> for KeyValue {
    fn from(value: &Self) -> Self {
        value.clone()
    }
}

impl<T, const N: usize> From<[T; N]> for Metadata
where
    for<'a> &'a T: Into<KeyValue>,
{
    fn from(value: [T; N]) -> Self {
        value.as_slice().into()
    }
}

impl<T, const N: usize> From<&[T; N]> for Metadata
where
    for<'a> &'a T: Into<KeyValue>,
{
    fn from(value: &[T; N]) -> Self {
        value.as_slice().into()
    }
}

impl<T> From<&[T]> for Metadata
where
    for<'a> &'a T: Into<KeyValue>,
{
    fn from(metadata: &[T]) -> Self {
        let mut map: HashMap<String, Vec<String>> = HashMap::default();
        for kv in metadata {
            let KeyValue { key, value } = kv.into();
            map.entry(key).or_default().push(value);
        }
        Self(map)
    }
}

impl From<Metadata> for Vec<KeyValue> {
    fn from(metadata: Metadata) -> Self {
        metadata.keyvalue_iter().collect()
    }
}

impl From<HashMap<String, Vec<String>>> for Metadata {
    fn from(metadata: HashMap<String, Vec<String>>) -> Self {
        Self(metadata)
    }
}

impl From<Option<HashMap<String, Vec<String>>>> for Metadata {
    fn from(metadata: Option<HashMap<String, Vec<String>>>) -> Self {
        Self(metadata.unwrap_or_default())
    }
}

impl Metadata {
    pub(crate) fn keyvalue_iter(&self) -> impl '_ + Iterator<Item = KeyValue> {
        self.0.iter().flat_map(|(k, v)| {
            v.iter().map(|v| KeyValue {
                key: k.clone(),
                value: v.clone(),
            })
        })
    }
}
