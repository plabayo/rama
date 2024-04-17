use serde::{Deserialize, Serialize};

use super::StringFilter;

#[derive(Debug, Clone, Hash)]
/// A filter wrapper around another filter to allow for being able to match any value.
pub enum AnyOr<T> {
    /// Matches any value.
    Any,
    /// A specific value.
    Specific(T),
}

impl<T> PartialEq for AnyOr<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AnyOr::Any, _) => true,
            (_, AnyOr::Any) => true,
            (AnyOr::Specific(a), AnyOr::Specific(b)) => a == b,
        }
    }
}

impl<T> Eq for AnyOr<T> where T: Eq {}

impl<T> PartialEq<T> for AnyOr<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &T) -> bool {
        match self {
            AnyOr::Any => true,
            AnyOr::Specific(value) => value == other,
        }
    }
}

impl<T: std::fmt::Display> std::fmt::Display for AnyOr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnyOr::Any => write!(f, "Any(*)"),
            AnyOr::Specific(value) => write!(f, "Specific({})", value),
        }
    }
}

impl From<StringFilter> for AnyOr<StringFilter> {
    fn from(value: StringFilter) -> Self {
        if value.as_ref() == "*" {
            AnyOr::Any
        } else {
            AnyOr::Specific(value)
        }
    }
}

impl Serialize for AnyOr<StringFilter> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AnyOr::Any => "*".serialize(serializer),
            AnyOr::Specific(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AnyOr<StringFilter> {
    fn deserialize<D>(deserializer: D) -> Result<AnyOr<StringFilter>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = StringFilter::deserialize(deserializer)?;
        Ok(value.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_any_or() {
        type AnyOr = super::AnyOr<i32>;

        assert_eq!(AnyOr::Any, AnyOr::Any);
        assert_eq!(AnyOr::Any, AnyOr::Specific(1));
        assert_eq!(AnyOr::Specific(1), AnyOr::Any);
        assert_eq!(AnyOr::Specific(1), AnyOr::Specific(1));
        assert_ne!(AnyOr::Specific(1), AnyOr::Specific(2));
    }

    #[test]
    fn display_any_or() {
        type AnyOr = super::AnyOr<i32>;

        assert_eq!(AnyOr::Any.to_string(), "Any(*)");
        assert_eq!(AnyOr::Specific(1).to_string(), "Specific(1)");
    }

    #[test]
    fn serialize_any_str_filter_or() {
        let any = AnyOr::Any;
        let specific = AnyOr::Specific(StringFilter::new("test"));

        assert_eq!(serde_json::to_string(&any).unwrap(), "\"*\"");
        assert_eq!(serde_json::to_string(&specific).unwrap(), "\"test\"");
    }

    #[test]
    fn deserialize_any_str_filter_or() {
        let any = "\"*\"";
        let specific = "\"test\"";

        assert_eq!(
            serde_json::from_str::<AnyOr<StringFilter>>(any).unwrap(),
            AnyOr::Any
        );
        assert_eq!(
            serde_json::from_str::<AnyOr<StringFilter>>(specific).unwrap(),
            AnyOr::Specific(StringFilter::new("test"))
        );
    }

    #[test]
    fn partial_eq_any_str_filter() {
        let test = StringFilter::new("test");
        let any: AnyOr<_> = StringFilter::from("*").into();
        assert_eq!(any, test);
    }
}
