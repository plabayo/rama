use serde::{
    Deserializer,
    de::{self, DeserializeSeed, EnumAccess, Error, MapAccess, SeqAccess, VariantAccess, Visitor},
    forward_to_deserialize_any,
};
use std::{any::type_name, fmt};

// this wrapper type is used as the deserializer error to hide the `serde::de::Error` impl which
// would otherwise be public if we used `ErrorKind` as the error directly
#[derive(Debug)]
pub(crate) struct PathDeserializationError {
    pub(super) kind: ErrorKind,
}

impl PathDeserializationError {
    pub(super) fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    pub(super) fn wrong_number_of_parameters() -> WrongNumberOfParameters<()> {
        WrongNumberOfParameters { got: () }
    }

    #[track_caller]
    pub(super) fn unsupported_type(name: &'static str) -> Self {
        Self::new(ErrorKind::UnsupportedType { name })
    }
}

pub(super) struct WrongNumberOfParameters<G> {
    got: G,
}

impl<G> WrongNumberOfParameters<G> {
    #[allow(clippy::unused_self)]
    pub(super) fn got<G2>(self, got: G2) -> WrongNumberOfParameters<G2> {
        WrongNumberOfParameters { got }
    }
}

impl WrongNumberOfParameters<usize> {
    pub(super) fn expected(self, expected: usize) -> PathDeserializationError {
        PathDeserializationError::new(ErrorKind::WrongNumberOfParameters {
            got: self.got,
            expected,
        })
    }
}

impl serde::de::Error for PathDeserializationError {
    #[inline]
    fn custom<T>(msg: T) -> Self
    where
        T: fmt::Display,
    {
        Self {
            kind: ErrorKind::Message(msg.to_string()),
        }
    }
}

impl fmt::Display for PathDeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for PathDeserializationError {}

/// The kinds of errors that can happen we deserializing into a [`Path`].
///
/// This type is obtained through [`FailedToDeserializePathParams::kind`] or
/// [`FailedToDeserializePathParams::into_kind`] and is useful for building
/// more precise error messages.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub(crate) enum ErrorKind {
    /// The URI contained the wrong number of parameters.
    WrongNumberOfParameters {
        /// The number of actual parameters in the URI.
        got: usize,
        /// The number of expected parameters.
        expected: usize,
    },

    /// Failed to parse the value at a specific key into the expected type.
    ///
    /// This variant is used when deserializing into types that have named fields, such as structs.
    ParseErrorAtKey {
        /// The key at which the value was located.
        key: String,
        /// The value from the URI.
        value: String,
        /// The expected type of the value.
        expected_type: &'static str,
    },

    /// Failed to parse the value at a specific index into the expected type.
    ///
    /// This variant is used when deserializing into sequence types, such as tuples.
    ParseErrorAtIndex {
        /// The index at which the value was located.
        index: usize,
        /// The value from the URI.
        value: String,
        /// The expected type of the value.
        expected_type: &'static str,
    },

    /// Failed to parse a value into the expected type.
    ///
    /// This variant is used when deserializing into a primitive type (such as `String` and `u32`).
    ParseError {
        /// The value from the URI.
        value: String,
        /// The expected type of the value.
        expected_type: &'static str,
    },

    /// Tried to serialize into an unsupported type such as nested maps.
    ///
    /// This error kind is caused by programmer errors and thus gets converted into a `500 Internal
    /// Server Error` response.
    UnsupportedType {
        /// The name of the unsupported type.
        name: &'static str,
    },

    /// Catch-all variant for errors that don't fit any other variant.
    Message(String),

    /// No parameters were found.
    NoParams,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoParams => write!(f, "No parameters found"),
            Self::Message(error) => error.fmt(f),
            Self::WrongNumberOfParameters { got, expected } => {
                write!(
                    f,
                    "Wrong number of path arguments for `Path`. Expected {expected} but got {got}"
                )?;

                if *expected == 1 {
                    write!(
                        f,
                        ". Note that multiple parameters must be extracted with a tuple `Path<(_, _)>` or a struct `Path<YourParams>`"
                    )?;
                }

                Ok(())
            }
            Self::UnsupportedType { name } => write!(f, "Unsupported type `{name}`"),
            Self::ParseErrorAtKey {
                key,
                value,
                expected_type,
            } => write!(
                f,
                "Cannot parse `{key}` with value `{value:?}` to a `{expected_type}`"
            ),
            Self::ParseError {
                value,
                expected_type,
            } => write!(f, "Cannot parse `{value:?}` to a `{expected_type}`"),
            Self::ParseErrorAtIndex {
                index,
                value,
                expected_type,
            } => write!(
                f,
                "Cannot parse value at index {index} with value `{value:?}` to a `{expected_type}`"
            ),
        }
    }
}

macro_rules! unsupported_type {
    ($trait_fn:ident) => {
        fn $trait_fn<V>(self, _: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            Err(PathDeserializationError::unsupported_type(type_name::<
                V::Value,
            >()))
        }
    };
}

macro_rules! parse_single_value {
    ($trait_fn:ident, $visit_fn:ident, $ty:literal) => {
        fn $trait_fn<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            if self.uri_params.len() != 1 {
                return Err(PathDeserializationError::wrong_number_of_parameters()
                    .got(self.uri_params.len())
                    .expected(1));
            }

            let value = self.uri_params[0].1.parse().map_err(|_| {
                PathDeserializationError::new(ErrorKind::ParseError {
                    value: self.uri_params[0].1.to_owned(),
                    expected_type: $ty,
                })
            })?;
            visitor.$visit_fn(value)
        }
    };
}

pub(crate) struct PathDeserializer<'de> {
    uri_params: &'de [(&'de str, &'de str)],
}

impl<'de> PathDeserializer<'de> {
    #[inline]
    pub(crate) fn new(uri_params: &'de [(&'de str, &'de str)]) -> Self {
        PathDeserializer { uri_params }
    }
}

impl<'de> Deserializer<'de> for PathDeserializer<'de> {
    type Error = PathDeserializationError;

    unsupported_type!(deserialize_bytes);
    unsupported_type!(deserialize_option);
    unsupported_type!(deserialize_identifier);
    unsupported_type!(deserialize_ignored_any);

    parse_single_value!(deserialize_bool, visit_bool, "bool");
    parse_single_value!(deserialize_i8, visit_i8, "i8");
    parse_single_value!(deserialize_i16, visit_i16, "i16");
    parse_single_value!(deserialize_i32, visit_i32, "i32");
    parse_single_value!(deserialize_i64, visit_i64, "i64");
    parse_single_value!(deserialize_i128, visit_i128, "i128");
    parse_single_value!(deserialize_u8, visit_u8, "u8");
    parse_single_value!(deserialize_u16, visit_u16, "u16");
    parse_single_value!(deserialize_u32, visit_u32, "u32");
    parse_single_value!(deserialize_u64, visit_u64, "u64");
    parse_single_value!(deserialize_u128, visit_u128, "u128");
    parse_single_value!(deserialize_f32, visit_f32, "f32");
    parse_single_value!(deserialize_f64, visit_f64, "f64");
    parse_single_value!(deserialize_string, visit_string, "String");
    parse_single_value!(deserialize_byte_buf, visit_string, "String");
    parse_single_value!(deserialize_char, visit_char, "char");

    fn deserialize_any<V>(self, v: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(v)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.uri_params.len() != 1 {
            return Err(PathDeserializationError::wrong_number_of_parameters()
                .got(self.uri_params.len())
                .expected(1));
        }
        visitor.visit_borrowed_str(self.uri_params[0].1)
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(SeqDeserializer {
            params: self.uri_params,
            idx: 0,
        })
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.uri_params.len() < len {
            return Err(PathDeserializationError::wrong_number_of_parameters()
                .got(self.uri_params.len())
                .expected(len));
        }
        visitor.visit_seq(SeqDeserializer {
            params: self.uri_params,
            idx: 0,
        })
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.uri_params.len() < len {
            return Err(PathDeserializationError::wrong_number_of_parameters()
                .got(self.uri_params.len())
                .expected(len));
        }
        visitor.visit_seq(SeqDeserializer {
            params: self.uri_params,
            idx: 0,
        })
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(MapDeserializer {
            params: self.uri_params,
            value: None,
            key: None,
        })
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.uri_params.len() != 1 {
            return Err(PathDeserializationError::wrong_number_of_parameters()
                .got(self.uri_params.len())
                .expected(1));
        }

        visitor.visit_enum(EnumDeserializer {
            value: self.uri_params[0].1,
        })
    }
}

struct MapDeserializer<'de> {
    params: &'de [(&'de str, &'de str)],
    key: Option<KeyOrIdx<'de>>,
    value: Option<&'de str>,
}

impl<'de> MapAccess<'de> for MapDeserializer<'de> {
    type Error = PathDeserializationError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        match self.params.split_first() {
            Some(((key, value), tail)) => {
                self.value = Some(value);
                self.params = tail;
                self.key = Some(KeyOrIdx::Key(key));
                seed.deserialize(KeyDeserializer { key }).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        match self.value.take() {
            Some(value) => seed.deserialize(ValueDeserializer {
                key: self.key.take(),
                value,
            }),
            None => Err(PathDeserializationError::custom("value is missing")),
        }
    }
}

struct KeyDeserializer<'de> {
    key: &'de str,
}

macro_rules! parse_key {
    ($trait_fn:ident) => {
        fn $trait_fn<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            visitor.visit_str(&self.key)
        }
    };
}

impl<'de> Deserializer<'de> for KeyDeserializer<'de> {
    type Error = PathDeserializationError;

    parse_key!(deserialize_identifier);
    parse_key!(deserialize_str);
    parse_key!(deserialize_string);

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathDeserializationError::custom("Unexpected key type"))
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char bytes
        byte_buf option unit unit_struct seq tuple
        tuple_struct map newtype_struct struct enum ignored_any
    }
}

macro_rules! parse_value {
    ($trait_fn:ident, $visit_fn:ident, $ty:literal) => {
        fn $trait_fn<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            let v = self.value.parse().map_err(|_| {
                if let Some(key) = self.key.take() {
                    let kind = match key {
                        KeyOrIdx::Key(key) => ErrorKind::ParseErrorAtKey {
                            key: key.to_owned(),
                            value: self.value.to_owned(),
                            expected_type: $ty,
                        },
                        KeyOrIdx::Idx { idx: index, key: _ } => ErrorKind::ParseErrorAtIndex {
                            index,
                            value: self.value.to_owned(),
                            expected_type: $ty,
                        },
                    };
                    PathDeserializationError::new(kind)
                } else {
                    PathDeserializationError::new(ErrorKind::ParseError {
                        value: self.value.to_owned(),
                        expected_type: $ty,
                    })
                }
            })?;
            visitor.$visit_fn(v)
        }
    };
}

#[derive(Debug)]
struct ValueDeserializer<'de> {
    key: Option<KeyOrIdx<'de>>,
    value: &'de str,
}

impl<'de> Deserializer<'de> for ValueDeserializer<'de> {
    type Error = PathDeserializationError;

    unsupported_type!(deserialize_map);
    unsupported_type!(deserialize_identifier);

    parse_value!(deserialize_bool, visit_bool, "bool");
    parse_value!(deserialize_i8, visit_i8, "i8");
    parse_value!(deserialize_i16, visit_i16, "i16");
    parse_value!(deserialize_i32, visit_i32, "i32");
    parse_value!(deserialize_i64, visit_i64, "i64");
    parse_value!(deserialize_i128, visit_i128, "i128");
    parse_value!(deserialize_u8, visit_u8, "u8");
    parse_value!(deserialize_u16, visit_u16, "u16");
    parse_value!(deserialize_u32, visit_u32, "u32");
    parse_value!(deserialize_u64, visit_u64, "u64");
    parse_value!(deserialize_u128, visit_u128, "u128");
    parse_value!(deserialize_f32, visit_f32, "f32");
    parse_value!(deserialize_f64, visit_f64, "f64");
    parse_value!(deserialize_string, visit_string, "String");
    parse_value!(deserialize_byte_buf, visit_string, "String");
    parse_value!(deserialize_char, visit_char, "char");

    fn deserialize_any<V>(self, v: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(v)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.value)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_bytes(self.value.as_bytes())
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_some(self)
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        struct PairDeserializer<'de> {
            key: Option<KeyOrIdx<'de>>,
            value: Option<&'de str>,
        }

        impl<'de> SeqAccess<'de> for PairDeserializer<'de> {
            type Error = PathDeserializationError;

            fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
            where
                T: DeserializeSeed<'de>,
            {
                match self.key.take() {
                    Some(KeyOrIdx::Idx { idx: _, key }) => {
                        return seed.deserialize(KeyDeserializer { key }).map(Some);
                    }
                    // `KeyOrIdx::Key` is only used when deserializing maps so `deserialize_seq`
                    // wouldn't be called for that
                    Some(KeyOrIdx::Key(_)) => unreachable!(),
                    None => {}
                };

                self.value
                    .take()
                    .map(|value| seed.deserialize(ValueDeserializer { key: None, value }))
                    .transpose()
            }
        }

        if len == 2 {
            match self.key {
                Some(key) => visitor.visit_seq(PairDeserializer {
                    key: Some(key),
                    value: Some(self.value),
                }),
                // `self.key` is only `None` when deserializing maps so `deserialize_seq`
                // wouldn't be called for that
                None => unreachable!(),
            }
        } else {
            Err(PathDeserializationError::unsupported_type(type_name::<
                V::Value,
            >()))
        }
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathDeserializationError::unsupported_type(type_name::<
            V::Value,
        >()))
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathDeserializationError::unsupported_type(type_name::<
            V::Value,
        >()))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathDeserializationError::unsupported_type(type_name::<
            V::Value,
        >()))
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_enum(EnumDeserializer { value: self.value })
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

struct EnumDeserializer<'de> {
    value: &'de str,
}

impl<'de> EnumAccess<'de> for EnumDeserializer<'de> {
    type Error = PathDeserializationError;
    type Variant = UnitVariant;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: de::DeserializeSeed<'de>,
    {
        Ok((
            seed.deserialize(KeyDeserializer { key: self.value })?,
            UnitVariant,
        ))
    }
}

struct UnitVariant;

impl<'de> VariantAccess<'de> for UnitVariant {
    type Error = PathDeserializationError;

    fn unit_variant(self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        Err(PathDeserializationError::unsupported_type(
            "newtype enum variant",
        ))
    }

    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathDeserializationError::unsupported_type(
            "tuple enum variant",
        ))
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathDeserializationError::unsupported_type(
            "struct enum variant",
        ))
    }
}

struct SeqDeserializer<'de> {
    params: &'de [(&'de str, &'de str)],
    idx: usize,
}

impl<'de> SeqAccess<'de> for SeqDeserializer<'de> {
    type Error = PathDeserializationError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        match self.params.split_first() {
            Some(((key, value), tail)) => {
                self.params = tail;
                let idx = self.idx;
                self.idx += 1;
                Ok(Some(seed.deserialize(ValueDeserializer {
                    key: Some(KeyOrIdx::Idx { idx, key }),
                    value,
                })?))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone)]
enum KeyOrIdx<'de> {
    Key(&'de str),
    Idx { idx: usize, key: &'de str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashMap;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    enum MyEnum {
        A,
        B,
        #[serde(rename = "c")]
        C,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Struct {
        c: String,
        b: bool,
        a: i32,
    }

    fn create_url_params<'de, I>(values: I) -> Vec<(&'de str, &'de str)>
    where
        I: IntoIterator<Item = (&'de str, &'de str)>,
    {
        values.into_iter().collect()
    }

    macro_rules! check_single_value {
        ($ty:ty, $value_str:literal, $value:expr) => {
            #[allow(clippy::bool_assert_comparison)]
            {
                let uri_params = create_url_params(vec![("value", $value_str)]);
                let deserializer = PathDeserializer::new(&uri_params);
                assert_eq!(<$ty>::deserialize(deserializer).unwrap(), $value);
            }
        };
    }

    #[test]
    fn test_parse_single_value() {
        check_single_value!(bool, "true", true);
        check_single_value!(bool, "false", false);
        check_single_value!(i8, "-123", -123);
        check_single_value!(i16, "-123", -123);
        check_single_value!(i32, "-123", -123);
        check_single_value!(i64, "-123", -123);
        check_single_value!(i128, "123", 123);
        check_single_value!(u8, "123", 123);
        check_single_value!(u16, "123", 123);
        check_single_value!(u32, "123", 123);
        check_single_value!(u64, "123", 123);
        check_single_value!(u128, "123", 123);
        check_single_value!(f32, "123", 123.0);
        check_single_value!(f64, "123", 123.0);
        check_single_value!(String, "abc", "abc");
        check_single_value!(&str, "abc", "abc");
        check_single_value!(char, "a", 'a');

        let uri_params = create_url_params(vec![("a", "B")]);
        assert_eq!(
            MyEnum::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            MyEnum::B
        );

        let uri_params = create_url_params(vec![("a", "1"), ("b", "2")]);
        let error_kind = i32::deserialize(PathDeserializer::new(&uri_params))
            .unwrap_err()
            .kind;
        assert!(matches!(
            error_kind,
            ErrorKind::WrongNumberOfParameters {
                expected: 1,
                got: 2
            }
        ));
    }

    #[test]
    fn test_parse_seq() {
        let uri_params = create_url_params(vec![("a", "1"), ("b", "true"), ("c", "abc")]);
        assert_eq!(
            <(i32, bool, String)>::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            (1, true, "abc".to_owned())
        );

        #[derive(Debug, Deserialize, Eq, PartialEq)]
        struct TupleStruct(i32, bool, String);
        assert_eq!(
            TupleStruct::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            TupleStruct(1, true, "abc".to_owned())
        );

        let uri_params = create_url_params(vec![("a", "1"), ("b", "2"), ("c", "3")]);
        assert_eq!(
            <Vec<i32>>::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            vec![1, 2, 3]
        );

        let uri_params = create_url_params(vec![("a", "c"), ("a", "B")]);
        assert_eq!(
            <Vec<MyEnum>>::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            vec![MyEnum::C, MyEnum::B]
        );
    }

    #[test]
    fn test_parse_seq_tuple_string_string() {
        let uri_params = create_url_params(vec![("a", "foo"), ("b", "bar")]);
        assert_eq!(
            <Vec<(String, String)>>::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            vec![
                ("a".to_owned(), "foo".to_owned()),
                ("b".to_owned(), "bar".to_owned())
            ]
        );
    }

    #[test]
    fn test_parse_seq_tuple_string_parse() {
        let uri_params = create_url_params(vec![("a", "1"), ("b", "2")]);
        assert_eq!(
            <Vec<(String, u32)>>::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            vec![("a".to_owned(), 1), ("b".to_owned(), 2)]
        );
    }

    #[test]
    fn test_parse_struct() {
        let uri_params = create_url_params(vec![("a", "1"), ("b", "true"), ("c", "abc")]);
        assert_eq!(
            Struct::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            Struct {
                c: "abc".to_owned(),
                b: true,
                a: 1,
            }
        );
    }

    #[test]
    fn test_parse_struct_ignoring_additional_fields() {
        let uri_params = create_url_params(vec![
            ("a", "1"),
            ("b", "true"),
            ("c", "abc"),
            ("d", "false"),
        ]);
        assert_eq!(
            Struct::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            Struct {
                c: "abc".to_owned(),
                b: true,
                a: 1,
            }
        );
    }

    #[test]
    fn test_parse_tuple_ignoring_additional_fields() {
        let uri_params = create_url_params(vec![
            ("a", "abc"),
            ("b", "true"),
            ("c", "1"),
            ("d", "false"),
        ]);
        assert_eq!(
            <(&str, bool, u32)>::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            ("abc", true, 1)
        );
    }

    #[test]
    fn test_parse_map() {
        let uri_params = create_url_params(vec![("a", "1"), ("b", "true"), ("c", "abc")]);
        assert_eq!(
            <HashMap<String, String>>::deserialize(PathDeserializer::new(&uri_params)).unwrap(),
            [("a", "1"), ("b", "true"), ("c", "abc")]
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect()
        );
    }

    macro_rules! test_parse_error {
        (
            $params:expr,
            $ty:ty,
            $expected_error_kind:expr $(,)?
        ) => {
            let uri_params = create_url_params($params);
            let actual_error_kind = <$ty>::deserialize(PathDeserializer::new(&uri_params))
                .unwrap_err()
                .kind;
            assert_eq!(actual_error_kind, $expected_error_kind);
        };
    }

    #[test]
    fn test_wrong_number_of_parameters_error() {
        test_parse_error!(
            vec![("a", "1")],
            (u32, u32),
            ErrorKind::WrongNumberOfParameters {
                got: 1,
                expected: 2,
            }
        );
    }

    #[test]
    fn test_parse_error_at_key_error() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Params {
            a: u32,
        }
        test_parse_error!(
            vec![("a", "false")],
            Params,
            ErrorKind::ParseErrorAtKey {
                key: "a".to_owned(),
                value: "false".to_owned(),
                expected_type: "u32",
            }
        );
    }

    #[test]
    fn test_parse_error_at_key_error_multiple() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Params {
            a: u32,
            b: u32,
        }
        test_parse_error!(
            vec![("a", "false")],
            Params,
            ErrorKind::ParseErrorAtKey {
                key: "a".to_owned(),
                value: "false".to_owned(),
                expected_type: "u32",
            }
        );
    }

    #[test]
    fn test_parse_error_at_index_error() {
        test_parse_error!(
            vec![("a", "false"), ("b", "true")],
            (bool, u32),
            ErrorKind::ParseErrorAtIndex {
                index: 1,
                value: "true".to_owned(),
                expected_type: "u32",
            }
        );
    }

    #[test]
    fn test_parse_error_error() {
        test_parse_error!(
            vec![("a", "false")],
            u32,
            ErrorKind::ParseError {
                value: "false".to_owned(),
                expected_type: "u32",
            }
        );
    }

    #[test]
    fn test_unsupported_type_error_nested_data_structure() {
        test_parse_error!(
            vec![("a", "false")],
            Vec<Vec<u32>>,
            ErrorKind::UnsupportedType {
                name: "alloc::vec::Vec<u32>",
            }
        );
    }

    #[test]
    fn test_parse_seq_tuple_unsupported_key_type() {
        test_parse_error!(
            vec![("a", "false")],
            Vec<(u32, String)>,
            ErrorKind::Message("Unexpected key type".to_owned())
        );
    }

    #[test]
    fn test_parse_seq_wrong_tuple_length() {
        test_parse_error!(
            vec![("a", "false")],
            Vec<(String, String, String)>,
            ErrorKind::UnsupportedType {
                name: "(alloc::string::String, alloc::string::String, alloc::string::String)",
            }
        );
    }

    #[test]
    fn test_parse_seq_seq() {
        test_parse_error!(
            vec![("a", "false")],
            Vec<Vec<String>>,
            ErrorKind::UnsupportedType {
                name: "alloc::vec::Vec<alloc::string::String>",
            }
        );
    }
}
