use std::ops::{Deref, DerefMut};

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::de::ValueDeserializer;
use super::ser::ValueSerializer;
use crate::error::JsError;
use crate::func::JsFnOutput;
use crate::value::{JsArg, JsObject, JsValue};

/// Wrapper to move any `serde`-capable type across the js boundary.
///
/// As a host function argument it deserializes the incoming
/// [`JsValue`]; as a host function return value it serializes into
/// one. Failures surface as conversion errors, thrown inside the
/// calling script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Serde<T>(pub T);

impl<T> Serde<T> {
    /// Consume into the wrapped value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Serde<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Serde<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<T> for Serde<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: DeserializeOwned> JsArg for Serde<T> {
    fn from_js(value: JsValue) -> Result<Self, JsError> {
        T::deserialize(ValueDeserializer(value))
            .map(Serde)
            .map_err(|err| JsError::conversion(format!("deserialize js value: {err}")))
    }
}

impl<T: Serialize> TryFrom<Serde<T>> for JsValue {
    type Error = JsError;

    fn try_from(value: Serde<T>) -> Result<Self, Self::Error> {
        value
            .0
            .serialize(ValueSerializer)
            .map_err(|err| JsError::conversion(format!("serialize into js value: {err}")))
    }
}

/// [`JsFnOutput`] marker for [`Serde`]-wrapped values.
#[derive(Debug)]
#[non_exhaustive]
pub struct SerdeOutput;

impl<T: Serialize + Send + 'static> JsFnOutput<SerdeOutput> for Serde<T> {
    fn into_js_fn_output(self) -> Result<JsValue, JsError> {
        self.try_into()
    }
}

impl JsValue {
    /// Deserialize this value into any `serde`-capable type.
    pub fn deserialize_into<T: DeserializeOwned>(&self) -> Result<T, JsError> {
        Serde::<T>::from_js(self.clone()).map(Serde::into_inner)
    }
}

impl JsObject {
    /// Deserialize this object into any `serde`-capable type.
    pub fn deserialize_into<T: DeserializeOwned>(&self) -> Result<T, JsError> {
        JsValue::Object(self.clone()).deserialize_into()
    }
}
