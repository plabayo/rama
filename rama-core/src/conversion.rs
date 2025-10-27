/// Alternative for [`From`] which can be implemented by external crates for external types
///
/// To implement this trait, use a crate local `CrateMarker` generic type
/// More info: <https://ramaproxy.org/book/intro/patterns.html#working-around-the-orphan-rule-in-specific-cases>
///
/// Note: [`RamaFrom`] has a blacket implementation for types that implement [`From`]
pub trait RamaFrom<T, CrateMarker = ()> {
    fn rama_from(value: T) -> Self;
}

impl<T, U> RamaFrom<T> for U
where
    U: From<T>,
{
    fn rama_from(value: T) -> Self {
        Self::from(value)
    }
}

/// Alternative for [`Into`] which can be implemented by external crates for external types
///
/// To implement this trait, use a crate local `CrateMarker` generic type
/// More info: <https://ramaproxy.org/book/intro/patterns.html#working-around-the-orphan-rule-in-specific-cases>
///
/// Note: [`RamaInto`] has a blacket implementation for types that implement [`RamaFrom`] in
/// the opposite direction, and as such also work for types that implement [`Into`]
pub trait RamaInto<T, CrateMarker = ()>: Sized {
    fn rama_into(self) -> T;
}

impl<T, U, CrateMarker> RamaInto<U, CrateMarker> for T
where
    U: RamaFrom<T, CrateMarker>,
{
    #[inline]
    fn rama_into(self) -> U {
        U::rama_from(self)
    }
}

/// Alternative for [`TryFrom`] which can be implemented by external crates for external types
///
/// To implement this trait, use a crate local `CrateMarker` generic type
/// More info: <https://ramaproxy.org/book/intro/patterns.html#working-around-the-orphan-rule-in-specific-cases>
///
/// Note: [`RamaTryFrom`] has a blacket implementation for types that implement [`TryFrom`]
pub trait RamaTryFrom<T, CrateMarker = ()>: Sized {
    type Error;
    fn rama_try_from(value: T) -> Result<Self, Self::Error>;
}

impl<T, U> RamaTryFrom<T> for U
where
    U: TryFrom<T>,
{
    type Error = U::Error;

    fn rama_try_from(value: T) -> Result<Self, Self::Error> {
        Self::try_from(value)
    }
}

/// Alternative for [`TryInto`] which can be implemented by external crates for external types
///
/// To implement this trait, use a crate local `CrateMarker` generic type
/// More info: <https://ramaproxy.org/book/intro/patterns.html#working-around-the-orphan-rule-in-specific-cases>
///
/// Note: [`RamaTryInto`] has a blacket implementation for types that implement [`RamaTryFrom`] in
/// the opposite direction, and as such also work for types that implement [`TryInto`]
pub trait RamaTryInto<T, CrateMarker = ()>: Sized {
    type Error;
    fn rama_try_into(self) -> Result<T, Self::Error>;
}

impl<T, U, CrateMarker> RamaTryInto<U, CrateMarker> for T
where
    U: RamaTryFrom<T, CrateMarker>,
{
    type Error = U::Error;

    #[inline]
    fn rama_try_into(self) -> Result<U, U::Error> {
        U::rama_try_from(self)
    }
}

/// Create `Self` from a reference `T`
///
/// This is mostly used for extractors, but it can be used for anything
/// that needs to create an owned type from a reference
pub trait FromRef<T> {
    /// Converts to this type from a reference to the input type.
    fn from_ref(input: &T) -> Self;
}

pub use rama_macros::FromRef;

impl<T> FromRef<T> for T
where
    T: Clone,
{
    fn from_ref(input: &T) -> Self {
        input.clone()
    }
}
