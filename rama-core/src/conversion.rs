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

mod tests {
    use super::*;

    struct Test;

    impl From<bool> for Test {
        fn from(value: bool) -> Self {
            Self
        }
    }

    #[test]
    fn test() {
        let x: Test = true.into();
        let x: Test = true.rama_into();
    }

    struct Crate1;
    struct Crate2;

    struct Bla;

    impl RamaFrom<bool, Crate1> for Bla {
        fn rama_from(value: bool) -> Self {
            todo!()
        }
    }

    impl RamaFrom<bool, Crate2> for Bla {
        fn rama_from(value: bool) -> Self {
            todo!()
        }
    }

    fn bla() {
        let _x: Bla = RamaFrom::<_, Crate1>::rama_from(true);
    }
}
