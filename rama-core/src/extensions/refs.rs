use core::pin::Pin;

use crate::std::{boxed::Box, sync::Arc};

use super::Extensions;

pub trait ExtensionsRef {
    /// Get reference to the underlying [`Extensions`] store
    fn extensions(&self) -> &Extensions;
}

/// Exclusive access to an owned input's extension store.
///
/// Replacing the store permits request-local overlays without mutating stores
/// shared by cloned inputs. Individual extension values remain shared.
pub trait ExtensionsMut: ExtensionsRef {
    /// Get the replaceable extension store owned by this input.
    fn extensions_mut(&mut self) -> &mut Extensions;
}

impl ExtensionsMut for Extensions {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self
    }
}

impl<T: ExtensionsMut> ExtensionsMut for &mut T {
    fn extensions_mut(&mut self) -> &mut Extensions {
        (**self).extensions_mut()
    }
}

impl<T: ExtensionsMut> ExtensionsMut for Box<T> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        (**self).extensions_mut()
    }
}

impl<T: ExtensionsMut + Unpin> ExtensionsMut for Pin<Box<T>> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self.as_mut().get_mut().extensions_mut()
    }
}

impl ExtensionsRef for Extensions {
    fn extensions(&self) -> &Extensions {
        self
    }
}

impl<T> ExtensionsRef for &T
where
    T: ExtensionsRef + ?Sized,
{
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for &mut T
where
    T: ExtensionsRef + ?Sized,
{
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for Box<T>
where
    T: ExtensionsRef + ?Sized,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for Pin<Box<T>>
where
    T: ExtensionsRef + ?Sized,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for Arc<T>
where
    T: ExtensionsRef + ?Sized,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

macro_rules! impl_extensions_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+,> ExtensionsRef for crate::combinators::$id<$($param),+>
        where
            $($param: ExtensionsRef,)+
        {
            fn extensions(&self) -> &Extensions {
                match self {
                    $(crate::combinators::$id::$param(s) => s.extensions(),)+
                }
            }
        }

        impl<$($param),+,> ExtensionsMut for crate::combinators::$id<$($param),+>
        where
            $($param: ExtensionsMut,)+
        {
            fn extensions_mut(&mut self) -> &mut Extensions {
                match self {
                    $(crate::combinators::$id::$param(s) => s.extensions_mut(),)+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_extensions_either);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::Extensions;
    use crate::extensions::tests::*;

    #[test]
    fn extensions_ref_blanket_impls_forward_to_underlying_extensions() {
        let base = Extensions::new();
        base.insert(RetryBudget(7));

        let by_ref: &Extensions = &base;
        assert_eq!(
            by_ref.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );

        let mut base_for_mut = base.clone();
        let by_mut_ref: &mut Extensions = &mut base_for_mut;
        assert_eq!(
            by_mut_ref.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );

        let boxed = Box::new(base.clone());
        assert_eq!(
            boxed.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );

        let pinned = Pin::new(Box::new(base.clone()));
        assert_eq!(
            pinned.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );

        let arced = Arc::new(base);
        assert_eq!(
            arced.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );
    }
}

#[cfg(test)]
mod derive_extensions_ref_tests {
    use super::*;
    use core::marker::PhantomData;

    use crate::extensions::{Extension, Extensions, ExtensionsRef};

    #[derive(Debug, Clone, PartialEq, Eq, Extension)]
    struct Marker(u8);

    struct Conn {
        extensions: Extensions,
    }

    impl ExtensionsRef for Conn {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    fn conn() -> Conn {
        let extensions = Extensions::new();
        extensions.insert(Marker(1));
        Conn { extensions }
    }

    // `W` is deliberately not `ExtensionsRef`.
    struct NotExtensions;

    #[derive(ExtensionsRef)]
    struct Middleware<S, W> {
        inner: S,
        _writer: W,
    }

    #[derive(ExtensionsRef)]
    struct Tuple<W, S>(W, #[extensions_ref] S);

    #[derive(ExtensionsRef)]
    struct TupleStore<B>(B, Extensions);

    #[derive(ExtensionsRef)]
    struct Shared<S> {
        inner: Arc<S>,
    }

    #[derive(ExtensionsRef)]
    struct Borrowed<'a, S> {
        conn: &'a S,
    }

    #[derive(ExtensionsRef)]
    struct Newtype<S>(S);

    #[derive(ExtensionsRef)]
    struct Owned<B> {
        extensions: Extensions,
        _body: B,
    }

    fn store<T: ExtensionsRef>(value: &T) -> &Extensions {
        value.extensions()
    }

    // Inherent consts shadow trait consts only when their bounds hold,
    // so this answers "is `T: ExtensionsRef`" without a compile failure.
    struct Probe<T>(PhantomData<T>);

    trait NotForwarding {
        const FORWARDS: bool;
    }

    impl<T> NotForwarding for Probe<T> {
        const FORWARDS: bool = false;
    }

    impl<T: ExtensionsRef> Probe<T> {
        const FORWARDS: bool = true;
    }

    #[test]
    fn bound_is_placed_on_the_forwarded_field_only() {
        const {
            assert!(Probe::<Middleware<Conn, NotExtensions>>::FORWARDS);
            assert!(!Probe::<Middleware<NotExtensions, Conn>>::FORWARDS);
            assert!(!Probe::<Newtype<NotExtensions>>::FORWARDS);
            assert!(Probe::<Owned<NotExtensions>>::FORWARDS);
        }
    }

    #[test]
    fn named_field_forwards_the_inner_store() {
        let svc = Middleware {
            inner: conn(),
            _writer: NotExtensions,
        };
        assert!(core::ptr::eq(store(&svc), &raw const svc.inner.extensions));
        assert_eq!(store(&svc).get_ref::<Marker>(), Some(&Marker(1)));
    }

    #[test]
    fn tuple_field_forwards_the_marked_field() {
        let svc = Tuple(NotExtensions, conn());
        assert!(core::ptr::eq(store(&svc), &raw const svc.1.extensions));
    }

    #[test]
    fn nested_wrappers_reach_the_innermost_store() {
        let svc = Middleware {
            inner: Tuple(
                NotExtensions,
                Shared {
                    inner: Arc::new(conn()),
                },
            ),
            _writer: (),
        };
        let innermost = &svc.inner.1.inner.extensions;
        assert!(core::ptr::eq(store(&svc), innermost));

        store(&svc).insert(Marker(2));
        assert_eq!(innermost.get_ref::<Marker>(), Some(&Marker(2)));
    }

    #[test]
    fn borrowed_field_forwards() {
        let conn = conn();
        let svc = Borrowed { conn: &conn };
        assert!(core::ptr::eq(store(&svc), &raw const conn.extensions));
    }

    #[test]
    fn extensions_tuple_field_is_returned() {
        let svc = TupleStore(NotExtensions, Extensions::new());
        assert!(core::ptr::eq(store(&svc), &raw const svc.1));
    }

    #[test]
    fn single_tuple_field_forwards() {
        let svc = Newtype(conn());
        assert!(core::ptr::eq(store(&svc), &raw const svc.0.extensions));
    }

    #[test]
    fn extensions_field_is_returned_without_bounds_on_other_params() {
        let svc = Owned {
            extensions: Extensions::new(),
            _body: NotExtensions,
        };
        assert!(core::ptr::eq(store(&svc), &raw const svc.extensions));
    }
}
