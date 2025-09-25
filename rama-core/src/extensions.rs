use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

#[cfg(feature = "debug-extensions")]
use std::any::type_name;

type AnyMap = HashMap<TypeId, Box<dyn AnyClone + Send + Sync>, BuildHasherDefault<IdHasher>>;
#[cfg(feature = "debug-extensions")]
type TypeIdMap = HashMap<TypeId, String, BuildHasherDefault<IdHasher>>;

// With TypeIds as keys, there's no need to hash them. They are already hashes
// themselves, coming from the compiler. The IdHasher just holds the u64 of
// the TypeId, and then returns it, instead of doing any bit fiddling.
#[derive(Default)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!("TypeId calls write_u64");
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// A type map of protocol extensions.
///
/// `Extensions` can be used by `Request` and `Response` to store
/// extra data derived from the underlying protocol.
#[derive(Clone, Default)]
pub struct Extensions {
    // If extensions are never used, no need to carry around an empty HashMap.
    // That's 3 words. Instead, this is only 1 word.
    map: Option<Box<AnyMap>>,
    #[cfg(feature = "debug-extensions")]
    type_map: Option<Box<TypeIdMap>>,
}

impl Extensions {
    /// Create an empty `Extensions`.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            map: None,
            #[cfg(feature = "debug-extensions")]
            type_map: None,
        }
    }

    /// Insert a type into this `Extensions`.
    ///
    /// If a extension of this type already existed, it will
    /// be returned.
    pub fn insert<T: Clone + Send + Sync + 'static>(&mut self, val: T) -> Option<T> {
        #[cfg(feature = "debug-extensions")]
        self.type_map
            .get_or_insert_with(Box::default)
            .insert(TypeId::of::<T>(), type_name::<T>().to_owned());

        self.map
            .get_or_insert_with(Box::default)
            .insert(TypeId::of::<T>(), Box::new(val))
            .and_then(|boxed| boxed.into_any().downcast().ok().map(|boxed| *boxed))
    }

    /// Insert a type only into this `Extensions`, if the value is `Some(T)`.
    ///
    /// See [`Self::insert`] for more information.
    pub fn maybe_insert<T: Clone + Send + Sync + 'static>(
        &mut self,
        mut val: Option<T>,
    ) -> Option<T> {
        val.take().and_then(|val| self.insert(val))
    }

    /// Extend these extensions with another Extensions.
    pub fn extend(&mut self, other: Self) {
        #[cfg(feature = "debug-extensions")]
        if let Some(other_map) = other.type_map {
            let map = self.type_map.get_or_insert_with(Box::default);
            #[allow(clippy::useless_conversion)]
            map.extend(other_map.into_iter());
        }

        if let Some(other_map) = other.map {
            let map = self.map.get_or_insert_with(Box::default);
            #[allow(clippy::useless_conversion)]
            map.extend(other_map.into_iter());
        }
    }

    /// Clear the `Extensions` of all inserted extensions.
    pub fn clear(&mut self) {
        #[cfg(feature = "debug-extensions")]
        if let Some(map) = self.type_map.as_mut() {
            map.clear();
        }

        if let Some(map) = self.map.as_mut() {
            map.clear();
        }
    }

    /// Returns true if the `Extensions` contains the given type.
    #[must_use]
    pub fn contains<T: Send + Sync + 'static>(&self) -> bool {
        self.map
            .as_ref()
            .map(|map| map.contains_key(&TypeId::of::<T>()))
            .unwrap_or_default()
    }

    /// Get a shared reference to a type previously inserted on this `Extensions`.
    #[must_use]
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.map
            .as_ref()
            .and_then(|map| map.get(&TypeId::of::<T>()))
            .and_then(|boxed| (**boxed).as_any().downcast_ref())
    }

    /// Get an exclusive reference to a type previously inserted on this `Extensions`.
    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.map
            .as_mut()
            .and_then(|map| map.get_mut(&TypeId::of::<T>()))
            .and_then(|boxed| (**boxed).as_any_mut().downcast_mut())
    }

    /// Inserts a value into the map computed from `f` into if it is [`None`],
    /// then returns an exclusive reference to the contained value.
    ///
    /// Use the cheaper [`Self::get_or_insert_with`] in case you do not need access to
    /// the extensions for the creation of `T`, as this function comes with
    /// an extra cost.
    pub fn get_or_insert_with_ext<T: Clone + Send + Sync + 'static>(
        &mut self,
        f: impl FnOnce(&Self) -> T,
    ) -> &mut T {
        if self.contains::<T>() {
            // NOTE: once <https://github.com/rust-lang/polonius>
            // is merged into rust we can use directly `if let Some(v) = self.extensions.get_mut()`,
            // until then we need this work around.
            return self.get_mut().unwrap();
        }
        let v = f(self);
        self.insert(v);
        self.get_mut().unwrap()
    }

    /// Inserts a value into the map computed from `f` into if it is [`None`],
    /// then returns an exclusive reference to the contained value.
    pub fn get_or_insert_with<T: Send + Sync + Clone + 'static>(
        &mut self,
        f: impl FnOnce() -> T,
    ) -> &mut T {
        #[cfg(feature = "debug-extensions")]
        self.type_map
            .get_or_insert_with(Box::default)
            .insert(TypeId::of::<T>(), type_name::<T>().to_owned());

        let map = self.map.get_or_insert_with(Box::default);
        let entry = map.entry(TypeId::of::<T>());

        let boxed = entry.or_insert_with(|| Box::new(f()));
        (**boxed)
            .as_any_mut()
            .downcast_mut()
            .expect("type mismatch")
    }

    /// Inserts a value into the map computed by converting `U` into `T` if it is `None`
    /// then returns an exclusive reference to the contained value.
    pub fn get_or_insert_from<T, U>(&mut self, src: U) -> &mut T
    where
        T: Send + Sync + Clone + 'static,
        U: Into<T>,
    {
        #[cfg(feature = "debug-extensions")]
        self.type_map
            .get_or_insert_with(Box::default)
            .insert(TypeId::of::<T>(), type_name::<T>().to_owned());

        let map = self.map.get_or_insert_with(Box::default);
        let entry = map.entry(TypeId::of::<T>());

        let boxed = entry.or_insert_with(|| Box::new(src.into()));
        (**boxed)
            .as_any_mut()
            .downcast_mut()
            .expect("type mismatch")
    }

    /// Retrieves a value of type `T` from the context.
    ///
    /// If the value does not exist, the given value is inserted and an exclusive reference to it is returned.
    pub fn get_or_insert<T: Clone + Send + Sync + 'static>(&mut self, fallback: T) -> &mut T {
        self.get_or_insert_with(|| fallback)
    }

    /// Get an extension or `T`'s [`Default`].
    ///
    /// see [`Extensions::get`] for more details.
    pub fn get_or_insert_default<T: Default + Clone + Send + Sync + 'static>(&mut self) -> &mut T {
        self.get_or_insert_with(T::default)
    }

    /// Remove a type from this `Extensions`.
    pub fn remove<T: Clone + Send + Sync + 'static>(&mut self) -> Option<T> {
        #[cfg(feature = "debug-extensions")]
        self.type_map
            .as_mut()
            .and_then(|map| map.remove(&TypeId::of::<T>()));

        self.map
            .as_mut()
            .and_then(|map| map.remove(&TypeId::of::<T>()))
            .and_then(|boxed| boxed.into_any().downcast().ok().map(|boxed| *boxed))
    }
}

impl fmt::Debug for Extensions {
    #[cfg(feature = "debug-extensions")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let items = self.map.as_ref().map(|map| {
            map.keys()
                .map(|key| {
                    self.type_map
                        .as_ref()
                        .and_then(|type_map| type_map.get(key))
                        .unwrap()
                })
                .collect::<Vec<&String>>()
        });

        f.debug_struct("Extensions").field("items", &items).finish()
    }

    #[cfg(not(feature = "debug-extensions"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extensions").finish()
    }
}

pub trait ExtensionsRef {
    fn extensions(&self) -> &Extensions;
}

impl ExtensionsRef for Extensions {
    fn extensions(&self) -> &Extensions {
        self
    }
}

impl<T> ExtensionsRef for &T
where
    T: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for &mut T
where
    T: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for Box<T>
where
    T: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for Arc<T>
where
    T: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

pub trait ExtensionsMut: ExtensionsRef {
    fn extensions_mut(&mut self) -> &mut Extensions;

    fn take_extensions(&mut self) -> Extensions {
        std::mem::take(self.extensions_mut())
    }
}

impl ExtensionsMut for Extensions {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self
    }
}

impl<T> ExtensionsMut for &mut T
where
    T: ExtensionsMut,
{
    fn extensions_mut(&mut self) -> &mut Extensions {
        (**self).extensions_mut()
    }
}

impl<T> ExtensionsMut for Box<T>
where
    T: ExtensionsMut,
{
    fn extensions_mut(&mut self) -> &mut Extensions {
        (**self).extensions_mut()
    }
}

trait AnyClone: Any {
    fn clone_box(&self) -> Box<dyn AnyClone + Send + Sync>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl<T: Clone + Send + Sync + 'static> AnyClone for T {
    fn clone_box(&self) -> Box<dyn AnyClone + Send + Sync> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl Clone for Box<dyn AnyClone + Send + Sync> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

#[test]
fn test_extensions() {
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct MyType(i32);

    let mut extensions = Extensions::new();

    extensions.insert(5i32);
    extensions.insert(MyType(10));

    assert_eq!(extensions.get(), Some(&5i32));

    let mut ext2 = extensions.clone();

    ext2.insert(true);

    assert_eq!(ext2.get(), Some(&5i32));
    assert_eq!(ext2.get(), Some(&MyType(10)));
    assert_eq!(ext2.get(), Some(&true));

    // test extend
    let mut extensions = Extensions::new();
    extensions.insert(5i32);
    extensions.insert(MyType(10));

    let mut extensions2 = Extensions::new();
    extensions2.extend(extensions);
    assert_eq!(extensions2.get(), Some(&5i32));
    assert_eq!(extensions2.get(), Some(&MyType(10)));

    // test clear
    extensions2.clear();
    assert_eq!(extensions2.get::<i32>(), None);
    assert_eq!(extensions2.get::<MyType>(), None);
}
