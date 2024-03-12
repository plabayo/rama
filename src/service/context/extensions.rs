use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

type AnyMap = HashMap<TypeId, Box<dyn AnyClone + Send + Sync>, BuildHasherDefault<IdHasher>>;

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
}

impl Extensions {
    /// Create an empty `Extensions`.
    #[inline]
    pub fn new() -> Extensions {
        Extensions { map: None }
    }

    /// Insert a type into this `Extensions`.
    ///
    /// If a extension of this type already existed, it will
    /// be returned.
    pub fn insert<T: Clone + Send + Sync + 'static>(&mut self, val: T) -> Option<T> {
        self.map
            .get_or_insert_with(Box::default)
            .insert(TypeId::of::<T>(), Box::new(val))
            .and_then(|boxed| boxed.into_any().downcast().ok().map(|boxed| *boxed))
    }

    /// Extend these extensions with another Extensions.
    pub fn extend(&mut self, other: Extensions) {
        if let Some(other_map) = other.map {
            let map = self.map.get_or_insert_with(Box::default);
            #[allow(clippy::useless_conversion)]
            map.extend(other_map.into_iter());
        }
    }

    /// Clear the `Extensions` of all inserted extensions.
    pub fn clear(&mut self) {
        if let Some(map) = self.map.as_mut() {
            map.clear();
        }
    }
    /// Get an extension or T's [default()](std::default::Default).
    /// Refer to [Context::get](Self::get) for more detail's
    pub fn get_or_insert_default<T: Send + Default + Clone + Sync + 'static>(&mut self) -> &mut T {
        self.get_or_insert_with(|| T::default())
    }
    /// Retrieves a value of type `T` from the context. If the value does not exist,
    /// returns the provided value.
    /// Refer to [Context::get](Self::get) for more detail's
    pub fn get_or_insert<T: Send + Clone + Sync + 'static>(&mut self, fallback: T) -> &T {
        let b = match &self.map {
            Some(boxed_map) => boxed_map.contains_key(&TypeId::of::<T>()),
            None => false,
        };
        if !b {
            self.insert(fallback);
        }
        // At this point, it is safe to unwrap because we know the value exists
        self.get::<T>().unwrap()
    }
    /// Inserts a value into the map computed from `f` into if it is [`None`],
    /// then returns a mutable reference to the contained value.
    pub fn get_or_insert_with<T: 'static + Send + Sync + Clone>(
        &mut self,
        f: impl FnOnce() -> T,
    ) -> &mut T {
        let type_id = TypeId::of::<T>();

        let map = self.map.get_or_insert_with(Default::default);

        let boxed_any = map.entry(type_id).or_insert_with(|| Box::new(f()));

        let any_ref_mut = boxed_any.as_any_mut();
        any_ref_mut.downcast_mut::<T>().expect("Type mismatch")
    }

    /// Get a reference to a type previously inserted on this `Extensions`.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.get_inner::<T>().or_else(|| {
            self.get_inner::<ParentExtensions>()
                .and_then(|parent| parent.extensions.get::<T>())
        })
    }

    fn get_inner<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.map
            .as_ref()
            .and_then(|map| map.get(&TypeId::of::<T>()))
            .and_then(|boxed| (**boxed).as_any().downcast_ref())
    }

    /// Get a new extension map with the current extensions as parent.
    ///
    /// Note that later edits to parent won't be reflected here.
    pub fn into_parent(self) -> Extensions {
        let mut ext = Extensions::new();
        ext.insert(ParentExtensions {
            extensions: Arc::new(self),
        });
        ext
    }
    /// Checks if a value of type T exists in the extensions map
    pub fn contains<T: 'static + Send + Sync>(&self) -> bool {
        match &self.map {
            Some(boxed_map) => boxed_map.contains_key(&TypeId::of::<T>()),
            None => false,
        }
    }
}

#[derive(Debug, Clone)]
struct ParentExtensions {
    extensions: Arc<Extensions>,
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extensions").finish()
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
    #[derive(Clone, Debug, PartialEq)]
    struct MyType(i32);

    let mut extensions = Extensions::new();

    extensions.insert(5i32);
    extensions.insert(MyType(10));

    assert_eq!(extensions.get(), Some(&5i32));

    let mut ext2 = extensions.clone();
    let mut ext3 = extensions.into_parent();

    ext2.insert(true);
    ext3.insert(false);

    assert_eq!(ext2.get(), Some(&5i32));
    assert_eq!(ext2.get(), Some(&MyType(10)));
    assert_eq!(ext2.get(), Some(&true));

    assert_eq!(ext3.get(), Some(&5i32));
    assert_eq!(ext3.get(), Some(&MyType(10)));
    assert_eq!(ext3.get(), Some(&false));

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
