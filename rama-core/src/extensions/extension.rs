use core::any::{Any, TypeId};
use core::fmt;

use crate::std::sync::Arc;

use super::Extensions;

#[derive(Clone, Debug)]
/// A [`TypeErasedExtension`] is a type erased item which can be stored in an [`Extensions`]
///
/// Internally the value is stored inside an `Arc` so this is cheap to clone
pub struct TypeErasedExtension {
    pub(super) type_id: TypeId,
    pub(super) value: Arc<dyn Extension>,
}

impl TypeErasedExtension {
    /// Create a new [`TypeErasedExtension`] for `T`
    ///
    /// If the value you are inserting is an `Arc<T>`, prefer using
    /// [`Self::new_arc()`] to prevent the double indirection of storing
    /// an `Arc<Arc<T>>`. This happens because internally we use a type erased
    /// Arc to store the actual value.
    pub fn new<T: Extension>(value: T) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value: Arc::new(value),
        }
    }

    /// Create a new [`TypeErasedExtension`] for `Arc<T>`
    ///
    ///
    /// If the value you are inserting is not an `Arc<T>` prefer using
    /// [`Self::new()`] instead.
    pub fn new_arc<T: Extension>(value: Arc<T>) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value,
        }
    }

    /// Get the [`TypeId`] for the internally stored type `Arc<T>`
    pub fn type_id(&self) -> TypeId {
        self.type_id
    }

    /// Get a cloned `Arc<T>` of the internally stored type `Arc<T>`
    ///
    /// This method will return `None`, if the internally stored
    /// type `S` doesn't match the requested type `T`
    pub fn cloned_downcast<T: Extension>(&self) -> Option<Arc<T>> {
        let any = self.value.clone() as Arc<dyn Any + Send + Sync>;
        any.downcast::<T>().ok()
    }

    /// Get a reference `&T` of the internally stored type `T`
    ///
    /// This method will return `None`, if the internally stored
    /// type `S` doesn't match the requested type `T`
    pub fn downcast_ref<T: Extension>(&self) -> Option<&T> {
        let inner_any = self.value.as_ref() as &dyn Any;
        (inner_any).downcast_ref::<T>()
    }
}

// We use this syntax: [`TlsExtension`] — TLS and secure transport
// Instead of [`TlsExtension`]: TLS and secure transport
// Because otherwise we hit `link definitions are not shown in rendered documentation`

/// [`Extension`] is type which can be stored inside an [`Extensions`] store
///
/// This is has to be manually implement or can be implemented using `#[derive(Extension)]`
///
/// We have not implemented this for any container types:
/// - `Arc<T>`: sounds nice, but by not implement it, it has become impossible to misuse `Extensions::insert()`
///   with `Extensions::insert_arc()`. Otherwise this is very tricky and error prone
/// - `Vec<T>`: Collections should use the new type pattern to give it a meaningfull name, and to prevent collisions
///
/// There might be valid use cases for implementing it for other type of containers, so in case you run into these
/// open a Github issue and we can see if implementing it makes sense
///
/// # Extension Tags
///
/// Extensions can be tagged with one or more categories using the `#[extension(tags(tag1, tag2))]`
/// attribute on the derive macro. This generates implementations for the corresponding
/// marker traits below, which groups them in rust docs
///
/// - [`TlsExtension`] — TLS and secure transport
/// - [`HttpExtension`] — HTTP protocol
/// - [`NetExtension`] — Network and connection level
/// - [`UaExtension`] — User-agent emulation
/// - [`ProxyExtension`] — Proxy
/// - [`WsExtension`] — WebSocket
/// - [`DnsExtension`] — DNS resolution
/// - [`GrpcExtension`] — gRPC
///
/// ```rust,ignore
/// #[derive(Debug, Clone, Extension)]
/// #[extension(tags(tls, net))]
/// pub struct SecureTransport(..);
/// ```
///
/// Types that implement [`Extension`] manually can opt into tagged docs by implementing
/// the marker trait(s) directly:
///
/// ```rust,ignore
/// impl Extension for MyType {}
/// impl HttpExtension for MyType {}
/// ```
///
/// # Extension Scope
///
/// An extension is either flow data, which keeps resolving through every fork
/// of the chain, or a fact about one connection, which must not answer for a
/// connection nested on top of it. Facts opt out of that inheritance with
/// `#[extension(scope(connection))]`, see [`ExtensionScope`] and
/// [`Extensions::fork_nested_connection`].
pub trait Extension: Any + Send + Sync + core::fmt::Debug + 'static {
    /// How far up an [`Extensions`] chain a lookup of this type resolves,
    /// [`ExtensionScope::Flow`] unless the type says otherwise.
    #[inline(always)]
    fn scope() -> ExtensionScope
    where
        Self: Sized,
    {
        ExtensionScope::Flow
    }
}

/// What a connection nested on another one keeps from it.
///
/// A [`Extensions::fork_nested_connection`] boundary stops every
/// [`ExtensionScope::Connection`] fact of the connection underneath. Some of
/// those facts still constrain the nested endpoint, and only the site that
/// establishes the nesting knows which: the extension types cannot say, and
/// neither can the layers that published them. So every nesting site owns a
/// transfer and exposes it for configuration.
pub trait NestedConnectionTransfer: Send + Sync + 'static {
    /// Put onto `nested` what it keeps from the `outer` chain it forks from.
    fn transfer(&self, outer: &Extensions, nested: &Extensions);

    /// Run `self`, then `other`.
    fn and<T: NestedConnectionTransfer>(self, other: T) -> NestedConnectionTransferAnd<Self, T>
    where
        Self: Sized,
    {
        NestedConnectionTransferAnd {
            first: self,
            second: other,
        }
    }

    /// Erase and share this transfer, so a connector can hold it.
    fn into_shared(self) -> SharedNestedConnectionTransfer
    where
        Self: Sized,
    {
        SharedNestedConnectionTransfer(Arc::new(self))
    }
}

/// Keeps nothing: the nested connection starts from the flow data alone.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoConnectionTransfer;

impl NestedConnectionTransfer for NoConnectionTransfer {
    fn transfer(&self, _outer: &Extensions, _nested: &Extensions) {}
}

impl<F> NestedConnectionTransfer for F
where
    F: Fn(&Extensions, &Extensions) + Send + Sync + 'static,
{
    fn transfer(&self, outer: &Extensions, nested: &Extensions) {
        self(outer, nested);
    }
}

/// Two transfers run in order, see [`NestedConnectionTransfer::and`].
#[derive(Debug, Clone)]
pub struct NestedConnectionTransferAnd<A, B> {
    first: A,
    second: B,
}

impl<A: NestedConnectionTransfer, B: NestedConnectionTransfer> NestedConnectionTransfer
    for NestedConnectionTransferAnd<A, B>
{
    fn transfer(&self, outer: &Extensions, nested: &Extensions) {
        self.first.transfer(outer, nested);
        self.second.transfer(outer, nested);
    }
}

/// A shared [`NestedConnectionTransfer`] of any type, see [`NestedConnectionTransfer::into_shared`].
#[derive(Clone)]
pub struct SharedNestedConnectionTransfer(Arc<dyn NestedConnectionTransfer>);

impl fmt::Debug for SharedNestedConnectionTransfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedNestedConnectionTransfer")
            .finish_non_exhaustive()
    }
}

impl NestedConnectionTransfer for SharedNestedConnectionTransfer {
    fn transfer(&self, outer: &Extensions, nested: &Extensions) {
        self.0.transfer(outer, nested);
    }

    fn into_shared(self) -> Self {
        self
    }
}

/// How far up an [`Extensions`] chain a lookup of an [`Extension`] resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ExtensionScope {
    /// Resolves through the whole chain: config, routing and any other intent
    /// that stays true however often the chain is forked.
    #[default]
    Flow,
    /// Resolves up to and including the nearest level created by
    /// [`Extensions::fork_nested_connection`]: a fact about one connection,
    /// which says nothing about a connection nested on top of it.
    Connection,
}

impl ExtensionScope {
    /// Whether this is [`Self::Connection`].
    #[inline(always)]
    #[must_use]
    pub const fn is_connection(self) -> bool {
        matches!(self, Self::Connection)
    }
}

/// TLS and secure transport related extensions.
///
/// Derive with `#[extension(tags(tls))]`
pub trait TlsExtension: Extension {}

/// HTTP protocol related extensions.
///
/// Derive with `#[extension(tags(http))]`
pub trait HttpExtension: Extension {}

/// Network and connection level extensions.
///
/// Derive with `#[extension(tags(net))]`
pub trait NetExtension: Extension {}

/// User-agent emulation related extensions.
///
/// Derive with `#[extension(tags(ua))]`
pub trait UaExtension: Extension {}

/// Proxy related extensions.
///
/// Derive with `#[extension(tags(proxy))]`
pub trait ProxyExtension: Extension {}

/// WebSocket related extensions.
///
/// Derive with `#[extension(tags(ws))]`
pub trait WsExtension: Extension {}

/// DNS resolution related extensions.
///
/// Derive with `#[extension(tags(dns))]`
pub trait DnsExtension: Extension {}

/// gRPC related extensions.
///
/// Derive with `#[extension(tags(grpc))]`
pub trait GrpcExtension: Extension {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::tests::*;

    #[test]
    fn type_erased_new_supports_downcast_ref_and_cloned_downcast() {
        let ext = TypeErasedExtension::new(TraceNote(String::from("hello")));

        assert_eq!(ext.type_id(), TypeId::of::<TraceNote>());
        assert_eq!(
            ext.downcast_ref::<TraceNote>().map(|it| it.0.as_str()),
            Some("hello")
        );
        assert_eq!(
            ext.cloned_downcast::<TraceNote>()
                .as_deref()
                .map(|it| it.0.as_str()),
            Some("hello")
        );
        assert!(ext.downcast_ref::<RetryBudget>().is_none());
        assert!(ext.cloned_downcast::<RetryBudget>().is_none());
    }

    #[test]
    fn type_erased_new_arc_supports_all_downcasts() {
        let ext = TypeErasedExtension::new_arc(Arc::new(TraceNote(String::from("hello"))));

        assert_eq!(ext.type_id(), TypeId::of::<TraceNote>());
        assert_eq!(
            ext.downcast_ref::<TraceNote>().map(|it| it.0.as_str()),
            Some("hello")
        );
        assert_eq!(
            ext.cloned_downcast::<TraceNote>()
                .as_deref()
                .map(|it| it.0.as_str()),
            Some("hello")
        );
        assert!(ext.downcast_ref::<RetryBudget>().is_none());
        assert!(ext.cloned_downcast::<RetryBudget>().is_none());
    }

    #[test]
    fn scope_defaults_to_flow() {
        assert_eq!(RetryBudget::scope(), ExtensionScope::Flow);
        assert_eq!(NegotiatedAlpn::scope(), ExtensionScope::Connection);
        assert_eq!(Reuse::scope(), ExtensionScope::Connection);
    }
}
