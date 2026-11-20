use core::any::TypeId;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::std::{boxed::Box, sync::Arc};

use super::store::type_slot;
use super::{Egress, Extension, ExtensionScope, Extensions, Ingress, TypeErasedExtension};

/// One requested type of a multi-type lookup: its identity and its
/// [`Extension::scope`], which single-value lookups read from the type itself.
///
/// Hidden and not part of the public API surface: built by
/// `#[derive(FromExtensions)]` and the [`GetManyRef`] / [`GetManyArc`] impls.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub(super) id: TypeId,
    pub(super) scope: ExtensionScope,
}

impl Target {
    /// The target for `T`.
    #[must_use]
    pub fn of<T: Extension>() -> Self {
        Self {
            id: TypeId::of::<T>(),
            scope: T::scope(),
        }
    }

    /// A target no entry ever matches, to fill a buffer before the real ones
    /// are written into it.
    #[must_use]
    pub const fn placeholder() -> Self {
        Self {
            id: TypeId::of::<()>(),
            scope: ExtensionScope::Flow,
        }
    }
}

/// The target types of one multi-type lookup, indexed by [`type_slot`].
///
/// Testing an entry against every target costs one comparison per target.
/// The slots reduce this to a table read for the (vast) majority of entries
/// that are none of the targets, and to a comparison or two for the others.
///
/// Hidden and not part of the public API surface: `#[derive(FromExtensions)]`
/// builds it once per type through a [`TargetPlan`].
#[doc(hidden)]
pub struct Targets<const N: usize> {
    pub(super) ids: [TypeId; N],
    /// Per slot: 1 + the index of the last target in that slot, 0 for none.
    head: [u16; usize::BITS as usize],
    /// Per target: the same for the target before it in its slot.
    next: [u16; N],
    /// The [`type_bit`] of every target, see [`Store::may_contain`].
    bits: usize,
    /// Per target: whether it is [`ExtensionScope::Connection`] scoped and so
    /// stops at a [`Extensions::fork_connection`] boundary.
    connection_scoped: [bool; N],
    /// Whether any target is [`ExtensionScope::Connection`] scoped.
    any_connection_scoped: bool,
}

impl<const N: usize> Targets<N> {
    #[inline(always)]
    fn new(targets: [Target; N]) -> Self {
        const {
            assert!(N < u16::MAX as usize, "too many extension targets");
        }
        let mut plan = Self {
            ids: targets.map(|target| target.id),
            head: [0; usize::BITS as usize],
            next: [0; N],
            bits: 0,
            connection_scoped: targets.map(|target| target.scope.is_connection()),
            any_connection_scoped: false,
        };
        for (i, target) in targets.iter().enumerate() {
            let slot = type_slot(target.id);
            plan.next[i] = plan.head[slot];
            plan.head[slot] = i as u16 + 1;
            plan.bits |= 1 << slot;
            plan.any_connection_scoped |= plan.connection_scoped[i];
        }
        plan
    }

    /// Whether a target that is not connection scoped is still unfilled, so
    /// walking past a connection boundary can still fill something.
    fn any_flow_unfilled(&self, out: &[Option<(&TypeErasedExtension, usize)>; N]) -> bool {
        out.iter()
            .zip(&self.connection_scoped)
            .any(|(slot, connection_scoped)| slot.is_none() && !connection_scoped)
    }
}

/// The [`Targets`] of a `#[derive(FromExtensions)]` type, built on first use.
///
/// The targets of such a type never change, so the derive keeps them in a
/// `static` instead of rebuilding them on every lookup.
///
/// Hidden and not part of the public API surface.
#[doc(hidden)]
pub struct TargetPlan<const N: usize> {
    /// Installed once: concurrent first uses race to build it, and the losers
    /// free theirs. Only needs `alloc`.
    // Safety invariant: null, or a pointer from `Box::into_raw` of a `Targets<N>`,
    // stored by a successful (Release) CAS from null, after which it is neither
    // written through nor freed until `self` drops.
    targets: AtomicPtr<Targets<N>>,
}

impl<const N: usize> TargetPlan<N> {
    /// An empty plan, to be kept in a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            targets: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// The targets, built from `requested` on the first call.
    #[inline]
    pub fn get(&self, requested: impl FnOnce() -> [Target; N]) -> &Targets<N> {
        let targets = self.targets.load(Ordering::Acquire);
        if targets.is_null() {
            return self.install(requested());
        }
        // SAFETY: `&*targets` needs a non-null, aligned pointer to an initialized
        // `Targets<N>` that stays live and unmutated while `self` is borrowed.
        // `targets` is non-null, so by the field invariant it is a `Box` allocation
        // that is never written through and is freed only when `self` drops. Its
        // contents are visible here: this Acquire load read the value of the
        // installing CAS (Release), which follows the `Box` write in that thread.
        unsafe { &*targets }
    }

    #[cold]
    fn install(&self, requested: [Target; N]) -> &Targets<N> {
        let new = Box::into_raw(Box::new(Targets::new(requested)));
        let targets = match self.targets.compare_exchange(
            core::ptr::null_mut(),
            new,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => new,
            Err(installed) => {
                // SAFETY: `Box::from_raw` needs a pointer from `Box::into_raw` that
                // nothing else owns. `new` comes from `Box::into_raw` above, and the
                // failed CAS did not publish it.
                drop(unsafe { Box::from_raw(new) });
                installed
            }
        };
        // SAFETY: `&*targets` needs what it needs in `get`. `targets` is either
        // `new`, now installed (written by this thread), or the non-null value the
        // CAS found, installed by a successful CAS (Release) whose value the failure
        // load (Acquire) read. Either way the field invariant applies as in `get`.
        unsafe { &*targets }
    }
}

impl<const N: usize> Drop for TargetPlan<N> {
    fn drop(&mut self) {
        let targets = *self.targets.get_mut();
        if !targets.is_null() {
            // SAFETY: `Box::from_raw` needs a pointer from `Box::into_raw` that
            // nothing else owns. The field invariant gives the origin, and `&mut
            // self` in `drop` means no `&Targets<N>` from `get` is alive anymore.
            drop(unsafe { Box::from_raw(targets) });
        }
    }
}

impl<const N: usize> Default for TargetPlan<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl Extensions {
    /// Fetch several extension types in a single pass, returning a tuple of
    /// `Option<&T>` mirroring the requested tuple. Each slot uses the same
    /// search rule as [`Self::get_ref`] (newest-wins, walking the
    /// [`Egress`] / [`Ingress`] wrappers and the parent chain), but the whole
    /// structure is traversed only once instead of once per type.
    ///
    /// See [`Self::get_many_arc`] for an owned-[`Arc`] variant.
    pub fn get_many_ref<'a, T: GetManyRef<'a>>(&'a self) -> T::Output {
        T::get_many_ref(self)
    }

    /// Like [`Self::get_many_ref`], but returns a tuple of `Option<Arc<T>>`
    /// (cheap, owned [`Arc`] clones) instead of borrowed references, the
    /// multi-fetch counterpart of [`Self::get_arc`]. Same single-pass traversal.
    pub fn get_many_arc<T: GetManyArc>(&self) -> T::Output {
        T::get_many_arc(self)
    }

    /// Single iteration logic behind [`Self::get_many_ref`], [`Self::get_many_arc`]
    /// and `#[derive(FromExtensions)]`. Hidden and not part of the public
    /// API surface: call `get_many_ref`/`get_many_arc` or the derive instead.
    ///
    /// For each requested [`Target`] in `targets`, fill the matching slot in
    /// `out` with the newest matching entry, walking wrappers and the parent
    /// chain like [`Self::get_ref`], each target up to its own scope boundary.
    /// Slots already `Some` are left untouched, so callers may pre-fill or
    /// reuse the buffer. `targets[i]` fills `out[i]`.
    ///
    /// Alongside the entry, each filled slot records its rank: the position of
    /// the entry in this single newest to oldest traversal. The newest entry
    /// visited is rank `0` and the count grows by one for every entry walked
    /// back (across wrappers and the parent chain). Comparing the ranks of two
    /// filled slots tells you which value was inserted more recently (0 = newest).
    ///
    /// A rank is a completely opaque type and should only be used to compare positions,
    /// it does not tell anything about the absolute position.
    #[doc(hidden)]
    #[inline]
    pub fn get_many_erased<'a, const N: usize>(
        &'a self,
        targets: &[Target; N],
        out: &mut [Option<(&'a TypeErasedExtension, usize)>; N],
    ) {
        self.get_many_targets(&Targets::new(*targets), out);
    }

    /// [`Self::get_many_erased`] for prepared `targets`, such as the ones a
    /// [`TargetPlan`] keeps between lookups.
    #[doc(hidden)]
    #[inline]
    pub fn get_many_targets<'a, const N: usize>(
        &'a self,
        targets: &Targets<N>,
        out: &mut [Option<(&'a TypeErasedExtension, usize)>; N],
    ) {
        let mut rank = 0;
        let mut remaining = out.iter().filter(|slot| slot.is_none()).count();
        self.get_many_erased_ranked(targets, out, &mut rank, &mut remaining, false);
    }

    /// One level of [`Self::get_many_erased`], then its wrappers and its parents
    /// in the order of [`Self::get_ref`]. `remaining` counts the slots of `out`
    /// that are still empty, and is kept up to date across the recursion.
    ///
    /// `past_boundary` says that a [`Self::fork_connection`] level was
    /// walked past to get here, which retires the connection-scoped targets for
    /// this branch of the traversal only: a wrapper reached from a level above
    /// the boundary still fills them.
    fn get_many_erased_ranked<'a, const N: usize>(
        &'a self,
        targets: &Targets<N>,
        out: &mut [Option<(&'a TypeErasedExtension, usize)>; N],
        rank: &mut usize,
        remaining: &mut usize,
        past_boundary: bool,
    ) {
        if *remaining == 0 {
            return;
        }
        let store = self.store();
        if store.may_contain(targets.bits) {
            let egress_id = TypeId::of::<Egress<Self>>();
            let ingress_id = TypeId::of::<Ingress<Self>>();
            let chunks = store.entries.chunks();
            // Read after the chunks (see `AppendOnlyVec::push_tagged`): every entry they
            // yield has its bit in here.
            let has_wrappers = store.has_wrappers();
            for chunk in chunks.rev() {
                for ext in chunk.iter().rev() {
                    let current = *rank;
                    *rank += 1;

                    // Most entries are none of the targets: their slot has none.
                    let mut target = targets.head[type_slot(ext.type_id)];
                    while target != 0 {
                        let i = usize::from(target) - 1;
                        if out[i].is_none()
                            && ext.type_id == targets.ids[i]
                            && !(past_boundary && targets.connection_scoped[i])
                        {
                            out[i] = Some((ext, current));
                            *remaining -= 1;

                            if *remaining == 0 {
                                return;
                            }
                        }
                        target = targets.next[i];
                    }

                    if !has_wrappers {
                        continue;
                    }
                    if ext.type_id == egress_id
                        && let Some(eg) = ext.downcast_ref::<Egress<Self>>()
                    {
                        eg.0.get_many_erased_ranked(targets, out, rank, remaining, past_boundary);
                        if *remaining == 0 {
                            return;
                        }
                    } else if ext.type_id == ingress_id
                        && let Some(ig) = ext.downcast_ref::<Ingress<Self>>()
                    {
                        ig.0.get_many_erased_ranked(targets, out, rank, remaining, past_boundary);
                        if *remaining == 0 {
                            return;
                        }
                    }
                }
            }
        }
        if let Some(parent) = self.parent() {
            let boundary = targets.any_connection_scoped && self.is_connection_boundary();
            if boundary && !targets.any_flow_unfilled(out) {
                return;
            }
            parent.get_many_erased_ranked(targets, out, rank, remaining, past_boundary || boundary);
        }
    }
}

/// Macro-support trait that lets a `#[derive(FromExtensions)]` group (e.g. an
/// any-of enum) be folded into a parent's single pass instead of running its own
/// traversal. Implemented by the derive, hidden and not part of the public API.
///
/// A group occupies [`Self::TARGETS`] consecutive slots in the shared buffers:
/// [`Self::from_ext_targets`] writes its candidate [`TypeId`]s at `offset`, and
/// after one [`Extensions::get_many_erased`] pass [`Self::from_ext_slots`] reads
/// the same window back. Because ranks are global across the pass, newest-wins
/// selection still holds across the whole struct.
#[doc(hidden)]
pub trait FromExtensionsGroup<'a>: Sized {
    /// Number of slots this group occupies in the shared single pass.
    const TARGETS: usize;
    /// Write the group's candidate [`Target`]s into `targets[offset..offset + TARGETS]`.
    fn from_ext_targets(targets: &mut [Target], offset: usize);
    /// Build the group value from the filled slots `out[offset..offset + TARGETS]`,
    /// or `None` if no candidate is present.
    fn from_ext_slots(
        out: &[Option<(&'a TypeErasedExtension, usize)>],
        offset: usize,
    ) -> Option<Self>;
}

/// Helper trait powering [`Extensions::get_many_ref`]: implemented for tuples of
/// [`Extension`] types (up to arity 12).
pub trait GetManyRef<'a>: Sized {
    /// Tuple of `Option<&'a T>` mirroring the requested tuple of types.
    type Output;

    #[doc(hidden)]
    const SEALED: seal::Seal;
    #[doc(hidden)]
    fn get_many_ref(ext: &'a Extensions) -> Self::Output;
}

/// Helper trait powering [`Extensions::get_many_arc`]; the owned-[`Arc`]
/// counterpart of [`GetManyRef`].
pub trait GetManyArc: Sized {
    /// Tuple of `Option<Arc<T>>` mirroring the requested tuple of types.
    type Output;

    #[doc(hidden)]
    const SEALED: seal::Seal;
    #[doc(hidden)]
    fn get_many_arc(ext: &Extensions) -> Self::Output;
}

macro_rules! impl_get_many {
    ($n:literal; $($T:ident => $idx:tt),+ $(,)?) => {
        impl<'a, $($T: Extension),+> GetManyRef<'a> for ($($T,)+) {
            type Output = ($(Option<&'a $T>,)+);

            const SEALED: seal::Seal = seal::Seal;
            fn get_many_ref(ext: &'a Extensions) -> Self::Output {
                let targets = [$(Target::of::<$T>()),+];
                let mut out: [Option<(&'a TypeErasedExtension, usize)>; $n] = [None; $n];
                ext.get_many_erased(&targets, &mut out);
                ($(out[$idx].and_then(|(e, _)| e.downcast_ref::<$T>()),)+)
            }
        }

        impl<$($T: Extension),+> GetManyArc for ($($T,)+) {
            type Output = ($(Option<Arc<$T>>,)+);

            const SEALED: seal::Seal = seal::Seal;
            fn get_many_arc(ext: &Extensions) -> Self::Output {
                let targets = [$(Target::of::<$T>()),+];
                let mut out: [Option<(&TypeErasedExtension, usize)>; $n] = [None; $n];
                ext.get_many_erased(&targets, &mut out);
                ($(out[$idx].and_then(|(e, _)| e.cloned_downcast::<$T>()),)+)
            }
        }
    };
}

impl_get_many!(1; A => 0);
impl_get_many!(2; A => 0, B => 1);
impl_get_many!(3; A => 0, B => 1, C => 2);
impl_get_many!(4; A => 0, B => 1, C => 2, D => 3);
impl_get_many!(5; A => 0, B => 1, C => 2, D => 3, E => 4);
impl_get_many!(6; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
impl_get_many!(7; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
impl_get_many!(8; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);
impl_get_many!(9; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8);
impl_get_many!(10; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9);
impl_get_many!(11; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10);
impl_get_many!(12; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10, L => 11);

mod seal {
    pub struct Seal;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::FromExtensions;
    use crate::extensions::tests::*;

    #[test]
    fn get_many_present_and_absent() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let (id, sock, toggle) = ext.get_many_ref::<(RequestId, ConnSocketInfo, FeatureToggle)>();
        assert_eq!(id, Some(&RequestId(7)));
        assert_eq!(sock, Some(&ConnSocketInfo("a")));
        assert_eq!(toggle, None);
    }

    #[test]
    fn get_many_each_slot_matches_get_ref() {
        let ext = Extensions::new();
        ext.insert(RequestId(1));
        ext.insert(RequestId(2)); // newest wins
        ext.insert(ConnSocketInfo("x"));

        let (id, sock) = ext.get_many_ref::<(RequestId, ConnSocketInfo)>();
        assert_eq!(id, ext.get_ref::<RequestId>());
        assert_eq!(sock, ext.get_ref::<ConnSocketInfo>());
        assert_eq!(id, Some(&RequestId(2)));
    }

    #[test]
    fn get_many_walks_parent_chain() {
        let parent = Extensions::new();
        parent.insert(RequestId(1));
        let child = parent.fork();
        child.insert(ConnSocketInfo("x"));

        let (id, sock) = child.get_many_ref::<(RequestId, ConnSocketInfo)>();
        assert_eq!(id, Some(&RequestId(1)));
        assert_eq!(sock, Some(&ConnSocketInfo("x")));
    }

    #[test]
    fn get_many_walks_wrappers() {
        let conn = Extensions::new();
        conn.insert(ConnSocketInfo("in"));
        let req = Extensions::new();
        req.insert(RequestId(7));
        req.insert(Ingress(conn));

        let (id, sock) = req.get_many_ref::<(RequestId, ConnSocketInfo)>();
        assert_eq!(id, Some(&RequestId(7)));
        assert_eq!(sock, Some(&ConnSocketInfo("in")));
    }

    #[derive(FromExtensions)]
    struct GatherView<'a> {
        id: Option<&'a RequestId>,
        sock: Option<&'a ConnSocketInfo>,
        toggle: Option<&'a FeatureToggle>,
    }

    #[test]
    fn derive_from_extensions_gathers_pieces() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let view = GatherView::from_extensions(&ext);
        assert_eq!(view.id, Some(&RequestId(7)));
        assert_eq!(view.sock, Some(&ConnSocketInfo("a")));
        assert_eq!(view.toggle, None);
        assert_eq!(view.id, ext.get_ref::<RequestId>());
    }

    #[test]
    fn derive_from_extensions_walks_parent() {
        let parent = Extensions::new();
        parent.insert(RequestId(1));
        let child = parent.fork();
        child.insert(ConnSocketInfo("x"));

        let view = GatherView::from_extensions(&child);
        assert_eq!(view.id, Some(&RequestId(1)));
        assert_eq!(view.sock, Some(&ConnSocketInfo("x")));
        assert_eq!(view.toggle, None);
    }

    #[test]
    fn get_many_arc_returns_owned_arcs() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));

        let (id, sock) = ext.get_many_arc::<(RequestId, ConnSocketInfo)>();
        assert_eq!(id.as_deref(), Some(&RequestId(7)));
        assert_eq!(sock, None);
    }

    #[derive(FromExtensions)]
    struct MixedView<'a> {
        id_ref: Option<&'a RequestId>,
        sock_arc: Option<Arc<ConnSocketInfo>>,
    }

    #[test]
    fn derive_from_extensions_mixed_ref_and_arc() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let view = MixedView::from_extensions(&ext);
        assert_eq!(view.id_ref, Some(&RequestId(7)));
        assert_eq!(view.sock_arc.as_deref(), Some(&ConnSocketInfo("a")));
    }

    #[derive(FromExtensions)]
    struct AllArc {
        id_ref: Option<Arc<RequestId>>,
        sock_arc: Option<Arc<ConnSocketInfo>>,
    }

    #[test]
    fn derive_from_extensions_all_arc() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let view = AllArc::from_extensions(&ext);
        assert_eq!(view.id_ref.as_deref(), Some(&RequestId(7)));
        assert_eq!(view.sock_arc.as_deref(), Some(&ConnSocketInfo("a")));
    }

    #[derive(FromExtensions)]
    struct RankedView<'a> {
        id: Option<(&'a RequestId, usize)>,
        sock: Option<(&'a ConnSocketInfo, usize)>,
        toggle: Option<(&'a FeatureToggle, usize)>,
    }

    #[test]
    fn derive_from_extensions_captures_rank() {
        let ext = Extensions::new();
        ext.insert(RequestId(7)); // oldest
        ext.insert(ConnSocketInfo("a")); // newest

        let view = RankedView::from_extensions(&ext);

        assert_eq!(view.sock, Some((&ConnSocketInfo("a"), 0)));
        assert_eq!(view.id, Some((&RequestId(7), 1)));
        assert_eq!(view.toggle, None);

        assert!(view.sock.unwrap().1 < view.id.unwrap().1);
    }

    #[test]
    fn derive_from_extensions_rank_arc_variant() {
        #[derive(FromExtensions)]
        struct RankedArc {
            id: Option<(Arc<RequestId>, usize)>,
        }

        let ext = Extensions::new();
        ext.insert(ConnSocketInfo("a"));
        ext.insert(RequestId(7));

        let view = RankedArc::from_extensions(&ext);
        let (id, rank) = view.id.expect("present");
        assert_eq!(&*id, &RequestId(7));
        assert_eq!(rank, 0);
    }

    #[derive(Debug, PartialEq, Eq, FromExtensions)]
    enum AnyOf<'a> {
        Req(&'a RequestId),
        Sock(&'a ConnSocketInfo),
    }

    #[test]
    fn derive_from_extensions_enum_newest_wins() {
        let ext = Extensions::new();
        ext.insert(ConnSocketInfo("a"));
        ext.insert(RequestId(7));
        assert_eq!(
            AnyOf::from_extensions(&ext),
            Some(AnyOf::Req(&RequestId(7)))
        );

        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));
        assert_eq!(
            AnyOf::from_extensions(&ext),
            Some(AnyOf::Sock(&ConnSocketInfo("a")))
        );

        let ext = Extensions::new();
        ext.insert(RequestId(7));
        assert_eq!(
            AnyOf::from_extensions(&ext),
            Some(AnyOf::Req(&RequestId(7)))
        );

        let ext = Extensions::new();
        ext.insert(FeatureToggle(true));
        assert_eq!(AnyOf::from_extensions(&ext), None);
    }

    #[derive(FromExtensions)]
    struct ConfigView<'a> {
        toggle: Option<&'a FeatureToggle>,
        either: Option<AnyOf<'a>>,
    }

    #[derive(Debug, PartialEq, Eq, FromExtensions)]
    enum SameType<'a> {
        First(&'a RequestId),
        Second(&'a RequestId),
    }

    #[test]
    fn derive_from_extensions_enum_same_type_ties_to_earlier_variant() {
        // Both variants name `RequestId`, so they resolve to the same entry
        // (equal rank), the tie breaks deterministically toward the earlier
        // variant, `First`.
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        assert_eq!(
            SameType::from_extensions(&ext),
            Some(SameType::First(&RequestId(7)))
        );
    }

    #[test]
    fn derive_from_extensions_nested_group_field() {
        let ext = Extensions::new();
        ext.insert(FeatureToggle(true));
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let view = ConfigView::from_extensions(&ext);
        assert_eq!(view.toggle, Some(&FeatureToggle(true)));
        assert_eq!(view.either, Some(AnyOf::Sock(&ConnSocketInfo("a"))));

        let ext = Extensions::new();
        ext.insert(FeatureToggle(false));
        let view = ConfigView::from_extensions(&ext);
        assert_eq!(view.toggle, Some(&FeatureToggle(false)));
        assert_eq!(view.either, None);
    }

    #[test]
    fn derive_from_extensions_is_empty_covers_every_field() {
        let empty = Extensions::new();
        assert!(GatherView::from_extensions(&empty).is_empty());
        assert!(RankedView::from_extensions(&empty).is_empty());
        assert!(ConfigView::from_extensions(&empty).is_empty());
        let unrelated = Extensions::new();
        unrelated.insert(FeatureToggle(true));
        assert!(MixedView::from_extensions(&unrelated).is_empty());

        let inserts: [fn(&Extensions); 3] = [
            |ext| {
                ext.insert(RequestId(7));
            },
            |ext| {
                ext.insert(ConnSocketInfo("a"));
            },
            |ext| {
                ext.insert(FeatureToggle(true));
            },
        ];
        for insert in inserts {
            let ext = Extensions::new();
            insert(&ext);
            assert!(!GatherView::from_extensions(&ext).is_empty());
            assert!(!RankedView::from_extensions(&ext).is_empty());
            // Covers both a direct field and the nested group.
            assert!(!ConfigView::from_extensions(&ext).is_empty());
        }
    }

    #[test]
    fn derive_from_extensions_enum_newest_wins_across_parent() {
        let parent = Extensions::new();
        parent.insert(RequestId(7));
        let child = parent.fork();
        child.insert(ConnSocketInfo("a"));

        assert_eq!(
            AnyOf::from_extensions(&child),
            Some(AnyOf::Sock(&ConnSocketInfo("a")))
        );

        let parent = Extensions::new();
        parent.insert(ConnSocketInfo("a"));
        let child = parent.fork();
        child.insert(RequestId(7));

        assert_eq!(
            AnyOf::from_extensions(&child),
            Some(AnyOf::Req(&RequestId(7)))
        );
    }
}
