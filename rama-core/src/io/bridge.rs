use crate::extensions::ExtensionsRef;

/// A bidirectional bridge between two [`Io`] objects.
///
/// Often this is for Client-Server communication,
/// but in a P2P like topology it can also be equal nodes.
///
/// [`ExtensionsRef`] and [`ExtensionsRef`] is implemented
/// in function of `Io1` as it is assumed that in flows where
/// [`BridgeIo`] is used that we keep moving from "left" (`Io1`)
/// to "right" (`Io2`) until we start to actually relay bytes,
/// handshakes or any kind of data.
///
/// If you ever use `Io2`'s extensions you can do so explicitly.
///
/// [`Io`]: super::Io
pub struct BridgeIo<Io1, Io2>(pub Io1, pub Io2);

impl<Io1: ExtensionsRef, Io2> ExtensionsRef for BridgeIo<Io1, Io2> {
    #[inline(always)]
    fn extensions(&self) -> &crate::extensions::Extensions {
        let Self(left, _) = self;
        left.extensions()
    }
}

impl<Ingress, Egress> super::PeekIoProvider for BridgeIo<Ingress, Egress>
where
    Ingress: super::Io,
    Egress: super::Io,
{
    type PeekIo = Ingress;
    type PeekEgressIo = Egress;
    type Mapped<PeekedIngress: super::Io, PeekedEgress: super::Io> =
        BridgeIo<PeekedIngress, PeekedEgress>;

    #[inline(always)]
    fn peek_io_mut(&mut self) -> &mut Self::PeekIo {
        let Self(ingress, _egress) = self;
        ingress
    }

    #[inline(always)]
    fn peek_ios_mut(&mut self) -> (&mut Self::PeekIo, Option<&mut Self::PeekEgressIo>) {
        let Self(ingress, egress) = self;
        (ingress, Some(egress))
    }

    #[inline(always)]
    fn map_peek_io<PeekedIngress, PeekedEgress, F, G>(
        self,
        map: F,
        map_egress: G,
    ) -> Self::Mapped<PeekedIngress, PeekedEgress>
    where
        PeekedIngress: super::Io,
        PeekedEgress: super::Io,
        F: FnOnce(Self::PeekIo) -> PeekedIngress,
        G: FnOnce(Self::PeekEgressIo) -> PeekedEgress,
    {
        let Self(ingress, egress) = self;
        BridgeIo(map(ingress), map_egress(egress))
    }
}
