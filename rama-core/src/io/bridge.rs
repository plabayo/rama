use crate::extensions::{ExtensionsMut, ExtensionsRef};

/// A bidirectional bridge between two [`Io`] objects.
///
/// Often this is for Client-Server communication,
/// but in a P2P like topology it can also be equal nodes.
///
/// [`ExtensionsRef`] and [`ExtensionsMut`] is implemented
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
impl<Io1: ExtensionsMut, Io2> ExtensionsMut for BridgeIo<Io1, Io2> {
    #[inline(always)]
    fn extensions_mut(&mut self) -> &mut crate::extensions::Extensions {
        let Self(left, _) = self;
        left.extensions_mut()
    }
}
