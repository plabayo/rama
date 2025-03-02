#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
/// Marker type that can be used to request an opt-in
/// decompression layer to decompress a body in case it is compressed.
pub struct DecompressIfPossible;
