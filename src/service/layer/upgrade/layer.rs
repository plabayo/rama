use std::fmt;

/// UpgradeLayer is a middleware that can be used to upgrade a request.
///
/// See [`UpgradeService`] for more details.
pub struct UpgradeLayer {}

impl fmt::Debug for UpgradeLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UpgradeLayer")
    }
}
