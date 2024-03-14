use std::fmt;

/// Upgrade service can be used to handle the possibility of upgrading a request,
/// after which it will pass down the transport RW to the attached upgrade service.
pub struct UpgradeService {}

impl fmt::Debug for UpgradeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UpgradeService")
    }
}
