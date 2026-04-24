//! Access helpers for Apple app-protected storage.
//!
//! This module currently exposes a thin wrapper around the Data Protection
//! keychain for generic-password items. It is intended for app, extension, and
//! other Apple-signed processes that already carry the necessary entitlements.

use security_framework::{
    base::Error,
    passwords::{PasswordOptions, generic_password, set_generic_password_options},
};
use security_framework_sys::base::errSecItemNotFound;

/// Load a raw generic-password secret from the Apple Data Protection keychain.
///
/// `service` and `account` identify the generic-password item. When
/// `access_group` is provided, the query is restricted to that access group.
///
/// Returns `Ok(None)` when no matching item exists.
pub fn load_raw_secret(
    service: &str,
    account: &str,
    access_group: Option<&str>,
) -> Result<Option<Vec<u8>>, Error> {
    let mut options = PasswordOptions::new_generic_password(service, account);
    options.use_protected_keychain();

    if let Some(access_group) = access_group.filter(|value| !value.is_empty()) {
        options.set_access_group(access_group);
    }

    match generic_password(options) {
        Ok(secret) => Ok(Some(secret)),
        Err(err) if err.code() == errSecItemNotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Store a raw generic-password secret in the Apple Data Protection keychain.
///
/// `service` and `account` identify the generic-password item. When
/// `access_group` is provided, the item is created or updated in that access
/// group.
pub fn store_raw_secret(
    service: &str,
    account: &str,
    access_group: Option<&str>,
    secret: &[u8],
) -> Result<(), Error> {
    let mut options = PasswordOptions::new_generic_password(service, account);
    options.use_protected_keychain();

    if let Some(access_group) = access_group.filter(|value| !value.is_empty()) {
        options.set_access_group(access_group);
    }

    set_generic_password_options(secret, options)
}

#[cfg(test)]
mod tests {
    use super::load_raw_secret;

    #[test]
    fn empty_access_group_is_treated_as_absent() {
        let missing = load_raw_secret(
            "rama-net-apple-networkextension.test.missing",
            "rama-net-apple-networkextension.test.missing",
            Some(""),
        )
        .expect("query missing protected-storage item");
        assert!(missing.is_none());
    }
}
