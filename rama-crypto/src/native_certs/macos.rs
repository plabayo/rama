use ahash::HashMap;
use security_framework::{
    base::Error as SecurityError,
    trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate},
};

use super::CertificateResult;
use crate::pki_types::CertificateDer;

#[derive(Clone, Copy)]
enum LookupMode {
    Static,
    Reload,
}

pub(super) fn load_native_certs() -> CertificateResult {
    load(LookupMode::Static)
}

pub(super) fn load_reloadable_native_certs() -> CertificateResult {
    load(LookupMode::Reload)
}

fn load(mode: LookupMode) -> CertificateResult {
    // The various domains are designed to interact like this:
    //
    // "Per-user Trust Settings override locally administered Trust Settings,
    //  which in turn override the System Trust Settings."
    //
    // So we collect the certificates in this order; as a map of their DER
    // encoding to what we'll do with them. We don't overwrite existing
    // elements, which means User settings trump Admin trump System, as desired.

    let mut result = CertificateResult::default();
    let mut all_certs = HashMap::default();
    for domain in &[Domain::User, Domain::Admin, Domain::System] {
        let ts = TrustSettings::new(*domain);
        let iter = match ts.iter() {
            Ok(iter) => iter,
            Err(err) => {
                let context = match domain {
                    Domain::User => "failed to load user trust settings",
                    Domain::Admin => "failed to load admin trust settings",
                    Domain::System => "failed to load system trust settings",
                };
                match mode {
                    LookupMode::Static => result.os_error(err.into(), context),
                    LookupMode::Reload => result.os_source_error(err.into(), context),
                }
                continue;
            }
        };

        for cert in iter {
            record_trust_setting(
                &mut all_certs,
                cert.to_der(),
                ts.tls_trust_settings_for_certificate(&cert),
                mode,
                &mut result,
            );
        }
    }

    // Now we have all the certificates and an idea of whether to use them.
    for (der, trusted) in all_certs.drain() {
        if let TrustSettingsForCertificate::TrustRoot | TrustSettingsForCertificate::TrustAsRoot =
            trusted
        {
            result.certs.push(CertificateDer::from(der));
        }
    }

    result
}

fn record_trust_setting(
    all_certs: &mut HashMap<Vec<u8>, TrustSettingsForCertificate>,
    der: Vec<u8>,
    lookup: Result<Option<TrustSettingsForCertificate>, SecurityError>,
    mode: LookupMode,
    result: &mut CertificateResult,
) {
    // SecTrustSettingsCopyTrustSettings uses this status when a certificate
    // has no settings in the requested domain, including concurrent removal.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    let trusted = match (lookup, mode) {
        // An empty trust settings array defaults to always trusting this root.
        (Ok(trusted), _) => trusted.unwrap_or(TrustSettingsForCertificate::TrustRoot),
        (Err(err), LookupMode::Static) => {
            result.os_error(err.into(), "certificate not trusted");
            return;
        }
        (Err(err), LookupMode::Reload) if err.code() == ERR_SEC_ITEM_NOT_FOUND => return,
        (Err(err), LookupMode::Reload) => {
            result.os_error(err.into(), "failed to read certificate trust settings");
            // Do not accept this root from a later domain when overriding
            // settings could not be determined.
            TrustSettingsForCertificate::Deny
        }
    };

    all_certs.entry(der).or_insert(trusted);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reload_blocks_lower_domain_trust_after_an_item_lookup_failure() {
        // errSecNotAvailable is a failed lookup, rather than a missing item.
        const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
        for (mode, expected) in [
            (LookupMode::Static, TrustSettingsForCertificate::TrustRoot),
            (LookupMode::Reload, TrustSettingsForCertificate::Deny),
        ] {
            let der = vec![1, 2, 3];
            let mut certs = HashMap::default();
            let mut result = CertificateResult::default();
            record_trust_setting(
                &mut certs,
                der.clone(),
                Err(SecurityError::from_code(ERR_SEC_NOT_AVAILABLE)),
                mode,
                &mut result,
            );
            record_trust_setting(
                &mut certs,
                der.clone(),
                Ok(Some(TrustSettingsForCertificate::TrustRoot)),
                mode,
                &mut result,
            );
            assert_eq!(certs.remove(&der), Some(expected));
            assert_eq!(result.errors.len(), 1);
            assert_eq!(result.source_error, None);
        }
    }
}
