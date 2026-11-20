use ahash::HashMap;
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};

use super::CertificateResult;
use crate::pki_types::CertificateDer;

pub(super) fn load_native_certs() -> CertificateResult {
    // The various domains are designed to interact like this:
    //
    // "Per-user Trust Settings override locally administered Trust Settings,
    //  which in turn override the System Trust Settings."
    //
    // So we collect the certificates in this order; as a map of their DER
    // encoding to what we'll do with them. We don't overwrite existing
    // elements, which means User settings trump Admin trump System, as desired.

    // SecTrustSettingsCopyTrustSettings returns this status when an item has
    // no settings in the requested domain, including a concurrent removal.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    let mut result = CertificateResult::default();
    let mut all_certs = HashMap::default();
    for domain in &[Domain::User, Domain::Admin, Domain::System] {
        let ts = TrustSettings::new(*domain);
        let iter = match ts.iter() {
            Ok(iter) => iter,
            Err(err) => {
                result.os_source_error(
                    err.into(),
                    match domain {
                        Domain::User => "failed to load user trust settings",
                        Domain::Admin => "failed to load admin trust settings",
                        Domain::System => "failed to load system trust settings",
                    },
                );
                continue;
            }
        };

        for cert in iter {
            let der = cert.to_der();

            // If there are no specific trust settings, the default is to trust
            // the certificate as a root cert. The docs say:
            //
            // "Note that an empty Trust Settings array means 'always trust this
            //  cert, with a resulting kSecTrustSettingsResult of
            //  kSecTrustSettingsResultTrustRoot'."
            let trusted = match ts.tls_trust_settings_for_certificate(&cert) {
                Ok(trusted) => trusted.unwrap_or(TrustSettingsForCertificate::TrustRoot),
                Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => continue,
                Err(err) => {
                    result.os_error(err.into(), "failed to read certificate trust settings");
                    // Avoid accepting this certificate via a later domain when
                    // its higher-priority settings could not be determined.
                    TrustSettingsForCertificate::Deny
                }
            };

            all_certs.entry(der).or_insert(trusted);
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
