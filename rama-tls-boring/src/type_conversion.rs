use crate::RamaTryFrom;
use itertools::Itertools;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_core::telemetry::tracing::trace;
use rama_net::tls::client::{ClientHello, parse_client_hello};

impl<'ssl> RamaTryFrom<rama_boring::ssl::ClientHello<'ssl>> for ClientHello {
    type Error = OpaqueError;

    fn rama_try_from(value: rama_boring::ssl::ClientHello<'ssl>) -> Result<Self, Self::Error> {
        parse_client_hello(value.as_bytes()).context("parse boring ssl ClientHello")
    }
}

impl<'ssl> RamaTryFrom<&rama_boring::ssl::ClientHello<'ssl>> for ClientHello {
    type Error = OpaqueError;

    fn rama_try_from(value: &rama_boring::ssl::ClientHello<'ssl>) -> Result<Self, Self::Error> {
        parse_client_hello(value.as_bytes()).context("parse boring ssl ClientHello")
    }
}

macro_rules! try_from_mapping {
    (
        type $rama_ty:ident = $boring_ty:ident;
        $(
            let $rama_val:ident = $boring_val:ident;
        )+
    ) => {
        impl RamaTryFrom<rama_net::tls::$rama_ty> for rama_boring::ssl::$boring_ty {
            type Error = rama_net::tls::$rama_ty;

            fn rama_try_from(value: rama_net::tls::$rama_ty) -> Result<Self, Self::Error> {
                match value {
                    $(
                        rama_net::tls::$rama_ty::$rama_val => Ok(rama_boring::ssl::$boring_ty::$boring_val),
                    )+
                    _ => Err(value),
                }
            }
        }

        impl RamaTryFrom<rama_boring::ssl::$boring_ty> for rama_net::tls::$rama_ty {
                type Error = rama_boring::ssl::$boring_ty;

                fn rama_try_from(value: rama_boring::ssl::$boring_ty) -> Result<Self, Self::Error> {
                    match value {
                        $(
                            rama_boring::ssl::$boring_ty::$boring_val => Ok(rama_net::tls::$rama_ty::$rama_val),
                        )+
                        _ => Err(value),
                    }
                }
            }
    };
}

try_from_mapping! {
    type SupportedGroup = SslCurve;
    let SECP256R1 = SECP256R1;
    let SECP384R1 = SECP384R1;
    let SECP521R1 = SECP521R1;
    let X25519 = X25519;
}

try_from_mapping! {
    type SignatureScheme = SslSignatureAlgorithm;
    let RSA_PKCS1_SHA1 = RSA_PKCS1_SHA1;
    let RSA_PKCS1_SHA256 = RSA_PKCS1_SHA256;
    let RSA_PKCS1_SHA384 = RSA_PKCS1_SHA384;
    let RSA_PKCS1_SHA512 = RSA_PKCS1_SHA512;
    let ECDSA_SHA1_Legacy = ECDSA_SHA1;
    let RSA_PKCS1_MD5_SHA1 = RSA_PKCS1_MD5_SHA1;
    let ECDSA_NISTP256_SHA256 = ECDSA_SECP256R1_SHA256;
    let ECDSA_NISTP384_SHA384 = ECDSA_SECP384R1_SHA384;
    let ECDSA_NISTP521_SHA512 = ECDSA_SECP521R1_SHA512;
    let RSA_PSS_SHA256 = RSA_PSS_RSAE_SHA256;
    let RSA_PSS_SHA384 = RSA_PSS_RSAE_SHA384;
    let RSA_PSS_SHA512 = RSA_PSS_RSAE_SHA512;
    let ED25519 = ED25519;
    // Not exposed in boring, but exists in openssl/ssl.h
    // let RSA_PKCS1_SHA256_LEGACY = RSA_PKCS1_SHA256_LEGACY;
}

try_from_mapping! {
    type ProtocolVersion = SslVersion;
    let TLSv1_3 = TLS1_3;
    let TLSv1_2 = TLS1_2;
    let TLSv1_1 = TLS1_1;
    let TLSv1_0 = TLS1;
    let SSLv3 = SSL3;
}

impl RamaTryFrom<&rama_boring::x509::X509> for rama_net::tls::DataEncoding {
    type Error = OpaqueError;

    fn rama_try_from(value: &rama_boring::x509::X509) -> Result<Self, Self::Error> {
        let der = value.to_der().context("boring X509 to Der DataEncoding")?;
        Ok(Self::Der(der))
    }
}

impl RamaTryFrom<&rama_boring::stack::StackRef<rama_boring::x509::X509>>
    for rama_net::tls::DataEncoding
{
    type Error = OpaqueError;

    fn rama_try_from(
        value: &rama_boring::stack::StackRef<rama_boring::x509::X509>,
    ) -> Result<Self, Self::Error> {
        let der = value
            .into_iter()
            .map(|cert| {
                cert.to_der()
                    .context("boring X509 stackref to DerStack DataEncoding")
            })
            .collect::<Result<Vec<Vec<u8>>, _>>()?;
        Ok(Self::DerStack(der))
    }
}

/// create an openssl cipher list str from the given [`CipherSuite`]
///
/// ref doc: <https://docs.openssl.org/1.1.1/man1/ciphers/#tls-v13-cipher-suites>
#[must_use]
pub fn openssl_cipher_list_str_from_cipher_list(
    suites: &[rama_net::tls::CipherSuite],
) -> Option<String> {
    let s = suites
        .iter()
        .filter_map(|s| {
            if s.is_grease() {
                trace!("ignore grease cipher suite {s}");
                return None;
            }

            openssl_cipher_str_from_cipher_suite(*s)
        })
        .dedup()
        .join(":");
    (!s.is_empty()).then_some(s)
}

fn openssl_cipher_str_from_cipher_suite(suite: rama_net::tls::CipherSuite) -> Option<&'static str> {
    match suite {
        rama_net::tls::CipherSuite::TLS_RSA_WITH_NULL_MD5 => Some("NULL-MD5"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_NULL_SHA => Some("NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_RC4_128_MD5 => Some("RC4-MD5"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_RC4_128_SHA => Some("RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_IDEA_CBC_SHA => Some("IDEA-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA => Some("DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA => Some("DH-DSS-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA => Some("DH-RSA-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => Some("DHE-DSS-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA => Some("DHE-RSA-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_RC4_128_MD5 => Some("ADH-RC4-MD5"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA => Some("ADH-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::SSL_FORTEZZA_KEA_WITH_NULL_SHA | rama_net::tls::CipherSuite::SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA => None, // not implemented (SSL v3.0)
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => Some("AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => Some("AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_AES_128_CBC_SHA => Some("DH-DSS-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_AES_256_CBC_SHA => Some("DH-DSS-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_AES_128_CBC_SHA => Some("DH-RSA-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_AES_256_CBC_SHA => Some("DH-RSA-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA => Some("DHE-DSS-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA => Some("DHE-DSS-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => Some("DHE-RSA-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => Some("DHE-RSA-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_AES_128_CBC_SHA => Some("ADH-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA => Some("ADH-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA => Some("CAMELLIA128-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA => Some("CAMELLIA256-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA => Some("DH-DSS-CAMELLIA128-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA => Some("DH-DSS-CAMELLIA256-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA => Some("DH-RSA-CAMELLIA128-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA => Some("DH-RSA-CAMELLIA256-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA => {
            Some("DHE-DSS-CAMELLIA128-SHA")
        }
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => {
            Some("DHE-DSS-CAMELLIA256-SHA")
        }
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA => {
            Some("DHE-RSA-CAMELLIA128-SHA")
        }
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => {
            Some("DHE-RSA-CAMELLIA256-SHA")
        }
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA => Some("ADH-CAMELLIA128-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA => Some("ADH-CAMELLIA256-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_SEED_CBC_SHA => Some("SEED-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_SEED_CBC_SHA => Some("DH-DSS-SEED-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_SEED_CBC_SHA => Some("DH-RSA-SEED-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_SEED_CBC_SHA => Some("DHE-DSS-SEED-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_SEED_CBC_SHA => Some("DHE-RSA-SEED-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_SEED_CBC_SHA => Some("ADH-SEED-SHA"),
        rama_net::tls::CipherSuite::TLS_GOSTR341094_WITH_28147_CNT_IMIT => Some("GOST94-GOST89-GOST89"),
        rama_net::tls::CipherSuite::TLS_GOSTR341001_WITH_28147_CNT_IMIT => Some("GOST2001-GOST89-GOST89"),
        rama_net::tls::CipherSuite::TLS_GOSTR341094_WITH_NULL_GOSTR3411 => Some("GOST94-NULL-GOST94"),
        rama_net::tls::CipherSuite::TLS_GOSTR341001_WITH_NULL_GOSTR3411 => Some("GOST2001-NULL-GOST94"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_RC4_128_SHA => Some("DHE-DSS-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_NULL_SHA => Some("ECDHE-RSA-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_RC4_128_SHA => Some("ECDHE-RSA-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => Some("ECDHE-RSA-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => Some("ECDHE-RSA-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => Some("ECDHE-RSA-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_NULL_SHA => Some("ECDHE-ECDSA-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => Some("ECDHE-ECDSA-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => {
            Some("ECDHE-ECDSA-DES-CBC3-SHA")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => Some("ECDHE-ECDSA-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => Some("ECDHE-ECDSA-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_anon_WITH_NULL_SHA => Some("AECDH-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_anon_WITH_RC4_128_SHA => Some("AECDH-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA => Some("AECDH-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_anon_WITH_AES_128_CBC_SHA => Some("AECDH-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_anon_WITH_AES_256_CBC_SHA => Some("AECDH-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_NULL_SHA256 => Some("NULL-SHA256"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 => Some("AES128-SHA256"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 => Some("AES256-SHA256"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 => Some("AES128-GCM-SHA256"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 => Some("AES256-GCM-SHA384"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_AES_128_CBC_SHA256 => Some("DH-RSA-AES128-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_AES_256_CBC_SHA256 => Some("DH-RSA-AES256-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_AES_128_GCM_SHA256 => Some("DH-RSA-AES128-GCM-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_AES_256_GCM_SHA384 => Some("DH-RSA-AES256-GCM-SHA384"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_AES_128_CBC_SHA256 => Some("DH-DSS-AES128-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_AES_256_CBC_SHA256 => Some("DH-DSS-AES256-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_AES_128_GCM_SHA256 => Some("DH-DSS-AES128-GCM-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_AES_256_GCM_SHA384 => Some("DH-DSS-AES256-GCM-SHA384"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => Some("DHE-RSA-AES128-SHA256"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => Some("DHE-RSA-AES256-SHA256"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => {
            Some("DHE-RSA-AES128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => {
            Some("DHE-RSA-AES256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => Some("DHE-DSS-AES128-SHA256"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => Some("DHE-DSS-AES256-SHA256"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 => {
            Some("DHE-DSS-AES128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 => {
            Some("DHE-DSS-AES256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => {
            Some("ECDHE-RSA-AES128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => {
            Some("ECDHE-RSA-AES256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            Some("ECDHE-RSA-AES128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            Some("ECDHE-RSA-AES256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => {
            Some("ECDHE-ECDSA-AES128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => {
            Some("ECDHE-ECDSA-AES256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            Some("ECDHE-ECDSA-AES128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            Some("ECDHE-ECDSA-AES256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_AES_128_CBC_SHA256 => Some("ADH-AES128-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA256 => Some("ADH-AES256-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_AES_128_GCM_SHA256 => Some("ADH-AES128-GCM-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_AES_256_GCM_SHA384 => Some("ADH-AES256-GCM-SHA384"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_128_CCM => Some("AES128-CCM"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_256_CCM => Some("AES256-CCM"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM => Some("DHE-RSA-AES128-CCM"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM => Some("DHE-RSA-AES256-CCM"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_128_CCM_8 => Some("AES128-CCM8"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_AES_256_CCM_8 => Some("AES256-CCM8"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8 => Some("DHE-RSA-AES128-CCM8"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8 => Some("DHE-RSA-AES256-CCM8"),
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM => Some("ECDHE-ECDSA-AES128-CCM"),
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM => Some("ECDHE-ECDSA-AES256-CCM"),
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 => Some("ECDHE-ECDSA-AES128-CCM8"),
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 => Some("ECDHE-ECDSA-AES256-CCM8"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_ARIA_128_GCM_SHA256 => Some("ARIA128-GCM-SHA256"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_ARIA_256_GCM_SHA384 => Some("ARIA256-GCM-SHA384"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 => {
            Some("DHE-RSA-ARIA128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 => {
            Some("DHE-RSA-ARIA256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 => {
            Some("DHE-DSS-ARIA128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 => {
            Some("DHE-DSS-ARIA256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 => {
            Some("ECDHE-ECDSA-ARIA128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 => {
            Some("ECDHE-ECDSA-ARIA256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 => {
            Some("ECDHE-ARIA128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 => {
            Some("ECDHE-ARIA256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_PSK_WITH_ARIA_128_GCM_SHA256 => Some("PSK-ARIA128-GCM-SHA256"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_ARIA_256_GCM_SHA384 => Some("PSK-ARIA256-GCM-SHA384"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 => {
            Some("DHE-PSK-ARIA128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 => {
            Some("DHE-PSK-ARIA256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 => {
            Some("RSA-PSK-ARIA128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 => {
            Some("RSA-PSK-ARIA256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("ECDHE-ECDSA-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => {
            Some("ECDHE-ECDSA-CAMELLIA256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("ECDHE-RSA-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 => {
            Some("ECDHE-RSA-CAMELLIA256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_PSK_WITH_NULL_SHA => Some("PSK-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA => Some("DHE-PSK-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA => Some("RSA-PSK-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_RC4_128_SHA => Some("PSK-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_3DES_EDE_CBC_SHA => Some("PSK-3DES-EDE-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA => Some("PSK-AES128-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA => Some("PSK-AES256-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_RC4_128_SHA => Some("DHE-PSK-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA => Some("DHE-PSK-3DES-EDE-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA => Some("DHE-PSK-AES128-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA => Some("DHE-PSK-AES256-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_RC4_128_SHA => Some("RSA-PSK-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA => Some("RSA-PSK-3DES-EDE-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA => Some("RSA-PSK-AES128-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA => Some("RSA-PSK-AES256-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256 => Some("PSK-AES128-GCM-SHA256"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384 => Some("PSK-AES256-GCM-SHA384"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 => {
            Some("DHE-PSK-AES128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 => {
            Some("DHE-PSK-AES256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 => {
            Some("RSA-PSK-AES128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 => {
            Some("RSA-PSK-AES256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256 => Some("PSK-AES128-CBC-SHA256"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384 => Some("PSK-AES256-CBC-SHA384"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_NULL_SHA256 => Some("PSK-NULL-SHA256"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_NULL_SHA384 => Some("PSK-NULL-SHA384"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 => {
            Some("DHE-PSK-AES128-CBC-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 => {
            Some("DHE-PSK-AES256-CBC-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA256 => Some("DHE-PSK-NULL-SHA256"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA384 => Some("DHE-PSK-NULL-SHA384"),
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 => {
            Some("RSA-PSK-AES128-CBC-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 => {
            Some("RSA-PSK-AES256-CBC-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA256 => Some("RSA-PSK-NULL-SHA256"),
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA384 => Some("RSA-PSK-NULL-SHA384"),
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_RC4_128_SHA => Some("ECDHE-PSK-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA => {
            Some("ECDHE-PSK-3DES-EDE-CBC-SHA")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA => Some("ECDHE-PSK-AES128-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA => Some("ECDHE-PSK-AES256-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 => {
            Some("ECDHE-PSK-AES128-CBC-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 => {
            Some("ECDHE-PSK-AES256-CBC-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA => Some("ECDHE-PSK-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA256 => Some("ECDHE-PSK-NULL-SHA256"),
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA384 => Some("ECDHE-PSK-NULL-SHA384"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 => Some("PSK-CAMELLIA128-SHA256"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 => Some("PSK-CAMELLIA256-SHA384"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("DHE-PSK-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => {
            Some("DHE-PSK-CAMELLIA256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("RSA-PSK-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 => {
            Some("RSA-PSK-CAMELLIA256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("ECDHE-PSK-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => {
            Some("ECDHE-PSK-CAMELLIA256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_128_CCM => Some("PSK-AES128-CCM"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_256_CCM => Some("PSK-AES256-CCM"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM => Some("DHE-PSK-AES128-CCM"),
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_AES_256_CCM => Some("DHE-PSK-AES256-CCM"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_128_CCM_8 => Some("PSK-AES128-CCM8"),
        rama_net::tls::CipherSuite::TLS_PSK_WITH_AES_256_CCM_8 => Some("PSK-AES256-CCM8"),
        rama_net::tls::CipherSuite::TLS_PSK_DHE_WITH_AES_128_CCM_8 => Some("DHE-PSK-AES128-CCM8"),
        rama_net::tls::CipherSuite::TLS_PSK_DHE_WITH_AES_256_CCM_8 => Some("DHE-PSK-AES256-CCM8"),
        rama_net::tls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("ECDHE-RSA-CHACHA20-POLY1305")
        }
        rama_net::tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("ECDHE-ECDSA-CHACHA20-POLY1305")
        }
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("DHE-RSA-CHACHA20-POLY1305")
        }
        rama_net::tls::CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => Some("PSK-CHACHA20-POLY1305"),
        rama_net::tls::CipherSuite::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("ECDHE-PSK-CHACHA20-POLY1305")
        }
        rama_net::tls::CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("DHE-PSK-CHACHA20-POLY1305")
        }
        rama_net::tls::CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("RSA-PSK-CHACHA20-POLY1305")
        }
        rama_net::tls::CipherSuite::TLS13_AES_128_GCM_SHA256 => Some("TLS_AES_128_GCM_SHA256"),
        rama_net::tls::CipherSuite::TLS13_AES_256_GCM_SHA384 => Some("TLS_AES_256_GCM_SHA384"),
        rama_net::tls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        rama_net::tls::CipherSuite::TLS13_AES_128_CCM_SHA256 => Some("TLS_AES_128_CCM_SHA256"),
        rama_net::tls::CipherSuite::TLS13_AES_128_CCM_8_SHA256 => Some("TLS_AES_128_CCM_8_SHA256"),
        rama_net::tls::CipherSuite::TLS_NULL_WITH_NULL_NULL => Some("NULL"),
        rama_net::tls::CipherSuite::TLS_RSA_EXPORT_WITH_RC4_40_MD5 => Some("EXP-RC4-MD5"),
        rama_net::tls::CipherSuite::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 => Some("EXP-RC2-CBC-MD5"),
        rama_net::tls::CipherSuite::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA => Some("EXP-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_DES_CBC_SHA => Some("DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA => Some("EXP-DH-DSS-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_DES_CBC_SHA => Some("DH-DSS-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA => Some("EXP-DH-RSA-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_DES_CBC_SHA => Some("DH-RSA-DES-CBC-SHA	"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA => {
            Some("EXP-EDH-DSS-DES-CBC-SHA")
        }
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_DES_CBC_SHA => Some("EDH-DSS-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA => {
            Some("EXP-EDH-RSA-DES-CBC-SHA")
        }
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_DES_CBC_SHA => Some("EDH-RSA-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 => Some("EXP-ADH-RC4-MD5"),
        rama_net::tls::CipherSuite::TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA => Some("EXP-ADH-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_DES_CBC_SHA => Some("ADH-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA => {
            Some("KRB5-DES-CBC-SHA")
        }
        rama_net::tls::CipherSuite::TLS_KRB5_WITH_3DES_EDE_CBC_SHA => Some("KRB5-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_KRB5_WITH_RC4_128_SHA => Some("KRB5-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_KRB5_WITH_IDEA_CBC_SHA => Some("KRB5-IDEA-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_KRB5_WITH_DES_CBC_MD5 => Some("KRB5-DES-CBC-MD5"),
        rama_net::tls::CipherSuite::TLS_KRB5_WITH_3DES_EDE_CBC_MD5 => Some("KRB5-DES-CBC3-MD5"),
        rama_net::tls::CipherSuite::TLS_KRB5_WITH_RC4_128_MD5 => Some("KRB5-RC4-MD5"),
        rama_net::tls::CipherSuite::TLS_KRB5_WITH_IDEA_CBC_MD5 => Some("KRB5-IDEA-CBC-MD5"),
        rama_net::tls::CipherSuite::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA => Some("EXP-KRB5-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA => Some("EXP-KRB5-RC2-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_KRB5_EXPORT_WITH_RC4_40_SHA => Some("EXP-KRB5-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 => Some("EXP-KRB5-DES-CBC-MD5"),
        rama_net::tls::CipherSuite::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 => Some("EXP-KRB5-RC2-CBC-MD5"),
        rama_net::tls::CipherSuite::TLS_KRB5_EXPORT_WITH_RC4_40_MD5 => Some("EXP-KRB5-RC4-MD5"),
        rama_net::tls::CipherSuite::TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 => Some("EXP1024-RC4-MD5"),
        rama_net::tls::CipherSuite::TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 => Some("EXP1024-RC2-CBC-MD5"),
        rama_net::tls::CipherSuite::TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA => Some("EXP1024-DES-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA => {
            Some("EXP1024-DHE-DSS-DES-CBC-SHA")
        }
        rama_net::tls::CipherSuite::TLS_RSA_EXPORT1024_WITH_RC4_56_SHA => Some("EXP1024-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA => {
            Some("EXP1024-DHE-DSS-RC4-SHA")
        }
        rama_net::tls::CipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 => Some("CAMELLIA256-SHA256"),
        rama_net::tls::CipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 => Some("CAMELLIA128-SHA256"),
        rama_net::tls::CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("DH-DSS-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("DH-RSA-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("DHE-DSS-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("DHE-RSA-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 => {
            Some("DHE-RSA-CAMELLIA256-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("ADH-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => Some("TLS_FALLBACK_SCSV"),
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_NULL_SHA => Some("ECDH-ECDSA-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_RC4_128_SHA => Some("ECDH-ECDSA-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA => Some("ECDH-ECDSA-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA => Some("ECDH-ECDSA-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA => Some("ECDH-ECDSA-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_NULL_SHA => Some("ECDH-RSA-NULL-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_RC4_128_SHA => Some("ECDH-RSA-RC4-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA => Some("ECDH-RSA-DES-CBC3-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA => Some("ECDH-RSA-AES128-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA => Some("ECDH-RSA-AES256-SHA"),
        rama_net::tls::CipherSuite::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA => Some("SRP-3DES-EDE-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA => {
            Some("SRP-RSA-3DES-EDE-CBC-SHA")
        }
        rama_net::tls::CipherSuite::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA => {
            Some("SRP-DSS-3DES-EDE-CBC-SHA")
        }
        rama_net::tls::CipherSuite::TLS_SRP_SHA_WITH_AES_128_CBC_SHA => Some("SRP-AES-128-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA => Some("SRP-RSA-AES-128-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA => Some("SRP-DSS-AES-128-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_SRP_SHA_WITH_AES_256_CBC_SHA => Some("SRP-AES-256-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA => Some("SRP-RSA-AES-256-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA => Some("SRP-DSS-AES-256-CBC-SHA"),
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 => {
            Some("ECDH-ECDSA-AES128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 => {
            Some("ECDH-ECDSA-AES256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 => Some("ECDH-RSA-AES128-SHA256"),
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 => Some("ECDH-RSA-AES256-SHA384"),
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 => {
            Some("ECDH-ECDSA-AES128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 => {
            Some("ECDH-ECDSA-AES256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 => {
            Some("ECDH-RSA-AES128-GCM-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => {
            Some("ECDH-RSA-AES256-GCM-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("ECDH-ECDSA-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => {
            Some("ECDH-ECDSA-CAMELLIA256-SHA384")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => {
            Some("ECDH-RSA-CAMELLIA128-SHA256")
        }
        rama_net::tls::CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 => {
            Some("ECDH-RSA-CAMELLIA256-SHA384")
        }
        other => {
            trace!(
                "openssl_cipher_str_From_cipher_suite: ignore cipher s
        uite: {other}"
            );
            None
        }
    }
}
