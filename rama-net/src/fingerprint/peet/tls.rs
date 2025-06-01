//! PeetPrint implementation for Rama (in Rust).
//!
//! PeetPrint is inspired by the custom fingerprint algorithm from TrackMe.
//! See license information below:
//!
//! > Original work from:
//! >   https://github.com/pagpeter/TrackMe
//! >
//! > Licensed under GPLv3.
//! > See https://github.com/pagpeter/TrackMe/blob/master/LICENSE for license details.

use crate::fingerprint::ClientHelloProvider;
use crate::tls::client::ClientHelloExtension;
use crate::tls::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CipherSuite, ExtensionId,
    ProtocolVersion, SecureTransport, SignatureScheme, SupportedGroup,
};
use itertools::Itertools;
use rama_core::context::Extensions;
use std::fmt;

#[derive(Clone)]
/// Input data for a "peetprint" fingerprint.
///
/// Computed using a future `PeetPrint::compute` method.
pub struct PeetPrint {
    supported_tls_versions: Vec<ProtocolVersion>,
    supported_protocols: Vec<ApplicationProtocol>,
    supported_groups: Vec<SupportedGroup>,
    supported_signature_algorithms: Vec<SignatureScheme>,
    psk_key_exchange_mode: Option<u8>,
    certificate_compression_algorithms: Option<Vec<CertificateCompressionAlgorithm>>,
    cipher_suites: Vec<CipherSuite>,
    sorted_extensions: Vec<String>,
}

impl PeetPrint {
    pub fn compute(ext: &Extensions) -> Result<Self, PeetComputeError> {
        let client_hello = ext
            .get::<SecureTransport>()
            .and_then(|st| st.client_hello())
            .ok_or(PeetComputeError::MissingClientHello)?;
        Self::compute_from_client_hello(client_hello)
    }

    pub fn compute_from_client_hello(
        client_hello: impl ClientHelloProvider,
    ) -> Result<Self, PeetComputeError> {
        let cipher_suites: Vec<CipherSuite> = client_hello
            .cipher_suites()
            .filter(|c| !c.is_grease())
            .collect();

        if cipher_suites.is_empty() {
            return Err(PeetComputeError::EmptyCipherSuites);
        }

        let mut supported_tls_versions = Vec::new();
        let mut supported_protocols = Vec::new();
        let mut supported_groups = Vec::new();
        let mut supported_signature_algorithms = Vec::new();
        let mut psk_key_exchange_mode = None;
        let mut certificate_compression_algorithms = Vec::new();
        let mut sorted_extensions = Vec::new();

        for ext in client_hello.extensions() {
            let id = ext.id();

            if id.is_grease() {
                sorted_extensions.push("GREASE".to_owned());
                continue;
            }

            sorted_extensions.push(u16::from(id).to_string());

            match ext {
                ClientHelloExtension::SupportedVersions(versions) => {
                    supported_tls_versions.extend(versions.iter().copied());
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpns) => {
                    for p in alpns {
                        match p {
                            ApplicationProtocol::HTTP_10 => {}
                            ApplicationProtocol::HTTP_11 => {}
                            ApplicationProtocol::HTTP_2 => {}
                            _ => {
                                continue;
                            }
                        }

                        supported_protocols.push(p.clone());
                    }
                }
                ClientHelloExtension::SupportedGroups(groups) => {
                    supported_groups.extend(groups.iter().copied());
                }
                ClientHelloExtension::SignatureAlgorithms(algos) => {
                    supported_signature_algorithms.extend(algos.iter().copied());
                }
                ClientHelloExtension::Opaque { id: ext_id, data }
                    if *ext_id == ExtensionId::from(45) =>
                {
                    if data.len() < 2 {
                        psk_key_exchange_mode = None;
                    } else {
                        psk_key_exchange_mode = Some(data[1]);
                    }
                }
                ClientHelloExtension::CertificateCompression(algs) => {
                    certificate_compression_algorithms.extend(algs.iter().cloned());
                }
                _ => {}
            }
        }

        sorted_extensions.sort();

        Ok(Self {
            supported_tls_versions,
            supported_protocols,
            supported_groups,
            supported_signature_algorithms,
            psk_key_exchange_mode,
            certificate_compression_algorithms: if certificate_compression_algorithms.is_empty() {
                None
            } else {
                Some(certificate_compression_algorithms)
            },
            cipher_suites,
            sorted_extensions,
        })
    }

    #[inline]
    pub fn to_human_string(&self) -> String {
        format!("{self:?}")
    }

    pub fn fmt_as(&self, f: &mut fmt::Formatter<'_>, hash_chunks: bool) -> fmt::Result {
        let tls_versions_str: String = self
            .supported_tls_versions
            .iter()
            .map(|v| {
                if v.is_grease() {
                    "GREASE".to_owned()
                } else {
                    u16::from(*v).to_string()
                }
            })
            .collect_vec()
            .join("-");

        // Process protocols; normalize HTTP values
        let protos: Vec<String> = self
            .supported_protocols
            .iter()
            .map(|p| {
                let lower = p.to_string().to_lowercase();
                if lower == "h2" || lower == "http/2" {
                    "2".to_owned()
                } else if lower == "http/1.1" {
                    "1.1".to_owned()
                } else if lower == "http/1.0" {
                    "1.0".to_owned()
                } else {
                    lower
                }
            })
            .collect();

        let protos_str = protos.join("-");

        let groups_str = self
            .supported_groups
            .iter()
            .map(|g| {
                if g.is_grease() {
                    "GREASE".to_owned()
                } else {
                    u16::from(*g).to_string()
                }
            })
            .collect_vec()
            .join("-");

        let sig_algs_str = self
            .supported_signature_algorithms
            .iter()
            .map(|sa| {
                if sa.is_grease() {
                    "GREASE".to_owned()
                } else {
                    u16::from(*sa).to_string()
                }
            })
            .collect_vec()
            .join("-");

        let key_mode_str = self
            .psk_key_exchange_mode
            .map(|val| val.to_owned())
            .unwrap_or_default();

        let comp_algs_str = if let Some(comps) = &self.certificate_compression_algorithms {
            comps
                .iter()
                .map(|ca| {
                    if ca.is_grease() {
                        "GREASE".to_owned()
                    } else {
                        u16::from(*ca).to_string()
                    }
                })
                .collect_vec()
                .join("-")
        } else {
            String::new()
        };

        let suites_str = self
            .cipher_suites
            .iter()
            .map(|cs| {
                if cs.is_grease() {
                    "GREASE".to_owned()
                } else {
                    u16::from(*cs).to_string()
                }
            })
            .collect_vec()
            .join("-");

        let exts_str = self.sorted_extensions.join("-");

        let fp = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            tls_versions_str,
            protos_str,
            groups_str,
            sig_algs_str,
            key_mode_str,
            comp_algs_str,
            suites_str,
            exts_str
        );

        if hash_chunks {
            write!(f, "{}", hash(&fp))
        } else {
            write!(f, "{}", fp)
        }
    }
}

impl fmt::Display for PeetPrint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(f, true)
    }
}

impl fmt::Debug for PeetPrint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(f, false)
    }
}

fn hash(s: &str) -> String {
    let hash = md5::compute(s);
    hex::encode(*hash)
}

#[derive(Debug, Clone)]
pub enum PeetComputeError {
    MissingClientHello,
    EmptyCipherSuites,
    InvalidTlsVersion,
}

impl fmt::Display for PeetComputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeetComputeError::MissingClientHello => write!(f, "PeetPrint: missing client hello"),
            PeetComputeError::EmptyCipherSuites => write!(f, "PeetPrint: no cipher suites found"),
            PeetComputeError::InvalidTlsVersion => {
                write!(f, "Ja4 Compute Error: invalid tls version")
            }
        }
    }
}

impl std::error::Error for PeetComputeError {}

#[cfg(test)]
mod tests {
    use crate::tls::client::parse_client_hello;

    use super::*;

    #[derive(Debug)]
    struct TestCase {
        client_hello: Vec<u8>,
        pcap: &'static str,
        expected_peet_str: &'static str,
        expected_peet_hash: &'static str,
    }

    #[test]
    fn test_peet_compute() {
        let test_cases = [TestCase {
            client_hello: vec![
                0x3, 0x3, 0x86, 0xad, 0xa4, 0xcc, 0x19, 0xe7, 0x14, 0x54, 0x54, 0xfd, 0xe7, 0x37,
                0x33, 0xdf, 0x66, 0xcb, 0xf6, 0xef, 0x3e, 0xc0, 0xa1, 0x54, 0xc6, 0xdd, 0x14, 0x5e,
                0xc0, 0x83, 0xac, 0xb9, 0xb4, 0xe7, 0x20, 0x1c, 0x64, 0xae, 0xa7, 0xa2, 0xc3, 0xe1,
                0x8c, 0xd1, 0x25, 0x2, 0x4d, 0xf7, 0x86, 0x4a, 0xc7, 0x19, 0xd0, 0xc4, 0xbd, 0xfb,
                0x40, 0xc2, 0xef, 0x7f, 0x6d, 0xd3, 0x9a, 0xa7, 0x53, 0xdf, 0xdd, 0x0, 0x22, 0x1a,
                0x1a, 0x13, 0x1, 0x13, 0x2, 0x13, 0x3, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0,
                0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x0, 0x9c, 0x0, 0x9d, 0x0,
                0x2f, 0x0, 0x35, 0x0, 0xa, 0x1, 0x0, 0x1, 0x91, 0xa, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x20, 0x0, 0x1e, 0x0, 0x0, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x64,
                0x73, 0x2e, 0x67, 0x2e, 0x64, 0x6f, 0x75, 0x62, 0x6c, 0x65, 0x63, 0x6c, 0x69, 0x63,
                0x6b, 0x2e, 0x6e, 0x65, 0x74, 0x0, 0x17, 0x0, 0x0, 0xff, 0x1, 0x0, 0x1, 0x0, 0x0,
                0xa, 0x0, 0xa, 0x0, 0x8, 0x9a, 0x9a, 0x0, 0x1d, 0x0, 0x17, 0x0, 0x18, 0x0, 0xb,
                0x0, 0x2, 0x1, 0x0, 0x0, 0x23, 0x0, 0x0, 0x0, 0x10, 0x0, 0xe, 0x0, 0xc, 0x2, 0x68,
                0x32, 0x8, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x0, 0x5, 0x0, 0x5, 0x1,
                0x0, 0x0, 0x0, 0x0, 0x0, 0xd, 0x0, 0x14, 0x0, 0x12, 0x4, 0x3, 0x8, 0x4, 0x4, 0x1,
                0x5, 0x3, 0x8, 0x5, 0x5, 0x1, 0x8, 0x6, 0x6, 0x1, 0x2, 0x1, 0x0, 0x12, 0x0, 0x0,
                0x0, 0x33, 0x0, 0x2b, 0x0, 0x29, 0x9a, 0x9a, 0x0, 0x1, 0x0, 0x0, 0x1d, 0x0, 0x20,
                0x59, 0x8, 0x6f, 0x41, 0x9a, 0xa5, 0xaa, 0x1d, 0x81, 0xe3, 0x47, 0xf0, 0x25, 0x5f,
                0x92, 0x7, 0xfc, 0x4b, 0x13, 0x74, 0x51, 0x46, 0x98, 0x8, 0x74, 0x3b, 0xde, 0x57,
                0x86, 0xe8, 0x2c, 0x74, 0x0, 0x2d, 0x0, 0x2, 0x1, 0x1, 0x0, 0x2b, 0x0, 0xb, 0xa,
                0xfa, 0xfa, 0x3, 0x4, 0x3, 0x3, 0x3, 0x2, 0x3, 0x1, 0x0, 0x1b, 0x0, 0x3, 0x2, 0x0,
                0x2, 0xba, 0xba, 0x0, 0x1, 0x0, 0x0, 0x15, 0x0, 0xbd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ],
            pcap: "chrome-grease-single.pcap",
            expected_peet_str: "GREASE-772-771-770-769|2-1.1|GREASE-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537-513|1|2|4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10|0-10-11-13-16-18-21-23-27-35-43-45-5-51-65281-GREASE-GREASE",
            expected_peet_hash: "4edb562771dce19be4223f5839af62c9",
        }];
        for test_case in test_cases {
            let mut ext = Extensions::new();
            ext.insert(SecureTransport::with_client_hello(
                parse_client_hello(&test_case.client_hello).expect(test_case.pcap),
            ));

            let ja4 = PeetPrint::compute(&ext).expect(test_case.pcap);

            assert_eq!(
                test_case.expected_peet_str,
                format!("{ja4:?}"),
                "pcap: {}",
                test_case.pcap,
            );

            assert_eq!(
                test_case.expected_peet_hash,
                format!("{ja4}"),
                "pcap: {}",
                test_case.pcap,
            );
        }
    }
}
