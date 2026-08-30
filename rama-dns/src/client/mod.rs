pub mod resolver;

mod connector;
#[doc(inline)]
pub use connector::{DnsConnector, DnsConnectorLayer};

#[cfg(feature = "hickory")]
#[cfg_attr(docsrs, doc(cfg(feature = "hickory")))]
pub mod hickory;
#[cfg(feature = "hickory")]
#[cfg_attr(docsrs, doc(cfg(feature = "hickory")))]
#[doc(inline)]
pub use self::hickory::HickoryDnsResolver;

mod tokio;
#[doc(inline)]
pub use self::tokio::{
    TokioDnsResolver, TokioDnsServiceBindingUnsupportedError, TokioDnsTxtUnsupportedError,
};

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(target_vendor = "apple")]
#[cfg_attr(docsrs, doc(cfg(target_vendor = "apple")))]
#[doc(inline)]
pub use self::apple::AppleDnsResolver;
#[cfg(target_vendor = "apple")]
#[cfg_attr(docsrs, doc(cfg(target_vendor = "apple")))]
pub type NativeDnsResolver = AppleDnsResolver;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
#[cfg_attr(docsrs, doc(cfg(target_os = "windows")))]
#[doc(inline)]
pub use self::windows::WindowsDnsResolver;
#[cfg(target_os = "windows")]
#[cfg_attr(docsrs, doc(cfg(target_os = "windows")))]
pub type NativeDnsResolver = WindowsDnsResolver;

// also compiled under test on any unix so the varlink client and its
// availability state machine are exercised on non-linux dev hosts
#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
mod systemd_resolved;

// dependency-free wire parsing, split out from the varlink client so the
// fuzz target below can compile it on any host without the linux-only deps
mod systemd_resolved_wire;

#[doc(hidden)]
pub mod fuzzing {
    /// Fuzz hook for the resolved wire-format RR parser: must never panic,
    /// and every TXT segment must derive from within the input buffer.
    /// Returns the TXT ttl + segment count, `None` for non-TXT verdicts.
    pub fn parse_txt_rr(raw: &[u8]) -> Option<(u32, usize)> {
        match super::systemd_resolved_wire::parse_txt_rr(raw) {
            super::systemd_resolved_wire::RrParse::Record {
                ttl,
                value: segments,
            } => {
                let total: usize = segments.iter().map(|segment| segment.len() + 1).sum();
                assert!(total <= raw.len(), "TXT segments exceed input buffer");
                Some((ttl, segments.len()))
            }
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn hook_reports_txt_verdicts() {
            // owner "a" | TXT IN ttl=7 rdlen=4 | rdata: "hi" + one empty segment
            let mut raw = vec![1, b'a', 0, 0, 16, 0, 1, 0, 0, 0, 7, 0, 4, 2, b'h', b'i', 0];
            assert_eq!(super::parse_txt_rr(&raw), Some((7, 2)));

            raw[3..5].copy_from_slice(&5_u16.to_be_bytes()); // CNAME: not txt
            assert_eq!(super::parse_txt_rr(&raw), None);

            assert_eq!(super::parse_txt_rr(&[0xC0]), None); // malformed
        }
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
#[doc(inline)]
pub use self::linux::LinuxDnsResolver;
#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
pub type NativeDnsResolver = LinuxDnsResolver;

#[cfg(not(any(target_vendor = "apple", target_os = "windows", target_os = "linux")))]
#[cfg_attr(
    docsrs,
    doc(cfg(not(any(target_vendor = "apple", target_os = "windows", target_os = "linux"))))
)]
pub type NativeDnsResolver = TokioDnsResolver;

mod deny_all;
#[doc(inline)]
pub use self::deny_all::{DenyAllDnsResolver, DnsDeniedError};

mod empty;
#[doc(inline)]
pub use self::empty::EmptyDnsResolver;

mod global;
#[doc(inline)]
pub use global::{GlobalDnsResolver, init_global_dns_resolver, try_init_global_dns_resolver};

mod chain;
mod tuple;
mod variant;

pub mod lb;
