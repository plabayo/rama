//! Private C interface: the target's resolver layout and symbol aliases stay
//! behind the shim. Only Rama-owned records have matching C/Rust definitions.

use std::{
    ffi::{CStr, CString, c_void},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    ptr::NonNull,
};

use libc::{c_char, c_int, c_uint, c_ulong};
use rama_core::error::BoxError;

use super::{LinuxDnsResolverError, MAX_NAMESERVERS};

/// A snapshot of the resolver configuration, independent of `__res_state`.
///
/// Every value is accepted: the shim clamps `nscount` to the nameservers the
/// resolver was configured with before it reaches libc.
#[repr(C)]
#[derive(Default)]
pub(super) struct Config {
    pub(super) retrans: c_int,
    pub(super) retry: c_int,
    pub(super) nscount: c_int,
    pub(super) options: c_ulong,
    pub(super) ndots: c_uint,
}

#[repr(C)]
pub(super) struct QueryResult {
    pub(super) len: c_int,
    pub(super) system_error: c_int,
    pub(super) resolver_error: c_int,
}

#[repr(C)]
#[derive(Default)]
struct Nameserver {
    family: c_int,
    address: [u8; 16],
    port: u16,
    scope_id: u32,
}

pub(super) struct ResState {
    // Safety invariant: an initialized resolver returned by
    // `rama_res_create`, owned by this value and destroyed only by `Drop`.
    native: NonNull<c_void>,
    pub(super) config: Config,
    pub(super) search: Vec<CString>,
}

impl ResState {
    pub(super) fn new() -> Result<Self, BoxError> {
        let mut config = Config::default();
        // SAFETY: `rama_res_create` writes the config it is given, a writable
        // local, and returns a uniquely owned, initialized resolver or null
        // (resolv_wrapper.c). The `native` invariant holds once non-null.
        let native = NonNull::new(unsafe { rama_res_create(&mut config) }).ok_or_else(|| {
            let error = std::io::Error::last_os_error();
            let message = match error.raw_os_error() {
                Some(0) | None => "native resolver initialization failed".to_owned(),
                _ => format!("native resolver initialization failed: {error}"),
            };
            LinuxDnsResolverError::message(message)
        })?;
        let mut state = Self {
            native,
            config,
            search: Vec::new(),
        };
        for index in 0.. {
            // SAFETY: `rama_res_search` reads a live resolver (the `native`
            // invariant) and returns null for an index outside `MAXDNSRCH`, or
            // the entry of libc's null-terminated `dnsrch` list.
            let suffix = unsafe { rama_res_search(state.native.as_ptr(), index) };
            if suffix.is_null() {
                break;
            }
            // SAFETY: `CStr::from_ptr`: a non-null `dnsrch` entry is a
            // NUL-terminated string owned by the resolver (resolv.h), which
            // nothing writes or frees until `Drop`; it is copied out at once.
            state
                .search
                .push(unsafe { CStr::from_ptr(suffix) }.to_owned());
        }
        Ok(state)
    }

    pub(super) fn query(&mut self, name: &CStr, rrtype: c_int, answer: &mut [u8]) -> QueryResult {
        let capacity = c_int::try_from(answer.len()).unwrap_or(c_int::MAX);
        // SAFETY: `rama_res_query` needs a live resolver no other call uses
        // (the `native` invariant and `&mut self`), a writable config (any
        // values: it clamps `nscount`), a NUL-terminated name (`&CStr`), and
        // an answer buffer writable for `capacity` bytes: `capacity` is at
        // most `answer.len()` and not negative.
        unsafe {
            rama_res_query(
                self.native.as_ptr(),
                &mut self.config,
                name.as_ptr(),
                rrtype,
                answer.as_mut_ptr(),
                capacity,
            )
        }
    }

    pub(super) fn nameservers(&self, count: c_int) -> Vec<SocketAddr> {
        (0..count.clamp(0, MAX_NAMESERVERS))
            .filter_map(|index| {
                let mut server = Nameserver::default();
                // SAFETY: `rama_res_nameserver` reads a live resolver (the
                // `native` invariant), returns 0 for an index outside its
                // nameservers, and writes only the record `server` it is given.
                if unsafe { rama_res_nameserver(self.native.as_ptr(), index, &mut server) } == 0 {
                    return None;
                }
                match server.family {
                    4 => Some(SocketAddr::from((
                        Ipv4Addr::new(
                            server.address[0],
                            server.address[1],
                            server.address[2],
                            server.address[3],
                        ),
                        server.port,
                    ))),
                    6 => Some(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(server.address),
                        server.port,
                        0,
                        server.scope_id,
                    ))),
                    _ => None,
                }
            })
            .collect()
    }
}

impl Drop for ResState {
    fn drop(&mut self) {
        // SAFETY: `rama_res_destroy` closes and frees a resolver from
        // `rama_res_create` once: the `native` invariant, and drop runs once.
        unsafe { rama_res_destroy(self.native.as_ptr()) };
    }
}

// Compiling against the target headers also preserves the resolver symbol
// mappings used by glibc before/after 2.34, including cargo-zigbuild's 2.17 ABI.
// These functions live in rama_dns_resolv; libresolv supplies its dependencies.
#[link(name = "resolv")]
unsafe extern "C" {
    fn rama_res_create(config: *mut Config) -> *mut c_void;
    fn rama_res_destroy(resolver: *mut c_void);
    fn rama_res_search(resolver: *const c_void, index: c_int) -> *const c_char;
    fn rama_res_nameserver(resolver: *const c_void, index: c_int, out: *mut Nameserver) -> c_int;
    fn rama_res_query(
        resolver: *mut c_void,
        config: *mut Config,
        name: *const c_char,
        rrtype: c_int,
        answer: *mut u8,
        capacity: c_int,
    ) -> QueryResult;
}

// DNS class/type constants mirrored from glibc's resolver headers.
//
// Sources:
// - https://codebrowser.dev/glibc/glibc/resolv/arpa/nameser_compat.h.html
// - https://codebrowser.dev/glibc/glibc/resolv/arpa/nameser.h.html

/// Internet
pub(super) const NS_C_IN: u16 = 1;

/// A (IPv4)
pub(super) const NS_T_A: u16 = 1;
/// CNAME (canonical name)
pub(super) const NS_T_CNAME: u16 = 5;
/// SOA (Start of Authority)
pub(super) const NS_T_SOA: u16 = 6;
/// TXT
pub(super) const NS_T_TXT: u16 = 16;
/// AAAA (IPv6)
pub(super) const NS_T_AAAA: u16 = 28;

// Resolver h_errno values from <netdb.h>.
//
// Source:
// - https://codebrowser.dev/glibc/glibc/resolv/netdb.h.html

/// Authoritative Answer Host not found.
pub(super) const HOST_NOT_FOUND: c_int = 1;
/// Non-authoritative failure: SERVFAIL, or no nameserver answered.
pub(super) const TRY_AGAIN: c_int = 2;
/// Non-recoverable failure, e.g. FORMERR or a name too long to ask.
#[cfg(test)]
pub(super) const NO_RECOVERY: c_int = 3;
/// Valid name, no data record of requested type.
pub(super) const NO_DATA: c_int = 4;

// Search options from glibc's <resolv.h>.

/// Search a name without dots in the default domain.
pub(super) const RES_DEFNAMES: libc::c_ulong = 0x80;
/// Search a dotted relative name in the search list.
pub(super) const RES_DNSRCH: libc::c_ulong = 0x200;
/// Take a truncated answer as is, rather than asking again over TCP.
pub(super) const RES_IGNTC: libc::c_ulong = 0x20;
/// Ask over TCP only (`use-vc`).
pub(super) const RES_USEVC: libc::c_ulong = 0x08;
/// Do not ask a name without dots as is once it was searched.
pub(super) const RES_NOTLDQUERY: libc::c_ulong = 0x0100_0000;

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, thread, time::Duration};

    use super::*;

    // Importing the dev dependency supplies the fixture's native link metadata.
    use rama_dns_native_tests as _;

    unsafe extern "C" {
        fn rama_res_test_override_nameservers(
            resolver: *mut c_void,
            servers: *const Nameserver,
            count: c_int,
        ) -> c_int;
        fn rama_res_test_contract() -> c_int;
        fn rama_res_test_layout(index: usize) -> usize;
    }

    impl ResState {
        pub(in super::super) fn override_ipv4_nameservers(&mut self, ports: &[u16]) {
            let servers: Vec<_> = ports
                .iter()
                .map(|&port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
                .collect();
            self.override_nameservers(&servers);
        }

        fn override_nameservers(&mut self, servers: &[SocketAddr]) {
            let servers: Vec<_> = servers
                .iter()
                .take(MAX_NAMESERVERS as usize)
                .map(|server| {
                    let mut record = Nameserver {
                        port: server.port(),
                        ..Nameserver::default()
                    };
                    match server {
                        SocketAddr::V4(server) => {
                            record.family = 4;
                            record.address[..4].copy_from_slice(&server.ip().octets());
                        }
                        SocketAddr::V6(server) => {
                            record.family = 6;
                            record.address = server.ip().octets();
                            record.scope_id = server.scope_id();
                        }
                    }
                    record
                })
                .collect();
            let count = c_int::try_from(servers.len()).unwrap();
            // SAFETY: the resolver is exclusively borrowed and servers holds count
            // initialized records. The helper releases the old native resources.
            assert_eq!(
                unsafe {
                    rama_res_test_override_nameservers(
                        self.native.as_ptr(),
                        servers.as_ptr(),
                        count,
                    )
                },
                1
            );
            self.config.nscount = count;
        }
    }

    #[test]
    fn native_shim_preserves_ownership_and_error_contracts() {
        // SAFETY: the C fixture owns its isolated resolver state and uses
        // deterministic libc replacements; zero means every assertion passed.
        let failed_line = unsafe { rama_res_test_contract() };
        assert_eq!(failed_line, 0, "resolv_wrapper_tests.c:{failed_line}");
    }

    #[test]
    fn every_shared_record_matches_the_target_c_abi() {
        use std::mem::{align_of, offset_of, size_of};
        let layout = [
            size_of::<Config>(),
            align_of::<Config>(),
            offset_of!(Config, retrans),
            offset_of!(Config, retry),
            offset_of!(Config, nscount),
            offset_of!(Config, options),
            offset_of!(Config, ndots),
            size_of::<QueryResult>(),
            align_of::<QueryResult>(),
            offset_of!(QueryResult, len),
            offset_of!(QueryResult, system_error),
            offset_of!(QueryResult, resolver_error),
            size_of::<Nameserver>(),
            align_of::<Nameserver>(),
            offset_of!(Nameserver, family),
            offset_of!(Nameserver, address),
            offset_of!(Nameserver, port),
            offset_of!(Nameserver, scope_id),
        ];
        for (index, expected) in layout.into_iter().enumerate() {
            // SAFETY: this pure C accessor returns one size_t, with no pointers.
            assert_eq!(
                unsafe { rama_res_test_layout(index) },
                expected,
                "layout entry {index}"
            );
        }
    }

    #[test]
    fn config_is_read_from_libc_and_search_suffixes_outlive_resolver() {
        const CHILD: &str = "RAMA_DNS_TEST_RESOLVER_CONFIG";
        if std::env::var_os(CHILD).is_none() {
            // Give libc deterministic settings in a fresh process, without
            // mutating the environment while other tests run on other threads.
            let path = concat!(
                module_path!(),
                "::config_is_read_from_libc_and_search_suffixes_outlive_resolver"
            );
            let (_, filter) = path.split_once("::").unwrap(); // libtest omits the crate name
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", filter, "--format=pretty"])
                .env(CHILD, "1")
                .env("LOCALDOMAIN", "corp.test other.test")
                .env("RES_OPTIONS", "ndots:5 timeout:2 attempts:1")
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout)
                        .contains("test result: ok. 1 passed;"),
                "child resolver test failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            return;
        }
        let mut state = ResState::new().unwrap();
        assert_eq!(state.config.ndots, 5);
        assert_eq!(state.config.retrans, 2);
        assert_eq!(state.config.retry, 1);
        let suffixes = std::mem::take(&mut state.search);
        drop(state);
        assert_eq!(
            suffixes,
            [c"corp.test".to_owned(), c"other.test".to_owned()]
        );
    }

    #[test]
    fn native_nameservers_keep_their_ports_and_requested_count() {
        let mut state = ResState::new().unwrap();
        state.override_ipv4_nameservers(&[12345, 23456]);
        let expected = [
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 23456)),
        ];
        assert_eq!(state.nameservers(2), expected);
        assert_eq!(state.nameservers(1), expected[..1]);
    }

    #[test]
    fn mixed_nameservers_preserve_ipv6_address_port_and_scope() {
        let mut state = ResState::new().unwrap();
        let expected = [
            "[fe80::1234%7]:853".parse().unwrap(),
            "192.0.2.1:23456".parse().unwrap(),
            "[::1]:34567".parse().unwrap(),
        ];
        state.override_nameservers(&expected);
        assert_eq!(state.nameservers(3), expected);
        assert_eq!(state.nameservers(1), expected[..1]);
        assert_eq!(state.nameservers(c_int::MAX), expected);
        assert!(state.nameservers(-1).is_empty());
        // Replacing the set must release its native IPv6 allocations.
        state.override_ipv4_nameservers(&[12345]);
        assert_eq!(
            state.nameservers(3),
            ["127.0.0.1:12345".parse::<SocketAddr>().unwrap()]
        );
        state.override_nameservers(&[]);
        assert!(state.nameservers(3).is_empty());
    }

    #[test]
    fn query_asks_at_most_the_configured_nameservers() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut state = ResState::new().unwrap();
        state.override_ipv4_nameservers(&[socket.local_addr().unwrap().port()]);
        state.config.retrans = 1;
        state.config.retry = 1;
        state.config.options &= !RES_USEVC;
        // libc indexes its MAXNS-sized arrays below this count.
        state.config.nscount = c_int::MAX;
        let responder = thread::spawn(move || {
            let mut packet = [0; 512];
            let (len, peer) = socket.recv_from(&mut packet).unwrap();
            let mut response = packet[..len].to_vec();
            response[2..4].copy_from_slice(&[0x81, 0x83]); // NXDOMAIN
            socket.send_to(&response, peer).unwrap();
        });
        let mut response = [0; 512];
        let result = state.query(c"clamp.stub.test.", c_int::from(NS_T_A), &mut response);
        responder.join().unwrap();
        assert_eq!(result.resolver_error, HOST_NOT_FOUND);
        assert_eq!(state.config.nscount, 1);
    }

    #[test]
    fn query_returns_a_successful_response() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut state = ResState::new().unwrap();
        state.override_ipv4_nameservers(&[socket.local_addr().unwrap().port()]);
        state.config.retrans = 1;
        state.config.retry = 1;
        state.config.options &= !RES_USEVC;
        let responder = thread::spawn(move || {
            let mut packet = [0; 512];
            let (len, peer) = socket.recv_from(&mut packet).unwrap();
            let mut question_end = 12;
            while packet[question_end] != 0 {
                question_end += usize::from(packet[question_end]) + 1;
            }
            question_end += 5; // terminal label, QTYPE and QCLASS
            assert!(question_end <= len);
            let mut response = packet[..question_end].to_vec();
            response[2..4].copy_from_slice(&[0x81, 0x80]);
            response[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 42]);
            socket.send_to(&response, peer).unwrap();
        });
        let mut response = [0; 512];
        let result = state.query(c"ffi.stub.test.", c_int::from(NS_T_A), &mut response);
        responder.join().unwrap();
        assert!(result.len > 0);
        // errno is unspecified on success. The deterministic C fixture
        // checks that it is cleared before a query and captured on failure.
        assert_eq!(
            &response[result.len as usize - 4..result.len as usize],
            &[127, 0, 0, 42]
        );
    }
}
