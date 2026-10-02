//! glibc's search walk (`__res_context_search`), asking one name at a time,
//! so each name's own answer, rcode and timing count; plus the TCP retry a
//! truncated answer needs, bounded by the lookup's deadline.

use std::{
    env,
    ffi::{CStr, CString},
    fs,
    io::{self, Read as _, Write as _},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream},
    ptr,
    time::{Duration, Instant},
};

use libc::c_int;
use rama_core::error::BoxError;
use rama_net::address::Domain;

use super::{
    DNS_HEADER_SIZE, INITIAL_RESPONSE_BUFFER_SIZE, LinuxDnsResolverError, MAX_NAMESERVERS,
    clear_errno, dns_name_from_domain, ffi, fit_retransmits, grow_response_buffer, try_secs,
    whole_secs,
};
use crate::{
    client::limit::DnsTimeoutError,
    wire::{MessageHeader, Name, RecordClass, ResponseCode},
};

/// Where a name of the walk comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The name as is, before the search list: it has `ndots` dots or more.
    AsIsFirst,
    Search {
        root: bool,
    },
    /// The name as is, once the search list came up empty.
    AsIsLast,
}

#[derive(Debug)]
struct Step {
    name: CString,
    kind: Kind,
    /// An earlier step asking the very same name, whose answer this reuses.
    same_as: Option<usize>,
}

/// The names glibc asks for one lookup, in its order.
#[derive(Debug)]
pub(super) struct Walk {
    steps: Vec<Step>,
    /// The first name decides alone: a rooted name, or a HOSTALIASES alias.
    alone: bool,
    /// A name without dots is not asked as is once searched (`NOTLDQUERY`).
    no_tld_query: bool,
}

/// One name's outcome.
#[derive(Debug)]
pub(super) enum Asked {
    Answer(Vec<u8>),
    NxDomain(Vec<u8>),
    NoData(Vec<u8>),
    ServerFailure(ResponseCode),
    Timeout,
    /// No nameserver took the query at all.
    Unreachable,
    Failed(BoxError),
}

impl Asked {
    /// The response a lookup hands its parser, or why there is none.
    pub(super) fn into_packet(self, timeout: Duration) -> Result<Option<Vec<u8>>, BoxError> {
        match self {
            Self::Answer(packet) | Self::NxDomain(packet) | Self::NoData(packet) => {
                Ok(Some(packet))
            }
            Self::ServerFailure(code) => {
                Err(LinuxDnsResolverError::message(format!("dns server answered {code:?}")).into())
            }
            Self::Timeout => Err(DnsTimeoutError::new(timeout).into()),
            Self::Unreachable => {
                Err(LinuxDnsResolverError::message("no dns nameserver reachable").into())
            }
            Self::Failed(err) => Err(err),
        }
    }
}

impl Walk {
    /// The names `__res_context_search` asks for `name`, with `alias` its
    /// HOSTALIASES entry, if any.
    pub(super) fn new(
        state: &ffi::ResState,
        name: &str,
        alias: Option<CString>,
    ) -> Result<Self, BoxError> {
        let dots = name.bytes().filter(|&byte| byte == b'.').count();
        let mut walk = Self {
            steps: Vec::new(),
            alone: false,
            no_tld_query: dots == 0 && state.options & ffi::RES_NOTLDQUERY != 0,
        };
        if let Some(alias) = alias {
            walk.alone = true;
            walk.push(alias, Kind::AsIsFirst);
            return Ok(walk);
        }
        let as_is = dns_name_from_domain(name)?;
        if name.ends_with('.') {
            walk.alone = true;
            walk.push(as_is, Kind::AsIsFirst);
            return Ok(walk);
        }

        let as_is_first = dots >= state.ndots() as usize;
        if as_is_first {
            walk.push(as_is.clone(), Kind::AsIsFirst);
        }
        let flag = if dots == 0 {
            ffi::RES_DEFNAMES
        } else {
            ffi::RES_DNSRCH
        };
        if state.options & flag != 0 {
            // without DNSRCH only the default domain is asked
            let domains = if state.options & ffi::RES_DNSRCH != 0 {
                state.dnsrch.len()
            } else {
                1
            };
            for &domain in state.dnsrch.iter().take(domains) {
                if domain.is_null() {
                    break;
                }
                // SAFETY: `res_ninit` points each set entry at a NUL-terminated
                // domain living as long as `state`, and nulls the rest
                let domain = unsafe { CStr::from_ptr(domain) }.to_bytes();
                let domain = domain.strip_prefix(b".").unwrap_or(domain);
                let searched = [name.as_bytes(), b".", domain].concat();
                let searched = CString::new(searched).map_err(|_e| {
                    LinuxDnsResolverError::message("dns search domain contains a NUL byte")
                })?;
                walk.push(
                    searched,
                    Kind::Search {
                        root: domain.is_empty(),
                    },
                );
            }
        }
        if !as_is_first {
            walk.push(as_is, Kind::AsIsLast);
        }
        Ok(walk)
    }

    fn push(&mut self, name: CString, kind: Kind) {
        let key = trim_root(name.to_bytes());
        let same_as = self
            .steps
            .iter()
            .position(|step| trim_root(step.name.to_bytes()).eq_ignore_ascii_case(key));
        self.steps.push(Step {
            name,
            kind,
            same_as,
        });
    }

    /// An empty outcome per step, for [`Self::run`] to fill.
    pub(super) fn outcomes(&self) -> Vec<Option<Asked>> {
        self.steps.iter().map(|_| None).collect()
    }

    /// Walks the names as glibc does, asking each name without an outcome
    /// with its share of the time left. Returns the step whose outcome
    /// decides, as glibc's final `h_errno` picks it.
    pub(super) fn run(
        &self,
        outcomes: &mut [Option<Asked>],
        deadline: Instant,
        mut ask: impl FnMut(&CStr, Duration) -> Asked,
    ) -> usize {
        let (mut as_is_first, mut no_data, mut server_failure) = (None, None, None);
        let (mut searched, mut root_searched, mut done) = (false, false, false);
        let mut last = 0;
        for (i, step) in self.steps.iter().enumerate() {
            match step.kind {
                Kind::Search { .. } if done => continue,
                Kind::AsIsLast if root_searched || (searched && self.no_tld_query) => continue,
                _ => {}
            }
            let at = step.same_as.unwrap_or(i);
            let share = self.sharing(i, outcomes);
            let asked = outcomes[at].get_or_insert_with(|| {
                let left = deadline.saturating_duration_since(Instant::now());
                ask(&self.steps[at].name, left / share)
            });
            last = at;
            if self.alone || matches!(asked, Asked::Answer(_)) {
                return at;
            }
            match step.kind {
                Kind::AsIsFirst => as_is_first = Some(at),
                Kind::Search { root } => {
                    searched = true;
                    root_searched |= root;
                    match asked {
                        Asked::Unreachable => return at,
                        Asked::NoData(_) => _ = no_data.get_or_insert(at),
                        Asked::NxDomain(_) => {}
                        Asked::ServerFailure(ResponseCode::ServFail) => {
                            _ = server_failure.get_or_insert(at);
                        }
                        _ => done = true,
                    }
                }
                Kind::AsIsLast => {}
            }
        }
        as_is_first.or(no_data).or(server_failure).unwrap_or(last)
    }

    /// How many names share the time left when step `i` is asked: a timeout
    /// ends the search list, so it can still lead to one more name.
    fn sharing(&self, i: usize, outcomes: &[Option<Asked>]) -> u32 {
        let position =
            |wanted: fn(Kind) -> bool| self.steps.iter().position(|step| wanted(step.kind));
        let next = match self.steps[i].kind {
            Kind::AsIsFirst => position(|kind| matches!(kind, Kind::Search { .. })),
            Kind::Search { .. } => {
                let root_searched = self.steps[..=i]
                    .iter()
                    .any(|step| step.kind == Kind::Search { root: true });
                (!root_searched && !self.no_tld_query)
                    .then(|| position(|kind| kind == Kind::AsIsLast))
                    .flatten()
            }
            Kind::AsIsLast => None,
        };
        let unasked = next.is_some_and(|j| {
            let at = self.steps[j].same_as.unwrap_or(j);
            at != self.steps[i].same_as.unwrap_or(i) && outcomes[at].is_none()
        });
        1 + u32::from(unasked)
    }
}

fn trim_root(name: &[u8]) -> &[u8] {
    name.strip_suffix(b".").unwrap_or(name)
}

/// The HOSTALIASES entry of a name without dots, which glibc asks instead.
pub(super) fn hostalias(name: &str) -> Option<CString> {
    if name.contains('.') {
        return None;
    }
    let aliases = fs::read(env::var_os("HOSTALIASES")?).ok()?;
    alias_in(&aliases, name)
}

/// `name`'s alias in a HOSTALIASES file, read as glibc's
/// `__res_context_hostalias` reads it.
fn alias_in(aliases: &[u8], name: &str) -> Option<CString> {
    // C's `isspace`
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    for line in aliases.split_inclusive(|&byte| byte == b'\n') {
        // a line without whitespace ends the file
        let end = line.iter().position(space)?;
        if !trim_root(&line[..end]).eq_ignore_ascii_case(trim_root(name.as_bytes())) {
            continue;
        }
        let rest = &line[end + 1..];
        let alias = &rest[rest.iter().position(|byte| !space(byte))?..];
        let len = alias.iter().position(space).unwrap_or(alias.len());
        return CString::new(&alias[..len]).ok();
    }
    None
}

/// Asks `name` once, retransmitting within `budget` from libc's configured
/// `tries`; a truncated answer is asked again over TCP.
pub(super) fn ask(
    state: &mut ffi::ResState,
    tries: (c_int, c_int),
    name: &CStr,
    rrtype: c_int,
    max_response_size: usize,
    budget: Duration,
) -> Asked {
    let deadline = Instant::now() + budget;
    (state.retrans, state.retry) = tries;
    fit_retransmits(state, budget);

    let mut buffer = vec![0_u8; INITIAL_RESPONSE_BUFFER_SIZE.min(max_response_size)];
    loop {
        clear_errno();
        // a failure's header then shows whether, and how, a server answered
        buffer[..DNS_HEADER_SIZE].fill(0);
        let called = Instant::now();
        // SAFETY:
        // - `state` is initialized by `res_ninit`.
        // - `name` is a valid NUL-terminated DNS name.
        // - `buffer` is writable response storage of the given length.
        let len = unsafe {
            ffi::res_nquery(
                state,
                name.as_ptr(),
                c_int::from(ffi::NS_C_IN),
                rrtype,
                buffer.as_mut_ptr(),
                c_int::try_from(buffer.len()).unwrap_or(c_int::MAX),
            )
        };
        let header = MessageHeader::parse(&buffer)
            .ok()
            .filter(MessageHeader::is_response);
        if header.is_some_and(|header| header.is_truncated()) {
            return ask_over_tcp(state, name, rrtype, deadline, max_response_size);
        }
        if let Ok(len) = usize::try_from(len) {
            return match grow_response_buffer(&mut buffer, len, max_response_size) {
                Ok(true) => continue,
                Ok(false) => {
                    buffer.truncate(len);
                    Asked::Answer(buffer)
                }
                Err(err) => Asked::Failed(err),
            };
        }

        let errno = io::Error::last_os_error().raw_os_error();
        return failed(state.res_h_errno, buffer, errno, called.elapsed());
    }
}

/// What a failed `res_nquery` means. libc reports `TRY_AGAIN` also for a
/// SERVFAIL, NOTIMP or REFUSED answer, whose header stays in `response`, and
/// for a failure it meets at once; only silence keeps libc waiting a second
/// at least.
fn failed(h_errno: c_int, response: Vec<u8>, errno: Option<c_int>, waited: Duration) -> Asked {
    let code = MessageHeader::parse(&response)
        .ok()
        .filter(MessageHeader::is_response)
        .map(|header| header.response_code());
    match h_errno {
        ffi::HOST_NOT_FOUND => Asked::NxDomain(response),
        0 | ffi::NO_DATA => Asked::NoData(response),
        ffi::TRY_AGAIN => match code {
            Some(
                code @ (ResponseCode::ServFail | ResponseCode::NotImp | ResponseCode::Refused),
            ) => Asked::ServerFailure(code),
            _ if errno == Some(libc::ECONNREFUSED) => Asked::Unreachable,
            _ if waited >= Duration::from_millis(900) => Asked::Timeout,
            _ => Asked::Failed(failure(h_errno, errno)),
        },
        _ => Asked::Failed(failure(h_errno, errno)),
    }
}

fn failure(h_errno: c_int, errno: Option<c_int>) -> BoxError {
    LinuxDnsResolverError::message(format!(
        "res_nquery failed (h_errno={h_errno}, errno={errno:?})"
    ))
    .into()
}

/// Whether another try of `names` timed-out names still fits before
/// `deadline`: libc waits at least a second per nameserver. Like the budget
/// itself, it rounds to the nearest second, so a try may end half a second
/// late.
pub(super) fn another_try(state: &ffi::ResState, deadline: Instant, names: usize) -> bool {
    let left = deadline.saturating_duration_since(Instant::now());
    let shortest = try_secs(1, state.nscount.clamp(1, MAX_NAMESERVERS));
    let names = c_int::try_from(names.max(1)).unwrap_or(c_int::MAX);
    whole_secs(left) / names >= shortest
}

/// Asks `name` over TCP, as a truncated answer requires (RFC 7766), within
/// `deadline`: libc's own TCP retry waits without one.
fn ask_over_tcp(
    state: &ffi::ResState,
    name: &CStr,
    rrtype: c_int,
    deadline: Instant,
    max_response_size: usize,
) -> Asked {
    let query = match TcpQuery::new(name, rrtype) {
        Ok(query) => query,
        Err(err) => return Asked::Failed(err),
    };
    let mut asked = Asked::Unreachable;
    for server in nameservers(state) {
        asked = match exchange(server, &query.wire, deadline, max_response_size) {
            Ok(response) => query.outcome(response),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Asked::Timeout;
            }
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => Asked::Unreachable,
            Err(err) => Asked::Failed(err.into()),
        };
        // like libc, a failing server hands the query to the next one
        if !matches!(asked, Asked::ServerFailure(_) | Asked::Unreachable) {
            break;
        }
    }
    asked
}

/// A query in TCP framing: its length, then the message.
struct TcpQuery {
    id: u16,
    question: Name,
    rrtype: u16,
    wire: Vec<u8>,
}

impl TcpQuery {
    fn new(name: &CStr, rrtype: c_int) -> Result<Self, BoxError> {
        let domain = Domain::try_from(name.to_str()?)?;
        let question = Name::from(&domain);
        let rrtype = u16::try_from(rrtype)?;
        let id: u16 = rand::random();
        let message_len = DNS_HEADER_SIZE + question.as_wire().len() + 4;
        let mut wire = Vec::with_capacity(2 + message_len);
        wire.extend_from_slice(&u16::try_from(message_len)?.to_be_bytes());
        wire.extend_from_slice(&id.to_be_bytes());
        // recursion desired, one question
        wire.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        wire.extend_from_slice(question.as_wire());
        wire.extend_from_slice(&rrtype.to_be_bytes());
        wire.extend_from_slice(&u16::from(RecordClass::IN).to_be_bytes());
        Ok(Self {
            id,
            question,
            rrtype,
            wire,
        })
    }

    /// What `response` says, if it answers this query.
    fn outcome(&self, response: Vec<u8>) -> Asked {
        let Ok(header) = MessageHeader::parse(&response) else {
            return Asked::Failed(
                LinuxDnsResolverError::message("dns TCP answer shorter than a header").into(),
            );
        };
        let answers_this = header.id() == self.id
            && header.is_response()
            && Name::from_message(&response, DNS_HEADER_SIZE).is_ok_and(|(name, len)| {
                let end = DNS_HEADER_SIZE + len;
                name == self.question
                    && response.get(end..end + 2) == Some(self.rrtype.to_be_bytes().as_slice())
            });
        if !answers_this {
            return Asked::Failed(
                LinuxDnsResolverError::message("dns TCP answer is for another query").into(),
            );
        }
        match header.response_code() {
            ResponseCode::NoError if header.answer_count() > 0 => Asked::Answer(response),
            ResponseCode::NoError => Asked::NoData(response),
            ResponseCode::NXDomain => Asked::NxDomain(response),
            code @ (ResponseCode::ServFail | ResponseCode::NotImp | ResponseCode::Refused) => {
                Asked::ServerFailure(code)
            }
            code => Asked::Failed(
                LinuxDnsResolverError::message(format!("dns server answered {code:?}")).into(),
            ),
        }
    }
}

/// The nameservers `res_ninit` read, as glibc's `__res_get_nsaddr` picks
/// them: once used, `_ext` holds a copy of each, also of an IPv4 one.
fn nameservers(state: &ffi::ResState) -> impl Iterator<Item = SocketAddr> + '_ {
    let count = usize::try_from(state.nscount.clamp(0, MAX_NAMESERVERS)).unwrap_or(0);
    (0..count).filter_map(|ns| {
        // SAFETY: `res_ninit` initialized `_ext`, the variant glibc uses
        let copy = unsafe { state._u._ext.nsaddrs[ns] };
        if copy.is_null() {
            return v4(&state.nsaddr_list[ns]);
        }
        // SAFETY: a set entry points at a `sockaddr_in6`-sized copy the state
        // owns, whose family says which address it holds
        let copy = unsafe { &*copy };
        if c_int::from(copy.sin6_family) == libc::AF_INET {
            // SAFETY: an IPv4 copy starts with a whole `sockaddr_in`
            return v4(unsafe { &*ptr::from_ref(copy).cast() });
        }
        (c_int::from(copy.sin6_family) == libc::AF_INET6).then(|| {
            // SAFETY: each variant of the address union is plain octets
            let octets = unsafe { copy.sin6_addr.__in6_u.__u6_addr8 };
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                u16::from_be(copy.sin6_port),
                0,
                copy.sin6_scope_id,
            ))
        })
    })
}

fn v4(address: &ffi::SockaddrIn) -> Option<SocketAddr> {
    (c_int::from(address.sin_family) == libc::AF_INET).then(|| {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
            u16::from_be(address.sin_port),
        ))
    })
}

/// One TCP exchange with `server`, every step of it within `deadline`.
fn exchange(
    server: SocketAddr,
    query: &[u8],
    deadline: Instant,
    max_response_size: usize,
) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&server, left(deadline)?)?;
    stream.set_write_timeout(Some(left(deadline)?))?;
    stream.write_all(query)?;
    let mut len = [0; 2];
    read_full(&mut stream, &mut len, deadline)?;
    let len = usize::from(u16::from_be_bytes(len));
    if len > max_response_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            LinuxDnsResolverError::message(format!(
                "dns TCP answer exceeds configured maximum: required={len} maximum={max_response_size}"
            )),
        ));
    }
    let mut response = vec![0; len];
    read_full(&mut stream, &mut response, deadline)?;
    Ok(response)
}

fn left(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(left)
}

/// Fills `buffer`, a peer trickling bytes included, by `deadline`.
fn read_full(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        stream.set_read_timeout(Some(left(deadline)?))?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => filled += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;

    const CORP: &CStr = c"corp.test";
    const ROOT: &CStr = c".";

    fn state(search: &[&CStr], ndots: u32, options: libc::c_ulong) -> ffi::ResState {
        // SAFETY: `__res_state` is plain old data; zeroed is a valid value.
        let mut state: ffi::ResState = unsafe { mem::zeroed() };
        state.options = options;
        state.set_ndots(ndots);
        for (entry, domain) in state.dnsrch.iter_mut().zip(search) {
            *entry = domain.as_ptr().cast_mut();
        }
        state
    }

    const SEARCH: libc::c_ulong = ffi::RES_DEFNAMES | ffi::RES_DNSRCH;

    /// The names a walk asks, `=` marking one asked before.
    fn names(walk: &Walk) -> Vec<String> {
        walk.steps
            .iter()
            .map(|step| {
                let name = step.name.to_str().unwrap();
                let kind = match step.kind {
                    Kind::AsIsFirst => "first",
                    Kind::Search { root: false } => "search",
                    Kind::Search { root: true } => "root",
                    Kind::AsIsLast => "last",
                };
                let reused = if step.same_as.is_some() { "=" } else { "" };
                format!("{kind}:{reused}{name}")
            })
            .collect()
    }

    fn walk(name: &str, search: &[&CStr], ndots: u32, options: libc::c_ulong) -> Vec<String> {
        names(&Walk::new(&state(search, ndots, options), name, None).unwrap())
    }

    #[test]
    fn the_walk_asks_the_names_glibc_asks() {
        // enough dots: as is first, then the search list
        assert_eq!(
            walk("api.example", &[CORP], 1, SEARCH),
            ["first:api.example", "search:api.example.corp.test"]
        );
        // too few dots: the search list first, then as is
        assert_eq!(
            walk("intranet", &[CORP], 1, SEARCH),
            ["search:intranet.corp.test", "last:intranet"]
        );
        assert_eq!(
            walk("api.example", &[CORP], 5, SEARCH),
            ["search:api.example.corp.test", "last:api.example"]
        );
        // systemd-resolved's stub writes `search .`: the same query as as is
        assert_eq!(
            walk("api.example", &[ROOT], 1, SEARCH),
            ["first:api.example", "root:=api.example."]
        );
        assert_eq!(
            walk("intranet", &[ROOT], 1, SEARCH),
            ["root:intranet.", "last:=intranet"]
        );
        assert_eq!(
            walk("api.example", &[c""], 1, SEARCH),
            ["first:api.example", "root:=api.example."]
        );
        // a rooted name skips the search list
        assert_eq!(
            walk("api.example.", &[CORP], 1, SEARCH),
            ["first:api.example."]
        );
        // no search list
        assert_eq!(walk("api.example", &[], 1, SEARCH), ["first:api.example"]);
        assert_eq!(walk("intranet", &[], 1, SEARCH), ["last:intranet"]);
        assert_eq!(
            walk("api.example", &[CORP, ROOT, c"other.test"], 1, SEARCH),
            [
                "first:api.example",
                "search:api.example.corp.test",
                "root:=api.example.",
                "search:api.example.other.test",
            ]
        );
    }

    #[test]
    fn search_options_shape_the_walk() {
        // without DNSRCH a dotted name is not searched
        assert_eq!(
            walk("api.example", &[CORP], 1, ffi::RES_DEFNAMES),
            ["first:api.example"]
        );
        // and a name without dots only gets the default domain
        assert_eq!(
            walk("intranet", &[CORP, c"other.test"], 1, ffi::RES_DEFNAMES),
            ["search:intranet.corp.test", "last:intranet"]
        );
        assert_eq!(walk("intranet", &[CORP], 1, 0), ["last:intranet"]);
        // a HOSTALIASES alias is asked alone
        let state = state(&[CORP], 1, SEARCH);
        let aliased = Walk::new(&state, "intranet", Some(c"real.example".to_owned())).unwrap();
        assert_eq!(names(&aliased), ["first:real.example"]);
        assert!(aliased.alone);
    }

    /// Runs `walk` against scripted outcomes, returning the names asked with
    /// their share of the time left, and the deciding outcome.
    fn run(walk: &Walk, mut script: impl FnMut(&str) -> Asked) -> (Vec<(String, u64)>, Asked) {
        let mut outcomes = walk.outcomes();
        let mut asked = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let at = walk.run(&mut outcomes, deadline, |name, budget| {
            let name = name.to_str().unwrap().to_owned();
            // whole seconds: the time left drifts while the test runs
            asked.push((name.clone(), budget.as_secs_f64().round() as u64));
            script(&name)
        });
        (asked, outcomes[at].take().unwrap())
    }

    fn walk_of(name: &str, search: &[&CStr], ndots: u32, options: libc::c_ulong) -> Walk {
        Walk::new(&state(search, ndots, options), name, None).unwrap()
    }

    #[test]
    fn a_slow_servfail_next_to_a_search_answer_stays_an_error() {
        let walk = walk_of("api.example", &[CORP], 1, SEARCH);
        let (asked, decided) = run(&walk, |name| match name {
            "api.example" => Asked::ServerFailure(ResponseCode::ServFail),
            _ => Asked::NxDomain(Vec::new()),
        });
        assert_eq!(asked.len(), 2);
        assert!(
            matches!(decided, Asked::ServerFailure(ResponseCode::ServFail)),
            "{decided:?}"
        );
    }

    #[test]
    fn a_timeout_next_to_a_search_answer_stays_a_timeout() {
        // as is first: its outcome decides
        let walk = walk_of("api.example", &[CORP], 1, SEARCH);
        let (asked, decided) = run(&walk, |name| match name {
            "api.example" => Asked::Timeout,
            _ => Asked::NxDomain(Vec::new()),
        });
        // a timeout could still lead to the search name: the time is shared
        assert_eq!(
            asked,
            [
                ("api.example".to_owned(), 5),
                ("api.example.corp.test".to_owned(), 10)
            ]
        );
        assert!(matches!(decided, Asked::Timeout), "{decided:?}");

        // as is last: the last name asked decides
        let walk = walk_of("intranet", &[CORP], 1, SEARCH);
        let (_, decided) = run(&walk, |name| match name {
            "intranet" => Asked::Timeout,
            _ => Asked::NxDomain(Vec::new()),
        });
        assert!(matches!(decided, Asked::Timeout), "{decided:?}");
    }

    #[test]
    fn the_search_list_continues_as_glibc_continues() {
        let walk = walk_of("intranet", &[CORP, c"other.test"], 1, SEARCH);
        // a SERVFAIL tries the next domain, and decides over a later NXDOMAIN
        let (asked, decided) = run(&walk, |name| match name {
            "intranet.corp.test" => Asked::ServerFailure(ResponseCode::ServFail),
            _ => Asked::NxDomain(Vec::new()),
        });
        assert_eq!(asked.len(), 3);
        assert!(
            matches!(decided, Asked::ServerFailure(ResponseCode::ServFail)),
            "{decided:?}"
        );

        // REFUSED ends the search list, the name as is still goes out
        let (asked, _) = run(&walk, |name| match name {
            "intranet.corp.test" => Asked::ServerFailure(ResponseCode::Refused),
            _ => Asked::NxDomain(Vec::new()),
        });
        let asked: Vec<_> = asked.into_iter().map(|(name, _)| name).collect();
        assert_eq!(asked, ["intranet.corp.test", "intranet"]);

        // NODATA keeps searching and decides over a later NXDOMAIN
        let (_, decided) = run(&walk, |name| match name {
            "intranet.other.test" => Asked::NoData(Vec::new()),
            _ => Asked::NxDomain(Vec::new()),
        });
        assert!(matches!(decided, Asked::NoData(_)), "{decided:?}");

        // an answer ends the walk
        let (asked, decided) = run(&walk, |name| match name {
            "intranet.other.test" => Asked::Answer(vec![1]),
            _ => Asked::NxDomain(Vec::new()),
        });
        assert_eq!(asked.len(), 2);
        assert!(matches!(decided, Asked::Answer(_)), "{decided:?}");

        // no nameserver at all ends it too
        let (asked, decided) = run(&walk, |_| Asked::Unreachable);
        assert_eq!(asked.len(), 1);
        assert!(matches!(decided, Asked::Unreachable), "{decided:?}");
    }

    #[test]
    fn the_root_and_notldquery_skip_the_last_as_is() {
        let walk = walk_of("intranet", &[ROOT], 1, SEARCH);
        let (asked, decided) = run(&walk, |_| Asked::NxDomain(Vec::new()));
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert!(matches!(decided, Asked::NxDomain(_)), "{decided:?}");

        let walk = walk_of("intranet", &[CORP], 1, SEARCH | ffi::RES_NOTLDQUERY);
        let (asked, _) = run(&walk, |_| Asked::NxDomain(Vec::new()));
        assert_eq!(asked.len(), 1, "{asked:?}");
    }

    #[test]
    fn the_same_name_is_asked_once() {
        // as is, then the root entry: one query for both
        let walk = walk_of("api.example", &[ROOT], 1, SEARCH);
        let (asked, decided) = run(&walk, |_| Asked::NxDomain(Vec::new()));
        assert_eq!(asked, [("api.example".to_owned(), 10)]);
        assert!(matches!(decided, Asked::NxDomain(_)), "{decided:?}");
    }

    #[test]
    fn a_retried_walk_asks_only_the_names_that_timed_out() {
        let walk = walk_of("api.example", &[CORP], 1, SEARCH);
        let mut outcomes = walk.outcomes();
        let deadline = Instant::now() + Duration::from_secs(10);
        let first = walk.run(&mut outcomes, deadline, |name, _| match name.to_bytes() {
            b"api.example" => Asked::Timeout,
            _ => Asked::NxDomain(Vec::new()),
        });
        assert!(matches!(outcomes[first], Some(Asked::Timeout)));

        for outcome in &mut outcomes {
            if matches!(outcome, Some(Asked::Timeout)) {
                *outcome = None;
            }
        }
        let mut asked = Vec::new();
        let again = walk.run(&mut outcomes, deadline, |name, budget| {
            asked.push((
                name.to_str().unwrap().to_owned(),
                budget.as_secs_f64().round() as u64,
            ));
            Asked::Answer(vec![1])
        });
        // the search name already answered: as is gets all the time left
        assert_eq!(asked, [("api.example".to_owned(), 10)]);
        assert!(matches!(outcomes[again], Some(Asked::Answer(_))));
    }

    #[test]
    fn aliases_read_as_glibc_reads_them() {
        let aliases =
            b"other  elsewhere.example\nINTRANET\treal.example extra\nlast first.example\n";
        let alias = |name| alias_in(aliases, name).map(|alias| alias.into_string().unwrap());
        assert_eq!(alias("intranet").as_deref(), Some("real.example"));
        assert_eq!(alias("other").as_deref(), Some("elsewhere.example"));
        assert_eq!(alias("missing"), None);
        // a name with nothing after it, or a line without whitespace, ends the file
        assert_eq!(
            alias_in(b"intranet \nintranet real.example\n", "intranet"),
            None
        );
        assert_eq!(alias_in(b"nowhitespace", "intranet"), None);
        assert_eq!(hostalias("api.example"), None);
    }

    #[test]
    fn a_failure_reads_as_glibc_meant_it() {
        let silence = vec![0; DNS_HEADER_SIZE];
        let waited = Duration::from_secs(1);
        let fail =
            |h_errno, response: &[u8], errno| failed(h_errno, response.to_vec(), errno, waited);
        let timeout = Some(libc::ETIMEDOUT);
        assert!(matches!(
            fail(ffi::TRY_AGAIN, &silence, timeout),
            Asked::Timeout
        ));
        assert!(matches!(
            fail(ffi::HOST_NOT_FOUND, &silence, None),
            Asked::NxDomain(_)
        ));
        assert!(matches!(
            fail(ffi::NO_DATA, &silence, None),
            Asked::NoData(_)
        ));
        assert!(matches!(
            fail(ffi::NO_RECOVERY, &silence, None),
            Asked::Failed(_)
        ));
        // no nameserver took the query
        let refused = Some(libc::ECONNREFUSED);
        assert!(matches!(
            fail(ffi::TRY_AGAIN, &silence, refused),
            Asked::Unreachable
        ));
        // a reply rejected at once is no silence
        let at_once = failed(ffi::TRY_AGAIN, silence.clone(), timeout, Duration::ZERO);
        assert!(matches!(at_once, Asked::Failed(_)));
        // a SERVFAIL, NOTIMP or REFUSED answer reads as a timeout to libc
        let mut answer = silence;
        for (rcode, code) in [
            (0x82, ResponseCode::ServFail),
            (0x84, ResponseCode::NotImp),
            (0x85, ResponseCode::Refused),
        ] {
            answer[2..4].copy_from_slice(&[0x81, rcode]);
            let asked = fail(ffi::TRY_AGAIN, &answer, timeout);
            assert!(
                matches!(asked, Asked::ServerFailure(got) if got == code),
                "{asked:?}"
            );
        }
    }

    #[test]
    fn another_try_needs_a_second_per_nameserver() {
        // SAFETY: `__res_state` is plain old data; zeroed is a valid value.
        let mut state: ffi::ResState = unsafe { mem::zeroed() };
        let after = |millis| Instant::now() + Duration::from_millis(millis);
        state.nscount = 1;
        assert!(!another_try(&state, after(400), 1));
        assert!(another_try(&state, after(700), 1));
        // a second for each of two names
        assert!(!another_try(&state, after(1200), 2));
        assert!(another_try(&state, after(1700), 2));
        state.nscount = 3;
        assert!(!another_try(&state, after(2300), 1));
        assert!(another_try(&state, after(2700), 1));
    }

    #[test]
    fn tcp_queries_ask_one_question() {
        let query = TcpQuery::new(c"big.stub.test", 16).unwrap();
        let message = &query.wire[2..];
        assert_eq!(
            usize::from(u16::from_be_bytes([query.wire[0], query.wire[1]])),
            message.len()
        );
        let header = MessageHeader::parse(message).unwrap();
        assert!(header.is_recursion_desired() && !header.is_response());
        assert_eq!((header.id(), header.question_count()), (query.id, 1));
        let (name, len) = Name::from_message(message, DNS_HEADER_SIZE).unwrap();
        assert_eq!(name, query.question);
        assert_eq!(&message[DNS_HEADER_SIZE + len..], &[0, 16, 0, 1]);

        // an answer to another query does not count
        let mut response = message.to_vec();
        response[2] |= 0x80;
        assert!(matches!(query.outcome(response.clone()), Asked::NoData(_)));
        response[0] ^= 0xff;
        assert!(matches!(query.outcome(response), Asked::Failed(_)));
    }
}
