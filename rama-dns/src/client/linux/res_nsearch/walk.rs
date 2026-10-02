//! glibc's search walk (`__res_context_search`), asking one name at a time,
//! so each name's own answer, rcode and timing count; plus the TCP retry a
//! truncated answer needs, bounded by the lookup's deadline.

use std::{
    env,
    ffi::{CStr, CString, OsString},
    fs,
    io::{self, BufRead, Read as _, Write as _},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream},
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use libc::c_int;
use parking_lot::Mutex;
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
    /// HOSTALIASES entry, if any, and `full_search` the whole search list.
    pub(super) fn new(
        state: &ffi::ResState,
        name: &str,
        alias: Option<CString>,
        full_search: impl FnOnce() -> Arc<[Box<[u8]>]>,
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
            let kept: Vec<&[u8]> = state
                .dnsrch
                .iter()
                .take_while(|domain| !domain.is_null())
                // SAFETY: `res_ninit` points each set entry at a NUL-terminated
                // domain living as long as `state`, and nulls the rest
                .map(|&domain| unsafe { CStr::from_ptr(domain) }.to_bytes())
                .collect();
            let mut domains = search_domains(&kept, full_search);
            // without DNSRCH only the default domain is asked
            if state.options & ffi::RES_DNSRCH == 0 {
                domains.truncate(1);
            }
            for domain in &domains {
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
                // libc waits a second at least: with under half of one left,
                // the name would only be answered after the deadline
                if left < Duration::from_millis(500) {
                    return Asked::Timeout;
                }
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

/// `MAXDNSRCH`, and the size of `defdname`: what `res_ninit` copies of the
/// search list into `dnsrch`.
const KEPT_SEARCH_DOMAINS: usize = 6;
const KEPT_SEARCH_BYTES: usize = 256;
/// The longest name in presentation form.
const MAX_DOMAIN_LEN: usize = 253;

/// The search list glibc walks: `res_ninit` keeps at most six domains, in
/// 256 bytes, so a longer list is read again whole, as glibc read it.
fn search_domains(kept: &[&[u8]], full: impl FnOnce() -> Arc<[Box<[u8]>]>) -> Vec<Box<[u8]>> {
    let used: usize = kept.iter().map(|domain| domain.len() + 1).sum();
    // room for six domains of any length, NULs included: nothing was cut
    let cut = kept.len() == KEPT_SEARCH_DOMAINS
        || KEPT_SEARCH_BYTES.saturating_sub(used) < MAX_DOMAIN_LEN + 1;
    if cut {
        let full = full();
        if full.len() > kept.len() && full.iter().zip(kept).all(|(full, kept)| **full == **kept) {
            return full.to_vec();
        }
    }
    kept.iter().map(|&domain| Box::from(domain)).collect()
}

/// `_PATH_RESCONF`.
const RESOLV_CONF: &str = "/etc/resolv.conf";

#[derive(PartialEq, Eq)]
struct SearchSource {
    conf: PathBuf,
    localdomain: Option<OsString>,
    metadata: Option<(Option<SystemTime>, u64, u64)>,
}

/// glibc's whole search list, read again only once `LOCALDOMAIN` or
/// resolv.conf changed.
pub(super) fn full_search_list() -> Arc<[Box<[u8]>]> {
    search_list_in(Path::new(RESOLV_CONF), env::var_os("LOCALDOMAIN"))
}

fn search_list_in(conf: &Path, localdomain: Option<OsString>) -> Arc<[Box<[u8]>]> {
    static READ: Mutex<Option<(SearchSource, Arc<[Box<[u8]>]>)>> = Mutex::new(None);
    let source = SearchSource {
        conf: conf.to_owned(),
        localdomain,
        metadata: fs::metadata(conf)
            .ok()
            .map(|meta| (meta.modified().ok(), meta.len(), meta.ino())),
    };
    let mut read = READ.lock();
    if let Some((was, list)) = read.as_ref()
        && *was == source
    {
        return list.clone();
    }
    let text = match source.localdomain {
        Some(_) => Vec::new(),
        None => fs::read(conf).unwrap_or_default(),
    };
    let localdomain = source.localdomain.as_ref().map(|value| value.as_bytes());
    let list: Arc<[Box<[u8]>]> = parse_search_list(localdomain, &text).into();
    *read = Some((source, list.clone()));
    list
}

/// The search list of glibc's `res_vinit_1`: `LOCALDOMAIN`, else the last
/// `domain` or `search` line of resolv.conf.
fn parse_search_list(localdomain: Option<&[u8]>, conf: &[u8]) -> Vec<Box<[u8]>> {
    let words = |line: &[u8]| -> Vec<Box<[u8]>> {
        line.split(|&byte| matches!(byte, b' ' | b'\t'))
            .filter(|word| !word.is_empty())
            .map(Box::from)
            .collect()
    };
    if let Some(localdomain) = localdomain {
        let line = localdomain
            .split(|&byte| byte == b'\n')
            .next()
            .unwrap_or_default();
        // glibc keeps the first word even when empty: the root
        let first = line
            .split(|&byte| matches!(byte, b' ' | b'\t'))
            .next()
            .unwrap_or_default();
        let mut list = vec![Box::from(first)];
        list.extend(words(line).into_iter().skip(usize::from(!first.is_empty())));
        return list;
    }
    let mut list = Vec::new();
    for line in conf.split(|&byte| byte == b'\n') {
        // libc's string functions end the line at a NUL
        let line = until_nul(line);
        if let Some(rest) = keyword(line, b"domain") {
            if let Some(domain) = words(rest).into_iter().next() {
                list = vec![domain];
            }
        } else if let Some(rest) = keyword(line, b"search") {
            let domains = words(rest);
            if !domains.is_empty() {
                list = domains;
            }
        }
    }
    list
}

fn until_nul(line: &[u8]) -> &[u8] {
    line.split(|&byte| byte == 0).next().unwrap_or_default()
}

/// What follows `name` in `line`, glibc's `MATCH`: the keyword, then a blank.
fn keyword<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let rest = line.strip_prefix(name)?;
    matches!(rest.first(), Some(b' ' | b'\t')).then_some(rest)
}

/// The HOSTALIASES entry of a name without dots, which glibc asks instead.
pub(super) fn hostalias(name: &str) -> Option<CString> {
    if name.contains('.') {
        return None;
    }
    let aliases = fs::File::open(env::var_os("HOSTALIASES")?).ok()?;
    alias_in(io::BufReader::new(aliases), name)
}

/// `name`'s alias in a HOSTALIASES file, read as glibc's
/// `__res_context_hostalias` reads it, a `fgets` line at a time.
fn alias_in(mut aliases: impl BufRead, name: &str) -> Option<CString> {
    // C's `isspace`
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let mut line = Vec::new();
    loop {
        line.clear();
        // `fgets` into `BUFSIZ`: a line, or the next part of a longer one
        let read = aliases
            .by_ref()
            .take(8191)
            .read_until(b'\n', &mut line)
            .ok()?;
        if read == 0 {
            return None;
        }
        // a line without whitespace before a NUL ends the file
        let line = until_nul(&line);
        let end = line.iter().position(space)?;
        if !trim_root(&line[..end]).eq_ignore_ascii_case(trim_root(name.as_bytes())) {
            continue;
        }
        let rest = &line[end + 1..];
        let alias = &rest[rest.iter().position(|byte| !space(byte))?..];
        let len = alias.iter().position(space).unwrap_or(alias.len());
        return CString::new(&alias[..len]).ok();
    }
}

/// How resolv.conf has libc ask: retransmits, and the nameservers to ask.
#[derive(Debug, Clone, Copy)]
pub(super) struct Tries {
    pub(super) retrans: c_int,
    pub(super) retry: c_int,
    pub(super) nscount: c_int,
    /// `use-vc`: TCP only.
    pub(super) tcp: bool,
}

/// Asks `name` once, retransmitting within `budget` as `tries` allow; a
/// truncated answer is asked again over TCP.
pub(super) fn ask(
    state: &mut ffi::ResState,
    tries: Tries,
    name: &CStr,
    rrtype: c_int,
    max_response_size: usize,
    budget: Duration,
) -> Asked {
    let deadline = Instant::now() + budget;
    if tries.tcp {
        return ask_over_tcp(
            state,
            tries.nscount,
            name,
            rrtype,
            deadline,
            max_response_size,
        );
    }
    (state.retrans, state.retry, state.nscount) = (tries.retrans, tries.retry, tries.nscount);
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
            return ask_over_tcp(
                state,
                tries.nscount,
                name,
                rrtype,
                deadline,
                max_response_size,
            );
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
        ffi::HOST_NOT_FOUND => Asked::NxDomain(trimmed(response)),
        0 | ffi::NO_DATA => Asked::NoData(trimmed(response)),
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

/// A negative answer without the rest of its receive buffer, which a walk
/// keeps per name until it ends.
fn trimmed(mut response: Vec<u8>) -> Vec<u8> {
    if let Some(len) = message_len(&response) {
        response.truncate(len);
        response.shrink_to_fit();
    }
    response
}

/// Where the DNS message at the start of `packet` ends, by its counts.
fn message_len(packet: &[u8]) -> Option<usize> {
    let header = MessageHeader::parse(packet).ok()?;
    let mut end = DNS_HEADER_SIZE;
    for _ in 0..header.question_count() {
        end += Name::from_message(packet, end).ok()?.1 + 4;
    }
    let records = u32::from(header.answer_count())
        + u32::from(header.authority_count())
        + u32::from(header.additional_count());
    for _ in 0..records {
        end += Name::from_message(packet, end).ok()?.1;
        let rdlen = packet.get(end + 8..end + 10)?;
        end += 10 + usize::from(u16::from_be_bytes([rdlen[0], rdlen[1]]));
    }
    (end <= packet.len()).then_some(end)
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
/// `deadline`: libc's own TCP retry waits without one. Each of the first
/// `nscount` nameservers gets its share of the time left, so one that does
/// not answer leaves time for the next.
fn ask_over_tcp(
    state: &ffi::ResState,
    nscount: c_int,
    name: &CStr,
    rrtype: c_int,
    deadline: Instant,
    max_response_size: usize,
) -> Asked {
    let query = match TcpQuery::new(name, rrtype) {
        Ok(query) => query,
        Err(err) => return Asked::Failed(err),
    };
    let servers: Vec<_> = nameservers(state, nscount).collect();
    let mut asked = Asked::Unreachable;
    for (i, &server) in servers.iter().enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        let remaining = u32::try_from(servers.len() - i).unwrap_or(u32::MAX);
        let outcome = match exchange(
            server,
            &query.wire,
            Instant::now() + left / remaining,
            max_response_size,
        ) {
            Ok(response) => query.outcome(response),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Asked::Timeout
            }
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => Asked::Unreachable,
            Err(err) => Asked::Failed(err.into()),
        };
        if matches!(
            outcome,
            Asked::Answer(_) | Asked::NxDomain(_) | Asked::NoData(_)
        ) {
            return outcome;
        }
        // like libc, a failing server hands the query to the next one
        if telling(&outcome) > telling(&asked) {
            asked = outcome;
        }
    }
    asked
}

/// How much a failure says, to report the most telling of several servers'.
fn telling(asked: &Asked) -> u8 {
    match asked {
        Asked::ServerFailure(_) => 3,
        Asked::Timeout => 2,
        Asked::Failed(_) => 1,
        _ => 0,
    }
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

/// The first `nscount` nameservers `res_ninit` read, as glibc's
/// `__res_get_nsaddr` picks them: once used, `_ext` holds a copy of each,
/// also of an IPv4 one.
fn nameservers(state: &ffi::ResState, nscount: c_int) -> impl Iterator<Item = SocketAddr> + '_ {
    let count = usize::try_from(nscount.clamp(0, MAX_NAMESERVERS)).unwrap_or(0);
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

    /// No search list beyond what glibc kept.
    fn kept_only() -> Arc<[Box<[u8]>]> {
        Arc::new([])
    }

    fn walk(name: &str, search: &[&CStr], ndots: u32, options: libc::c_ulong) -> Vec<String> {
        names(&Walk::new(&state(search, ndots, options), name, None, kept_only).unwrap())
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
        let aliased = Walk::new(
            &state,
            "intranet",
            Some(c"real.example".to_owned()),
            kept_only,
        )
        .unwrap();
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
        Walk::new(&state(search, ndots, options), name, None, kept_only).unwrap()
    }

    #[test]
    fn a_long_search_list_is_read_whole() {
        let kept = [
            c"s1.test", c"s2.test", c"s3.test", c"s4.test", c"s5.test", c"s6.test",
        ];
        let six = state(&kept, 1, SEARCH);
        let full: Arc<[Box<[u8]>]> = (1..=8)
            .map(|i| format!("s{i}.test").into_bytes().into_boxed_slice())
            .collect();
        let walk = Walk::new(&six, "intranet", None, || full.clone()).unwrap();
        // eight domains, then the name as is
        assert_eq!(walk.steps.len(), 9);
        assert_eq!(walk.steps[7].name.to_bytes(), b"intranet.s8.test");

        // a list that does not extend what glibc kept is not the one it read
        let other: Arc<[Box<[u8]>]> = Arc::new([Box::from(&b"other.test"[..])]);
        let walk = Walk::new(&six, "intranet", None, || other).unwrap();
        assert_eq!(walk.steps.len(), 7);

        // `search .` leaves room for any other domain: nothing was cut
        let root = state(&[ROOT], 1, SEARCH);
        let walk = Walk::new(&root, "intranet", None, || panic!("read again")).unwrap();
        assert_eq!(walk.steps.len(), 2);
    }

    #[test]
    fn search_lists_read_as_glibc_reads_them() {
        let read = |localdomain: Option<&[u8]>, conf: &[u8]| -> Vec<String> {
            parse_search_list(localdomain, conf)
                .iter()
                .map(|domain| String::from_utf8(domain.to_vec()).unwrap())
                .collect()
        };
        let conf: &[u8] = b"# search not.test\nnameserver 127.0.0.53\nsearch a.test b.test\ndomain only.test\nsearch\tc.test  d.test\n";
        // the last `domain` or `search` line wins
        assert_eq!(read(None, conf), ["c.test", "d.test"]);
        assert_eq!(
            read(None, b"search a.test\ndomain only.test extra\n"),
            ["only.test"]
        );
        // an empty line changes nothing, a keyword needs a blank after it
        assert_eq!(
            read(None, b"search a.test\nsearch \nsearching x\nsearch\n"),
            ["a.test"]
        );
        assert!(read(None, b"nameserver ::1\n").is_empty());
        // a NUL ends a line, as it ends a C string
        assert_eq!(
            read(None, b"search s1.test s2.test\0junk s3.test\n"),
            ["s1.test", "s2.test"]
        );
        // a leading blank in LOCALDOMAIN puts the root first
        assert_eq!(
            read(Some(b" s1.test s2.test"), b""),
            ["", "s1.test", "s2.test"]
        );
        // LOCALDOMAIN overrides the file
        assert_eq!(
            read(Some(b"env.test\tother.test\nignored"), conf),
            ["env.test", "other.test"]
        );
    }

    #[test]
    fn the_search_list_is_read_again_once_it_changed() {
        let conf = env::temp_dir().join(format!("rama-dns-resolv-{}.conf", std::process::id()));
        let domains = (1..=8)
            .map(|i| format!("s{i}.test"))
            .collect::<Vec<_>>()
            .join(" ");
        fs::write(&conf, format!("nameserver 127.0.0.1\nsearch {domains}\n")).unwrap();
        assert_eq!(search_list_in(&conf, None).len(), 8);

        fs::write(&conf, "search a.test b.test\n").unwrap();
        let read = search_list_in(&conf, None);
        assert_eq!(
            read.iter().map(|domain| &domain[..]).collect::<Vec<_>>(),
            [b"a.test", b"b.test"]
        );
        // LOCALDOMAIN wins over the file
        let read = search_list_in(&conf, Some(OsString::from("env.test")));
        assert_eq!(
            read.iter().map(|domain| &domain[..]).collect::<Vec<_>>(),
            [b"env.test"]
        );
        fs::remove_file(&conf).unwrap();
        assert!(search_list_in(&conf, None).is_empty());
    }

    #[test]
    fn no_name_is_asked_past_the_deadline() {
        let walk = walk_of("intranet", &[CORP], 1, SEARCH);
        let mut outcomes = walk.outcomes();
        let at = walk.run(&mut outcomes, Instant::now(), |_, _| panic!("asked late"));
        assert!(matches!(outcomes[at], Some(Asked::Timeout)));
    }

    #[test]
    fn negative_answers_keep_only_their_message() {
        // NXDOMAIN for `a.test`, with a SOA in its authority section
        let mut packet = vec![0x12, 0x34, 0x81, 0x83, 0, 1, 0, 0, 0, 1, 0, 0];
        packet.extend_from_slice(b"\x01a\x04test\x00\x00\x01\x00\x01");
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 60, 0, 24]);
        packet.extend_from_slice(&[0xc0, 0x0e, 0xc0, 0x0e, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]);
        let len = packet.len();
        assert_eq!(message_len(&packet), Some(len));
        // the rest of a receive buffer goes
        let mut buffer = packet.clone();
        buffer.resize(16 * 1024, 0);
        assert_eq!(trimmed(buffer), packet);
        // a cut message keeps its buffer for the parser to judge
        assert_eq!(message_len(&packet[..len - 1]), None);
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
        let aliases: &[u8] =
            b"other  elsewhere.example\nINTRANET\treal.example extra\nlast first.example\n";
        let alias = |name| alias_in(aliases, name).map(|alias| alias.into_string().unwrap());
        assert_eq!(alias("intranet").as_deref(), Some("real.example"));
        assert_eq!(alias("other").as_deref(), Some("elsewhere.example"));
        assert_eq!(alias("missing"), None);
        // a name with nothing after it, or a line without whitespace, ends the file
        let cut: &[u8] = b"intranet \nintranet real.example\n";
        assert_eq!(alias_in(cut, "intranet"), None);
        assert_eq!(alias_in(&b"nowhitespace"[..], "intranet"), None);
        assert_eq!(alias_in(&b"junk\0 \nq real.example\n"[..], "q"), None);
        // like `fgets`, an endless file ends at its first part without whitespace
        assert_eq!(
            alias_in(io::BufReader::new(io::repeat(0)), "intranet"),
            None
        );
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
