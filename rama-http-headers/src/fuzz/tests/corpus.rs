//! Adversarial inputs and a seeded generator for the panic tests.

use rama_http_types::HeaderValue;

pub(super) const ADVERSARIAL: &[&[u8]] = &[
    b"",
    b" ",
    b"\t",
    b"W",
    b"W/",
    b"W/\"",
    b"W/\"a",
    b"w/\"a\"",
    b"W/ \"a\"",
    b"\"",
    b"\"\"",
    b"\"\"\"",
    b"\"a",
    b"a\"",
    b"\"a b\"",
    b"\" \"",
    b"\"\t\"",
    b"x",
    b"xyzzy",
    b"\"xyzzy\"",
    b"W/\"xyzzy\"",
    b" \"a\" ",
    b"\"a\", W/",
    b"\"a\",,W/\"b\"",
    b"*",
    b"*, \"a\"",
    b",",
    b",,",
    b", ,",
    b"=",
    b";",
    b";;q=",
    b"q=",
    // fuzzer finds: weights without a named item
    b";;q=1",
    b";0;q=1",
    b";q=;;q=1",
    b";\t;q=1.",
    b"f;;q=1",
    b"a;q=2;q=1",
    b"a;b;q=1",
    b"text/html;q=2;q=1",
    b"q=2",
    b"q=-0",
    b"q=1.001",
    b"q=0.0000",
    b"a;q=",
    b"a;q=0.5",
    b"a;q=1.",
    b";q=1",
    b"*/*",
    b"*/*;q=",
    b"*/*;q=0.1, text/html",
    b"/",
    b"a/",
    b"/b",
    b"a/b;c",
    b"a/b; charset=\"",
    b"text/plain; charset=utf-8",
    b"bytes=",
    b"bytes=-",
    b"bytes=0-",
    b"bytes=-0",
    b"bytes=0-0",
    b"bytes=5-1",
    b"bytes=1-5",
    b"bytes=,",
    b"bytes=0-1,2-3,-4,5-",
    b"bytes=0-18446744073709551615",
    b"bytes=18446744073709551615-18446744073709551616",
    b"bytes=18446744073709551615-",
    b"bytes=-18446744073709551615",
    b"bytes=\xc3\xa9",
    b"bytes */0",
    b"bytes */*",
    b"bytes 0-0/0",
    b"bytes 5-1/10",
    b"bytes 0-18446744073709551615/18446744073709551615",
    b"bytes 18446744073709551615-18446744073709551615/*",
    b"bytes -1-2/3",
    b"0",
    b"-0",
    b"-1",
    b"+1",
    b"0x10",
    b"1e9",
    b"1.5",
    b"NaN",
    b"inf",
    b"-inf",
    b"4294967296",
    b"2147483648",
    b"18446744073709551615",
    b"18446744073709551616",
    b"99999999999999999999999999999999",
    b"00000000000000000000000000001",
    b"Sun, 06 Nov 1994 08:49:37 GMT",
    b"Sunday, 06-Nov-94 08:49:37 GMT",
    b"Sun Nov  6 08:49:37 1994",
    b"Thu, 01 Jan 1970 00:00:00 GMT",
    b"Wed, 31 Dec 1969 23:59:59 GMT",
    b"Mon, 01 Jan 0000 00:00:00 GMT",
    b"Fri, 31 Dec 9999 23:59:59 GMT",
    b"Sat, 01 Jan 10000 00:00:00 GMT",
    b"Mon, 01 Jan 99999 00:00:00 GMT",
    b"Mon, 32 Jan 2024 00:00:00 GMT",
    b"Wed, 29 Feb 2023 00:00:00 GMT",
    b"Mon, 01 Jan 2024 25:61:61 GMT",
    b"2024-01-01T00:00:00Z",
    b"2024-01-01T00:00:00+99:99",
    b"2024-01-01T00:00:00-00:00",
    b"0000-01-01",
    b"9999-12-31T23:59:59Z",
    b"+009999-12-31",
    b"-000001-01-01",
    b"-009999-01-01T00:00:00Z",
    b"25 Jun 2010 15:00:00 PST",
    b"Friday, 01-Jan-99 00:00:00 XYZ",
    b"unavailable_after: 2024-13-45",
    b"unavailable_after: -000001-01-01",
    b"unavailable_after: -009999-01-01T00:00:00Z",
    b"unavailable_after: 0000-01-01",
    b"\xc3\xa9",
    b"\xe6\x97\xa5\xe6\x9c\xac",
    b"\xf0\x9f\x98\x80",
    b"\x80",
    b"\xff",
    b"\xc3",
    b"\xe6\x97",
    b"a\x80b",
    b"\"\x80\"",
    b"W/\"\xff\"",
    b"\"\xc3\xa9\"",
    b"W/\"\xc3\xa9\"",
    b"Basic",
    b"Basic ",
    b"Basic  ",
    b"Basic !!!",
    b"Basic dXNlcg==",
    b"Basic dXNlcjo=",
    b"Basic OnBhc3M=",
    b"Basic Og==",
    b"Basic gA==",
    b"basic dXNlcjpwYXNz",
    b"Basic\tdXNlcjpwYXNz",
    b"Basic dXNlcjpwYXNz",
    b"Bearer",
    b"Bearer ",
    b"Bearer  ",
    b"Bearer \x80",
    b"bearer x",
    b"Digest x",
    b"[::1",
    b"[::1]",
    b"[::1]:",
    b"[::1]:99999",
    b"::ffff:1.2.3.4",
    b"1.2.3.4:",
    b"1.2.3.4:65536",
    b"[",
    b"]",
    b"[]",
    b":",
    b"::",
    b":80",
    b"host:",
    b"a..b",
    b".",
    b"-a.com",
    b"xn--",
    b"xn--\xc3\xa9",
    b"http://",
    b"https://a",
    b"https://a/",
    b"https://a/b",
    b"https://a?b",
    b"https://a#b",
    b"https://u@a",
    b"null",
    b"http://[::1]:0",
    b"https://\xc3\xa9.com",
    b"a://b:99999",
    b"default-src 'self'",
    b"script-src 'nonce-",
    b"script-src 'sha256-'",
    b"img-src *:*",
    b"a https://:*/",
    b"a ://",
    b"'",
    b"''",
    b"h3=\":443\"",
    b"h3=\":\"",
    b"h3=\"\"",
    b"h3=\"[::1]:443\"; ma=18446744073709551616; persist=1",
    b"h3=\"a:1\"; ma=1; ma=2",
    b"h3=\"a:1\";",
    b"%",
    b"%%",
    b"%zz=\":1\"",
    b"h%33=\":1\"",
    b"clear",
    b"u=",
    b"u=8",
    b"u=-1, i",
    b"i=?2",
    b"u=99999999999999999",
    b"camera=()",
    b"camera=(\"\")",
    b"camera=(self \"https://a\")",
    b"camera",
    b"=()",
    b"max-age=",
    b"max-age=-1",
    b"max-age=18446744073709551616",
    b"max-age=\"1\"; includeSubDomains; preload",
    b"no-cache, max-age=1, max-age=2",
    b"s-maxage=18446744073709551615",
    b"permessage-deflate; server_max_window_bits=99999",
    b"permessage-deflate; client_max_window_bits",
    b"permessage-deflate;;",
    b"attachment; filename*=UTF-8''%",
    b"attachment; filename*=UTF-8''%e9",
    b"form-data",
    b"websocket, h2c",
    b"dGhlIHNhbXBsZSBub25jZQ==",
    b"13",
    b"100-continue",
    b"on",
    b"off",
    b"slow-2g",
    b"sec-ch-ua, ect",
    b"noindex, googlebot: nofollow",
    b"max-snippet: -1",
    b"max-video-preview: 99999999999",
    b"max-image-preview: \xc3\xa9",
    b"googlebot:",
    b"a: b: c",
    b"for=1.2.3.4;proto=https;by=_x;host=\"a:1\"",
    b"for=\"[::1]:80\"",
    b"for=",
    b";;;",
    b"1.1 proxy",
    b"HTTP/1.1 a, 2 b",
    b"/1.1 x",
    b"http/ x",
    b"same-origin; report-to=\"",
    b"require-corp; report-to=",
    b"no-referrer, ,unsafe-url",
];

pub(super) fn long_inputs() -> Vec<Vec<u8>> {
    vec![
        vec![b'a'; 64 * 1024],
        vec![0xff; 64 * 1024],
        vec![b','; 10_000],
        vec![b'"'; 10_000],
        vec![b'['; 10_000],
        vec![b'('; 10_000],
        vec![b';'; 10_000],
        vec![b'1'; 10_000],
        b"W/\"".repeat(5_000),
        b"\"a\", ".repeat(5_000),
        b"0-1,".repeat(5_000),
        [b"bytes=".as_slice(), &b"0-1,".repeat(5_000)].concat(),
        [b"bytes=".as_slice(), &b"-1,".repeat(5_000)].concat(),
        [b"q=0.".as_slice(), &[b'0'; 10_000]].concat(),
        b"a=b; ".repeat(5_000),
        b"%41".repeat(5_000),
        b"noindex, ".repeat(5_000),
        b"a: ".repeat(5_000),
        b"h3=\":1\", ".repeat(2_000),
    ]
}

pub(super) const TOKENS: &[&[u8]] = &[
    b"W/",
    b"\"",
    b"*",
    b",",
    b", ",
    b";",
    b"=",
    b" ",
    b"\t",
    b"q=",
    b"q=0.5",
    b"q=1",
    b"q=2",
    b"0",
    b"1",
    b"9",
    b"-",
    b"/",
    b":",
    b".",
    b"[",
    b"]",
    b"(",
    b")",
    b"%",
    b"%41",
    b"'",
    b"?1",
    b"a",
    b"Z",
    b"xyzzy",
    b"\xc3\xa9",
    b"\x80",
    b"\xff",
    b"bytes=",
    b"bytes ",
    b"*/*",
    b"text/html",
    b"gzip",
    b"br",
    b"identity",
    b"chunked",
    b"Basic ",
    b"Bearer ",
    b"dXNlcjpwYXNz",
    b"max-age=",
    b"no-cache",
    b"ma=",
    b"persist=1",
    b"h3=",
    b"\":443\"",
    b"u=",
    b"i",
    b"filename*=UTF-8''",
    b"'self'",
    b"'nonce-",
    b"'sha256-",
    b"https://",
    b"example.com",
    b"::1",
    b"1.2.3.4",
    b"for=",
    b"proto=",
    b"by=",
    b"host=",
    b"HTTP/1.1",
    b"null",
    b"close",
    b"keep-alive",
    b"websocket",
    b"noindex",
    b"googlebot:",
    b"unavailable_after: ",
    b"2024-01-01",
    b"Sun, 06 Nov 1994 08:49:37 GMT",
    b"GMT",
    b"18446744073709551615",
    b"18446744073709551616",
    b"99999",
    b"-1",
    b"NaN",
    b"1e9",
    b"report-to=",
    b"permessage-deflate",
    b"server_max_window_bits=",
    b"camera=",
];

pub(super) const STR_ONLY: &[&str] = &[
    "\n",
    "\r\n",
    "\0",
    "\x7f",
    "a\nb",
    "\"\n\"",
    "W/\"\n\"",
    "https://a\n",
    "attachment\u{7f}",
    "\u{2028}",
    "\u{feff}",
    "\u{10ffff}",
    "é://é",
    "a://",
    "://",
    "'nonce-\n'",
    "*:\n",
];

pub(super) struct XorShift(pub(super) u64);

impl XorShift {
    pub(super) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x.wrapping_shl(13);
        x ^= x.wrapping_shr(7);
        x ^= x.wrapping_shl(17);
        self.0 = x;
        x
    }

    pub(super) fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next())
            .unwrap_or_default()
            .checked_rem(n)
            .unwrap_or_default()
    }

    pub(super) fn bytes(&mut self) -> Vec<u8> {
        let count = self.below(10).saturating_add(1);
        (0..count)
            .flat_map(|_| TOKENS[self.below(TOKENS.len())].iter().copied())
            .collect()
    }
}

pub(super) fn value(bytes: &[u8]) -> Option<HeaderValue> {
    HeaderValue::from_bytes(bytes).ok()
}

pub(super) fn value_corpus() -> Vec<Vec<HeaderValue>> {
    let mut singles: Vec<Vec<u8>> = ADVERSARIAL.iter().map(|b| b.to_vec()).collect();
    singles.extend(
        (0x20..=0x7e)
            .chain([0x09, 0x80, 0xc3, 0xff])
            .map(|b| vec![b]),
    );
    singles.extend(long_inputs());
    let mut corpus: Vec<Vec<HeaderValue>> = singles
        .iter()
        .filter_map(|b| value(b))
        .map(|v| vec![v])
        .collect();
    let pairable: Vec<HeaderValue> = ADVERSARIAL
        .iter()
        .step_by(4)
        .filter_map(|b| value(b))
        .collect();
    for a in &pairable {
        for b in &pairable {
            corpus.push(vec![a.clone(), b.clone()]);
        }
    }
    corpus.push(pairable);
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..3_000 {
        let count = rng.below(3).saturating_add(1);
        let values: Vec<HeaderValue> = (0..count).filter_map(|_| value(&rng.bytes())).collect();
        if !values.is_empty() {
            corpus.push(values);
        }
    }
    corpus
}

pub(super) fn str_corpus() -> Vec<String> {
    let mut corpus: Vec<String> = ADVERSARIAL
        .iter()
        .filter_map(|b| std::str::from_utf8(b).ok())
        .chain(STR_ONLY.iter().copied())
        .map(str::to_owned)
        .collect();
    corpus.extend((0u8..=0x7f).map(|b| char::from(b).to_string()));
    corpus.extend(
        long_inputs()
            .into_iter()
            .filter_map(|b| String::from_utf8(b).ok()),
    );
    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    for _ in 0..3_000 {
        let mut bytes = rng.bytes();
        if rng.below(4) == 0 {
            bytes.push(b"\n\r\0\x7f"[rng.below(4)]);
        }
        if let Ok(s) = String::from_utf8(bytes) {
            corpus.push(s);
        }
    }
    corpus
}

pub(super) const EDGE_NUMBERS: &[u64] = &[
    0,
    1,
    2,
    12,
    13,
    31,
    32,
    99,
    100,
    101,
    1_000,
    4_294_967_295,
    253_402_300_799,
    253_402_300_800,
    i64::MAX.unsigned_abs(),
    u64::MAX - 1,
    u64::MAX,
];
