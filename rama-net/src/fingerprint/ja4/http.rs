//! Ja4H implementation for Rama (in Rust).
//!
//! JA4H is part of the Ja4+ is copyrighted
//! and licensed by FoxIO. See license information below:
//!
//! > Copyright 2023 AOL Inc. All rights reserved.
//! > Portions Copyright 2023 FoxIO
//! >
//! > SPDX-License-Identifier: FoxIO License 1.1
//! >
//! > This software requires a license to use. See
//! > - <https://github.com/FoxIO-LLC/ja4#licensing>
//! > - <https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md>

use itertools::Itertools as _;
use std::{
    borrow::Cow,
    fmt::{self, Write},
};

use rama_http_types::{
    Method, Version,
    header::{ACCEPT_LANGUAGE, COOKIE, REFERER},
};

use crate::fingerprint::{HttpRequestInput, HttpRequestProvider};

#[derive(Clone)]
/// Input data for a "ja4h" hash.
/// or displaying it.
///
/// Computed using [`Ja4H::compute`].
pub struct Ja4H {
    req_method: HttpRequestMethod,
    version: HttpVersion,
    has_cookie_header: bool,
    has_referer_header: bool,
    language: Option<String>,
    headers: Vec<String>,
    cookie_pairs: Option<Vec<(String, Option<String>)>>,
}

impl Ja4H {
    /// Compute the [`Ja4H`] (hash).
    ///
    /// As specified by <https://blog.foxio.io/ja4%2B-network-fingerprinting>
    /// and reference implementations found at <https://github.com/FoxIO-LLC/ja4>.
    pub fn compute(req: impl HttpRequestProvider) -> Result<Self, Ja4HComputeError> {
        let HttpRequestInput {
            header_map,
            http_method,
            version,
        } = req.http_request_input();

        let req_method = HttpRequestMethod::from(http_method);
        let version: HttpVersion = version.try_into()?;

        let mut has_cookie_header = false;
        let mut has_referer_header = false;
        let mut language = None;

        let mut cookie_pairs = None;

        let headers: Vec<_> = header_map
            .into_iter()
            .filter_map(|(name, value)| match *name.header_name() {
                ACCEPT_LANGUAGE => {
                    language = std::str::from_utf8(value.as_bytes())
                        .ok()
                        .and_then(|s| s.split(',').next())
                        .and_then(|s| s.split(';').next())
                        .map(|s| {
                            s.trim()
                                .chars()
                                .filter(|c| c.is_alphabetic())
                                .take(4)
                                .map(|c| c.to_ascii_lowercase())
                                .collect()
                        });
                    Some(name.as_str().to_owned())
                }
                COOKIE => {
                    has_cookie_header = true;
                    // split on ; and then trim to handle different spacing, fixing the sorting issue
                    if let Ok(s) = std::str::from_utf8(value.as_bytes()) {
                        let pairs = cookie_pairs.get_or_insert_with(Vec::default);
                        pairs.extend(s.split(';').map(|cookie| {
                            let cookie = cookie.trim();
                            match cookie.split_once('=') {
                                None => (cookie.to_owned(), None),
                                Some((name, value)) => (name.to_owned(), Some(value.to_owned())),
                            }
                        }));
                        pairs.sort_unstable();
                    }
                    None
                }
                REFERER => {
                    has_referer_header = true;
                    None
                }
                _ => Some(name.as_str().to_owned()),
            })
            .collect();
        if headers.is_empty() {
            return Err(Ja4HComputeError::MissingHeaders);
        }

        Ok(Self {
            req_method,
            version,
            has_cookie_header,
            has_referer_header,
            language,
            headers,
            cookie_pairs,
        })
    }

    #[inline]
    #[must_use]
    pub fn to_human_string(&self) -> String {
        format!("{self:?}")
    }

    fn fmt_as(&self, f: &mut fmt::Formatter<'_>, hash_chunks: bool) -> fmt::Result {
        let req_method = &self.req_method;
        let version = self.version;
        let cookie_marker = if self.has_cookie_header { 'c' } else { 'n' };
        let referer_marker = if self.has_referer_header { 'r' } else { 'n' };
        let nr_headers = 99.min(self.headers.len());

        // application fingerprint: part I
        write!(
            f,
            "{req_method}{version}{cookie_marker}{referer_marker}{nr_headers:02}"
        )?;
        match self.language.as_deref() {
            Some(s) => format_str_truncate(4, s, f)?,
            None => write!(f, "0000")?,
        }

        // application fingerprint: part II
        debug_assert!(
            !self.headers.is_empty(),
            "validated in Ja4H::compute constructor"
        );
        let headers = self.headers.iter().join(",");

        // website cookie fingerprint
        let cookie_names = joined_cookie_names(self.cookie_pairs.iter().flatten());

        // user cookie fingerprint
        let cookie_pairs = joined_cookie_pairs(self.cookie_pairs.iter().flatten());

        if hash_chunks {
            write!(
                f,
                "_{}_{}_{}",
                hash12(headers),
                hash12(cookie_names),
                hash12(cookie_pairs),
            )
        } else {
            write!(f, "_{headers}_{cookie_names}_{cookie_pairs}")
        }
    }
}

impl fmt::Display for Ja4H {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(f, true)
    }
}

impl fmt::Debug for Ja4H {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(f, false)
    }
}

fn format_str_truncate(n: usize, s: &str, f: &mut fmt::Formatter) -> fmt::Result {
    let len = s.chars().count();
    if len > n {
        f.write_str(&s[..n])?;
    } else {
        f.write_str(s)?;
        for _ in 0..(n - len) {
            f.write_char('0')?;
        }
    }
    Ok(())
}

fn joined_cookie_names<'a, I>(cookie_pairs: I) -> String
where
    I: IntoIterator<Item = &'a (String, Option<String>)>,
{
    cookie_pairs
        .into_iter()
        .map(|(name, _)| {
            debug_assert!(!name.is_empty());
            name.to_owned()
        })
        .join(",")
}

fn joined_cookie_pairs<'a, I>(cookie_pairs: I) -> String
where
    I: IntoIterator<Item = &'a (String, Option<String>)>,
{
    cookie_pairs
        .into_iter()
        .map(|(name, value)| {
            debug_assert!(!name.is_empty());
            match value {
                None => name.to_owned(),
                Some(value) => format!("{name}={value}"),
            }
        })
        .join(",")
}

#[derive(Debug, Clone)]
/// error identifying a failure in [`Ja4H::compute`]
pub enum Ja4HComputeError {
    /// triggered when the request's version is not recognised
    InvalidHttpVersion,
    /// no headers detected
    MissingHeaders,
}

impl fmt::Display for Ja4HComputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHttpVersion => {
                write!(f, "Ja4H Compute Error: unexpected http request version")
            }
            Self::MissingHeaders => {
                write!(f, "Ja4H Compute Error: missing http headers")
            }
        }
    }
}

impl std::error::Error for Ja4HComputeError {}

fn hash12(s: impl AsRef<str>) -> Cow<'static, str> {
    use sha2::{Digest as _, Sha256};

    let s = s.as_ref();
    if s.is_empty() {
        "000000000000".into()
    } else {
        let sha256 = Sha256::digest(s);
        #[allow(deprecated)]
        hex::encode(&sha256.as_slice()[..6]).into()
    }
}

#[derive(Debug, Clone, PartialEq)]
struct HttpRequestMethod(Method);

impl fmt::Display for HttpRequestMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self.0 {
            Method::CONNECT => "co",
            Method::DELETE => "de",
            Method::GET => "ge",
            Method::HEAD => "he",
            Method::OPTIONS => "op",
            Method::PATCH => "pa",
            Method::POST => "po",
            Method::PUT => "pu",
            Method::TRACE => "tr",
            _ => {
                let mut c = self.0.as_str().chars();
                return write!(
                    f,
                    "{}{}",
                    c.next().map(|c| c.to_ascii_lowercase()).unwrap_or('0'),
                    c.next().map(|c| c.to_ascii_lowercase()).unwrap_or('0'),
                );
            }
        };
        f.write_str(code)
    }
}

impl From<Method> for HttpRequestMethod {
    #[inline]
    fn from(value: Method) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
enum HttpVersion {
    Http1_0,
    Http1_1,
    Http2,
    Http3,
}

impl TryFrom<Version> for HttpVersion {
    type Error = Ja4HComputeError;

    fn try_from(value: Version) -> Result<Self, Self::Error> {
        match value {
            Version::HTTP_10 => Ok(Self::Http1_0),
            Version::HTTP_11 => Ok(Self::Http1_1),
            Version::HTTP_2 => Ok(Self::Http2),
            Version::HTTP_3 => Ok(Self::Http3),
            _ => Err(Ja4HComputeError::InvalidHttpVersion),
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::Http1_0 => "10",
            Self::Http1_1 => "11",
            Self::Http2 => "20",
            Self::Http3 => "30",
        };
        f.write_str(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::{Request, proto::h1::Http1HeaderMap};

    #[derive(Debug)]
    struct TestCase {
        description: &'static str,
        expected_ja4h_str_debug: &'static str,
        expected_ja4h_str_hash: &'static str,
        req: Request<()>,
    }

    macro_rules! test_case {
        (
            description: $description:literal,
            debug_str: $expected_ja4h_str_debug:literal,
            hash_str: $expected_ja4h_str_hash:literal,
            version: $version:expr,
            method: $method:expr,
            headers: {$(
                $header_name:literal: $header_value:literal,
            )+}
            $(,)?
        ) => {
            {
                let mut map = Http1HeaderMap::default();
                $(
                    map.try_append(
                        $header_name,
                        rama_http_types::HeaderValue::from_str($header_value).unwrap()
                    ).unwrap();
                )+

                let mut extensions = rama_core::extensions::Extensions::default();
                let headers = map.consume(&mut extensions);

                let (mut parts, body) = Request::new(()).into_parts();
                parts.method = $method;
                parts.version = $version;
                parts.uri = "/".parse::<rama_http_types::Uri>().unwrap();
                parts.headers = headers;
                parts.extensions = extensions;

                let req = Request::from_parts(parts, body);

                TestCase {
                    description: $description,
                    expected_ja4h_str_debug: $expected_ja4h_str_debug,
                    expected_ja4h_str_hash: $expected_ja4h_str_hash,
                    req,
                }
            }
        };
    }

    #[test]
    fn test_ja4h_compute() {
        let test_cases = [
            test_case!(
                description: "rust_ja4_http_test_http_stats_into_out",
                debug_str: "ge11cr11enus_Host,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,User-Agent,Sec-Ch-Ua-Platform,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Accept-Encoding,Accept-Language_FastAB,_dd_s,countryCode,geoData,sato,stateCode,umto,usprivacy_FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929,_dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726,countryCode=US,geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511,sato=1,stateCode=VA,umto=1,usprivacy=1---",
                hash_str: "ge11cr11enus_974ebe531c03_0f2659b474bf_161698816dab",
                version: Version::HTTP_11,
                method: Method::GET,
                headers: {
                    "Host": "www.cnn.com",
                    "Cookie": "FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726",
                    "Sec-Ch-Ua": "",
                    "Sec-Ch-Ua-Mobile": "?0",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36",
                    "Sec-Ch-Ua-Platform": "\"\"",
                    "Accept": "*/*",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Dest": "empty", // should not have duplicated headers
                    "Referer": "https://www.cnn.com/",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            ),
            test_case!(
                description: "wireshark_ja4_firefox_133_macos_fp.ramaproxy.org_http11_plain",
                debug_str: "ge11cr09enus_Host,User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,DNT,Sec-GPC,Priority_rama-fp_rama-fp=ready",
                hash_str: "ge11cr09enus_df50b14dec48_d733b88e2d70_774e52af4cfe",
                version: Version::HTTP_11,
                method: Method::GET,
                headers: {
                    "Host": "h1.fp.ramaproxy.org",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
                    "Accept": "text/css,*/*;q=0.1",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Referer": "http://h1.fp.ramaproxy.org/consent",
                    "Cookie": "rama-fp=ready",
                    "DNT": "1",
                    "Sec-GPC": "1",
                    "Priority": "u=2",
                },
            ),
            test_case!(
                description: "curl_ja4h_http2_cookies_different_order",
                debug_str: "ge20cn030000_authorization,user-agent,accept_alpha,sierra,zulu_alpha=bravo,sierra=echo,zulu=tango",
                hash_str: "ge20cn030000_a8ea46949477_7efd8825dc5a_f0c5f5a36bc1",
                version: Version::HTTP_2,
                method: Method::GET,
                headers: {
                    "authorization": "Basic d29yZDp3b3Jk",
                    "user-agent": "curl/7.81.0",
                    "accept": "*/*",
                    "cookie": "sierra=echo;alpha=bravo;zulu=tango",
                },
            ),
        ];
        for test_case in test_cases {
            let ja4h = Ja4H::compute(&test_case.req).expect(test_case.description);
            assert_eq!(
                test_case.expected_ja4h_str_debug,
                format!("{ja4h:?}"),
                "{}",
                test_case.description
            );
            assert_eq!(
                test_case.expected_ja4h_str_hash,
                format!("{ja4h}"),
                "{}",
                test_case.description
            );
        }
    }
}
