use super::*;

fn expand_with(template: &str, vars: &[(&str, &str)]) -> String {
    let template = UriTemplate::try_new(template).unwrap();
    let resolved: Vec<_> = vars
        .iter()
        .filter_map(|(name, value)| template.variable(name).map(|v| (v, *value)))
        .collect();
    template.expand(|variable| {
        resolved
            .iter()
            .find(|(v, _)| *v == variable)
            .map(|(_, value)| *value)
    })
}

// RFC 6570 §1.2 / §3.2 example variables, string values only.
const RFC_VARS: &[(&str, &str)] = &[
    ("var", "value"),
    ("hello", "Hello World!"),
    ("path", "/foo/bar"),
    ("empty", ""),
    ("x", "1024"),
    ("y", "768"),
];

#[test]
fn expands_rfc6570_level_1_to_3_examples() {
    for (template, expected) in [
        ("{var}", "value"),
        ("{hello}", "Hello%20World%21"),
        ("{+var}", "value"),
        ("{+hello}", "Hello%20World!"),
        ("{+path}/here", "/foo/bar/here"),
        ("here?ref={+path}", "here?ref=/foo/bar"),
        ("map?{x,y}", "map?1024,768"),
        ("{x,hello,y}", "1024,Hello%20World%21,768"),
        ("{+x,hello,y}", "1024,Hello%20World!,768"),
        ("{+path,x}/here", "/foo/bar,1024/here"),
        ("{#x,hello,y}", "#1024,Hello%20World!,768"),
        ("{#path,x}/here", "#/foo/bar,1024/here"),
        ("X{.var}", "X.value"),
        ("X{.x,y}", "X.1024.768"),
        ("{/var}", "/value"),
        ("{/var,x}/here", "/value/1024/here"),
        ("{;x,y}", ";x=1024;y=768"),
        ("{;x,y,empty}", ";x=1024;y=768;empty"),
        ("{?x,y}", "?x=1024&y=768"),
        ("{?x,y,empty}", "?x=1024&y=768&empty="),
        ("?fixed=yes{&x}", "?fixed=yes&x=1024"),
        ("{&x,y,empty}", "&x=1024&y=768&empty="),
        ("{undef}", ""),
        ("{?undef,x}", "?x=1024"),
    ] {
        assert_eq!(expand_with(template, RFC_VARS), expected, "{template}");
    }
}

#[test]
fn simple_and_query_values_encode_everything_outside_unreserved() {
    let ipv6 = [("target_host", "2001:db8::42"), ("target_port", "443")];
    assert_eq!(
        expand_with(
            "/.well-known/masque/udp/{target_host}/{target_port}/",
            &ipv6
        ),
        "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
    );
    assert_eq!(
        expand_with("/masque{?target_host,target_port}", &ipv6),
        "/masque?target_host=2001%3Adb8%3A%3A42&target_port=443"
    );
    assert_eq!(
        expand_with("/m?h={target_host}&p={target_port}", &ipv6),
        "/m?h=2001%3Adb8%3A%3A42&p=443"
    );
    assert_eq!(
        expand_with("{v}", &[("v", "a/b?c#d&e=f%g+h~i-j.k_l")]),
        "a%2Fb%3Fc%23d%26e%3Df%25g%2Bh~i-j.k_l"
    );
}

#[test]
fn reserved_expansion_keeps_existing_escapes() {
    assert_eq!(expand_with("{+v}", &[("v", "a%20b%zz")]), "a%20b%25zz");
}

#[test]
fn rejects_invalid_templates() {
    for (template, expected) in [
        (
            "/{unclosed",
            UriTemplateError::UnclosedExpression { offset: 1 },
        ),
        ("/{}", UriTemplateError::InvalidVariableName { offset: 1 }),
        ("/{a,}", UriTemplateError::InvalidVariableName { offset: 1 }),
        (
            "/{a..b}",
            UriTemplateError::InvalidVariableName { offset: 1 },
        ),
        (
            "/{a-b}",
            UriTemplateError::InvalidVariableName { offset: 1 },
        ),
        ("/{=a}", UriTemplateError::ReservedOperator { offset: 1 }),
        ("/{|a}", UriTemplateError::ReservedOperator { offset: 1 }),
        ("/{a*}", UriTemplateError::UnsupportedModifier { offset: 1 }),
        (
            "/{a:3}",
            UriTemplateError::UnsupportedModifier { offset: 1 },
        ),
        ("/a b", UriTemplateError::InvalidLiteral { offset: 2 }),
        ("/a\"b", UriTemplateError::InvalidLiteral { offset: 2 }),
        ("/a}b", UriTemplateError::InvalidLiteral { offset: 2 }),
        ("/é", UriTemplateError::InvalidLiteral { offset: 1 }),
        (
            "/a%2",
            UriTemplateError::InvalidPercentEncoding { offset: 2 },
        ),
        (
            "/a%zz",
            UriTemplateError::InvalidPercentEncoding { offset: 2 },
        ),
    ] {
        assert_eq!(
            UriTemplate::try_new(template).unwrap_err(),
            expected,
            "{template}"
        );
    }
    let long = "/".repeat(MAX_TEMPLATE_LEN + 1);
    assert_eq!(
        UriTemplate::try_new(long).unwrap_err(),
        UriTemplateError::TooLong
    );
}

#[test]
fn repeated_variables_share_one_identity() {
    let template = UriTemplate::try_new("/{a}/{b}{?a}").unwrap();
    assert_eq!(template.variables().len(), 2);
    assert_eq!(
        template.variable_name(template.variable("a").unwrap()),
        Some("a")
    );
}

fn matcher(template: &str) -> (UriTemplate, UriTemplateMatcher) {
    let template = UriTemplate::try_new(template).unwrap();
    let matcher = UriTemplateMatcher::try_new(&template).unwrap();
    (template, matcher)
}

fn split(uri: &str) -> (&str, Option<&str>) {
    match uri.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (uri, None),
    }
}

#[test]
fn expansion_round_trips_through_the_matcher() {
    for template in [
        "/.well-known/masque/udp/{target_host}/{target_port}/",
        "/masque?h={target_host}&p={target_port}",
        "/masque{?target_host,target_port}",
        "/v1/{target_host}{?target_port}",
        "/v1?key=abc&h={target_host}&p={target_port}",
        "/z%333/{target_host}/{target_port}",
        "/{target_host}@{target_port}",
        "/{target_host}:{target_port}/x",
    ] {
        let (template_value, matcher) = matcher(template);
        let host = template_value.variable("target_host").unwrap();
        let port = template_value.variable("target_port").unwrap();
        for target in [
            "192.0.2.6",
            "2001:db8::42",
            "example.org",
            "xn--bcher-kva.example",
        ] {
            let expanded = template_value.expand(|v| {
                if v == host {
                    Some(target)
                } else if v == port {
                    Some("443")
                } else {
                    None
                }
            });
            let (path, query) = split(&expanded);
            let captures = matcher
                .captures(path, query)
                .unwrap_or_else(|| panic!("{template}: {expanded} did not match"));
            assert_eq!(captures.get(host), Some(target), "{template}: {expanded}");
            assert_eq!(captures.get(port), Some("443"), "{template}: {expanded}");
        }
    }
}

#[test]
fn query_matching_is_order_lenient_and_ignores_unknown_pairs() {
    let (template, matcher) = matcher("/masque{?target_host,target_port}");
    let host = template.variable("target_host").unwrap();
    let captures = matcher
        .captures("/masque", Some("x=1&target_port=443&target_host=a.example"))
        .unwrap();
    assert_eq!(captures.get(host), Some("a.example"));
}

#[test]
fn query_values_use_percent_decoding_not_form_decoding() {
    let (template, matcher) = matcher("/m?h={target_host}&p={target_port}");
    let host = template.variable("target_host").unwrap();
    let captures = matcher.captures("/m", Some("h=a+b%20c&p=1")).unwrap();
    assert_eq!(captures.get(host), Some("a+b c"));
}

#[test]
fn matcher_rejects_mismatches() {
    let (_, default) = matcher("/.well-known/masque/udp/{target_host}/{target_port}/");
    for (path, query) in [
        ("/.well-known/masque/udp/a.example/443", None),
        ("/.well-known/masque/udp//443/", None),
        ("/.well-known/masque/tcp/a.example/443/", None),
        ("/.well-known/masque/udp/a.example/443/extra/", None),
        ("/.well-known/masque/udp/a%zz/443/", None),
        ("/.well-known/masque/udp/a%FF/443/", None),
        ("/.well-known/masque/udp/caf\u{e9}/443/", None),
    ] {
        assert!(default.captures(path, query).is_none(), "{path}");
    }

    let (_, query) = matcher("/v1?key=abc&h={target_host}&p={target_port}");
    assert!(query.captures("/v1", Some("h=a&p=1")).is_none());
    assert!(query.captures("/v1", Some("key=xyz&h=a&p=1")).is_none());
    assert!(query.captures("/v1", Some("key=abc&h=a&h=b&p=1")).is_none());
    assert!(query.captures("/v2", Some("key=abc&h=a&p=1")).is_none());
}

#[test]
fn matcher_rejects_unmatchable_templates() {
    for template in [
        "/{a,b}",
        "/{+a}",
        "/{/a}",
        "/{a.b}",
        "/{a}/{a}",
        "/x?{a}",
        "/x?h={a}{b}",
        "/x?h={a}b",
        "/x?h={+a}",
        "relative/{a}",
        // Found by fuzzing: empty segments never match their own expansion.
        "//",
        "/a//{a}",
        // Found by fuzzing: values followed by unreserved bytes or '%' are ambiguous.
        "/x{a}y{b}",
        "/{a}x",
        "/{a}%41",
        "/{a}{b}",
        // Found by fuzzing: `[` and `]` are not path characters, so never match.
        "/z]3]/{a}",
        "/x?a=b={a}",
        "/{a}{?a}",
        "/?x&x",
        "/?x=1&x=2",
        "/?a=1&a={a}",
        "/x?a=1{?b}",
        "/x{?a}{?b}",
    ] {
        let template = UriTemplate::try_new(template).unwrap();
        assert!(
            matches!(
                UriTemplateMatcher::try_new(&template),
                Err(UriTemplateError::NotMatchable(_))
            ),
            "{template}"
        );
    }
}

#[test]
fn templates_compare_by_text() {
    let a = UriTemplate::try_new("/{x}").unwrap();
    let b = UriTemplate::try_new("/{x}").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.to_string(), "/{x}");
}

#[test]
fn literal_byte_table_matches_rfc6570_grammar() {
    for b in 0..=u8::MAX {
        let grammar = matches!(b,
            0x21 | 0x23..=0x24 | 0x26 | 0x28..=0x3B | 0x3D | 0x3F..=0x5B | 0x5D | 0x5F
                | 0x61..=0x7A | 0x7E);
        assert_eq!(
            crate::byte_sets::is_template_literal_byte(b),
            grammar,
            "{b:#04x}"
        );
    }
}
