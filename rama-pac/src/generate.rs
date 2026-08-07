//! Generate a PAC script from typed routing rules.

use rama_net::address::Domain;

use crate::{PacDirectives, PacScript};

/// Builds a PAC script that routes matching hosts to given proxies.
///
/// Rules are tried in order and the first match wins; anything unmatched
/// falls through to the default route.
#[derive(Debug, Clone, Default)]
pub struct PacGenerator {
    routes: Vec<Route>,
    default_route: Option<PacDirectives>,
}

#[derive(Debug, Clone)]
struct Route {
    directives: PacDirectives,
    matcher: RouteMatcher,
}

/// Kept private and open-ended so new rule kinds (CIDR, glob, ...) can be
/// added without breaking the generated script's shape.
#[derive(Debug, Clone)]
enum RouteMatcher {
    /// The listed domains, and optionally any subdomain of them.
    Domains {
        domains: Vec<Domain>,
        subdomains: bool,
    },
}

impl PacGenerator {
    /// Create a new [`PacGenerator`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Route the given domains, **and any of their subdomains**, through
    /// these directives: `example.com` also matches `www.example.com`.
    #[must_use]
    pub fn with_route(
        mut self,
        directives: PacDirectives,
        domains: impl IntoIterator<Item = Domain>,
    ) -> Self {
        self.set_route(directives, domains);
        self
    }

    /// See [`Self::with_route`].
    pub fn set_route(
        &mut self,
        directives: PacDirectives,
        domains: impl IntoIterator<Item = Domain>,
    ) -> &mut Self {
        self.push_route(directives, domains, true)
    }

    /// Route exactly the given domains, and no subdomain of them, through
    /// these directives.
    #[must_use]
    pub fn with_exact_route(
        mut self,
        directives: PacDirectives,
        domains: impl IntoIterator<Item = Domain>,
    ) -> Self {
        self.set_exact_route(directives, domains);
        self
    }

    /// See [`Self::with_exact_route`].
    pub fn set_exact_route(
        &mut self,
        directives: PacDirectives,
        domains: impl IntoIterator<Item = Domain>,
    ) -> &mut Self {
        self.push_route(directives, domains, false)
    }

    fn push_route(
        &mut self,
        directives: PacDirectives,
        domains: impl IntoIterator<Item = Domain>,
        subdomains: bool,
    ) -> &mut Self {
        let domains: Vec<Domain> = domains.into_iter().collect();
        if !domains.is_empty() {
            self.routes.push(Route {
                directives,
                matcher: RouteMatcher::Domains {
                    domains,
                    subdomains,
                },
            });
        }
        self
    }

    /// What to return when no route matches (defaults to `DIRECT`).
    #[must_use]
    pub fn with_default_route(mut self, directives: PacDirectives) -> Self {
        self.default_route = Some(directives);
        self
    }

    /// What to return when no route matches (defaults to `DIRECT`).
    pub fn set_default_route(&mut self, directives: PacDirectives) -> &mut Self {
        self.default_route = Some(directives);
        self
    }

    /// Render the PAC script.
    #[must_use]
    pub fn generate(&self) -> PacScript {
        let mut out = String::from(
            "function FindProxyForURL(url, host) {\n    \
             if (!host) { return \"DIRECT\"; }\n    \
             host = host.toLowerCase();\n    \
             // browsers may pass a fully qualified name like \"example.com.\"\n    \
             if (host.charCodeAt(host.length - 1) === 46) { host = host.slice(0, -1); }\n",
        );

        for (index, route) in self.routes.iter().enumerate() {
            match &route.matcher {
                RouteMatcher::Domains {
                    domains,
                    subdomains,
                } => {
                    write_domain_route(&mut out, index, domains, &route.directives, *subdomains);
                }
            }
        }

        let default_route = self
            .default_route
            .clone()
            .unwrap_or_else(PacDirectives::direct);
        out.push_str("    return ");
        out.push_str(&js_string(&default_route.to_string()));
        out.push_str(";\n}\n");

        PacScript::from(out)
    }
}

/// Exact hosts go in an object literal (hash lookup); with `subdomains`
/// the same names also back a suffix scan.
fn write_domain_route(
    out: &mut String,
    index: usize,
    domains: &[Domain],
    route: &PacDirectives,
    subdomains: bool,
) {
    let mut names: Vec<String> = domains
        .iter()
        .map(|domain| domain.as_str().trim_matches('.').to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return;
    }

    out.push_str(&format!("    var exact{index} = {{"));
    for (position, name) in names.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        out.push_str(&js_string(name));
        out.push_str(":1");
    }
    out.push_str("};\n");

    let result = js_string(&route.to_string());
    out.push_str(&format!(
        "    if (exact{index}[host] === 1) {{ return {result}; }}\n"
    ));
    if !subdomains {
        return;
    }

    out.push_str(&format!("    var suffix{index} = ["));
    for (position, name) in names.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        out.push_str(&js_string(&format!(".{name}")));
    }
    out.push_str("];\n");

    out.push_str(&format!(
        "    for (var i{index} = 0; i{index} < suffix{index}.length; i{index}++) {{\n        \
         var s{index} = suffix{index}[i{index}];\n        \
         if (host.length > s{index}.length && \
         host.lastIndexOf(s{index}) === host.length - s{index}.length) \
         {{ return {result}; }}\n    }}\n",
    ));
}

/// Render a js string literal. Domains are LDH-validated and directives
/// render from typed values, so this only has to be correct, not clever.
fn js_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            // U+2028/U+2029 terminate a string literal in older js parsers
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directives(raw: &str) -> PacDirectives {
        raw.parse()
            .unwrap_or_else(|err| panic!("`{raw}` must parse: {err}"))
    }

    #[test]
    fn empty_generator_is_direct_only() {
        let script = PacGenerator::new().generate();
        assert!(script.as_str().contains("function FindProxyForURL"));
        assert!(script.as_str().contains(r#"return "DIRECT";"#));
    }

    #[test]
    fn route_contains_its_domains_and_directives() {
        let script = PacGenerator::new()
            .with_route(
                directives("PROXY p.example:8080; DIRECT"),
                [
                    Domain::from_static("example.com"),
                    Domain::from_static("aikido.gent"),
                ],
            )
            .generate();

        let source = script.as_str();
        assert!(source.contains("example.com"), "{source}");
        assert!(source.contains("aikido.gent"), "{source}");
        assert!(
            source.contains(r#"return "PROXY p.example:8080; DIRECT";"#),
            "{source}",
        );
    }

    #[test]
    fn default_route_is_configurable() {
        let script = PacGenerator::new()
            .with_default_route(directives("PROXY fallback:1"))
            .generate();
        assert!(
            script.as_str().contains(r#"return "PROXY fallback:1";"#),
            "{}",
            script.as_str(),
        );
    }

    #[test]
    fn domains_are_normalised_and_deduplicated() {
        let script = PacGenerator::new()
            .with_route(
                directives("DIRECT"),
                [
                    Domain::from_static("Example.COM"),
                    Domain::from_static("example.com"),
                ],
            )
            .generate();

        let source = script.as_str();
        assert_eq!(source.matches("\"example.com\"").count(), 1, "{source}");
        assert!(!source.contains("Example.COM"), "{source}");
    }

    #[test]
    fn an_empty_domain_list_adds_no_rule() {
        let script = PacGenerator::new()
            .with_route(directives("PROXY p:1"), [])
            .generate();
        assert!(!script.as_str().contains("exact0"), "{}", script.as_str());
    }

    #[test]
    fn generated_script_stays_pre_es6() {
        let script = PacGenerator::new()
            .with_route(
                directives("PROXY p:1"),
                [Domain::from_static("example.com")],
            )
            .generate();
        // consumers may be old pac engines: no ES2015-only methods
        assert!(!script.as_str().contains("endsWith"), "{}", script.as_str());
        assert!(!script.as_str().contains("let "), "{}", script.as_str());
    }

    #[test]
    fn js_strings_are_escaped() {
        assert_eq!(js_string("plain"), r#""plain""#);
        assert_eq!(js_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(js_string("a\\b"), r#""a\\b""#);
        assert_eq!(js_string("a\nb"), r#""a\nb""#);
        assert_eq!(js_string("a\rb"), r#""a\rb""#);
        assert_eq!(js_string("a\u{0}b"), r#""a\u0000b""#);
        // line separators end a string literal in older js parsers
        assert_eq!(js_string("a\u{2028}b"), r#""a\u2028b""#);
        assert_eq!(js_string("a\u{2029}b"), r#""a\u2029b""#);
    }
}
