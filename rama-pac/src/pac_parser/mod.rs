use boa_engine::{Context as JsContext, JsString, JsValue, Source, js_string, property::Attribute};
use boa_runtime::Console;
use rama_core::error::BoxError;
use rama_http::Uri;

const PAC_STDLIB: &str = r#"
// spec-ish helpers
function dnsDomainIs(host, domain) {
    return host.length >= domain.length &&
           host.substring(host.length - domain.length) === domain;
}
function shExpMatch(str, shexp) {
    // very small glob impl: * only
    var re = new RegExp('^' + shexp.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
    return re.test(str);
}
function isPlainHostName(host) { return host.indexOf('.') < 0; }
function localHostOrDomainIs(host, hostdom) { return host === hostdom || hostdom.startsWith(host + "."); }
function dnsResolve(host) { return host; }          // stub; swap for real resolver if needed
function myIpAddress() { return "127.0.0.1"; }      // stub
function isInNet(ip, pattern, mask) { return false; } // stub
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyDirective {
    Direct,
    Proxy(String),
    Http(String),
    Https(String),
    Socks(String),
    Socks4(String),
    Socks5(String),
}

pub fn parse_pac_file(request_url: &Uri, pac_file: &str) -> Result<Vec<ProxyDirective>, BoxError> {
    let url: JsString = request_url.to_string().into();
    let host: JsString = request_url.host().unwrap().into();
    let pac_code = Source::from_bytes(pac_file.as_bytes());

    let mut context = JsContext::default();
    let console = Console::init(&mut context);

    context
        .register_global_property(js_string!(Console::NAME), console, Attribute::all())
        .expect("the console object shouldn't exist yet");

    context.eval(Source::from_bytes(PAC_STDLIB)).unwrap();

    let result = context.eval(pac_code).unwrap();
    let find_proxy_for_url_fn = result.as_function().unwrap();

    let result = find_proxy_for_url_fn
        .call(
            &JsValue::undefined(),
            &[JsValue::String(url), JsValue::String(host)],
            &mut context,
        )
        .unwrap();

    let js_str = result.to_string(&mut context).unwrap();

    let directives: String = js_str.to_std_string().unwrap();

    let endpoints = directives
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }

            let mut it = part.split_whitespace();
            let kind = it.next().unwrap_or_default().to_ascii_uppercase();
            let target = it.next().unwrap_or_default();

            match kind.as_str() {
                "DIRECT" => Some(ProxyDirective::Direct),
                "PROXY" if !target.is_empty() => Some(ProxyDirective::Proxy(target.to_string())),
                "HTTP" if !target.is_empty() => Some(ProxyDirective::Http(target.to_string())),
                "HTTPS" if !target.is_empty() => Some(ProxyDirective::Https(target.to_string())),
                "SOCKS" if !target.is_empty() => Some(ProxyDirective::Socks(target.to_string())),
                "SOCKS4" if !target.is_empty() => Some(ProxyDirective::Socks4(target.to_string())),
                "SOCKS5" if !target.is_empty() => Some(ProxyDirective::Socks5(target.to_string())),
                _ => None,
            }
        })
        .collect();

    Ok(endpoints)
}
