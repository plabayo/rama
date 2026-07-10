use std::{
    collections::BTreeMap,
    ffi::{CString, c_char, c_void},
    fmt::Debug,
};

use rama::telemetry::tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
    subscriber::layer::{Context, Layer},
};

#[cfg(target_vendor = "apple")]
unsafe extern "C" {
    fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
    fn os_release(object: *mut c_void);
    fn rama_os_log_split(
        log: *mut c_void,
        level: u8,
        public_message: *const c_char,
        private_metadata: *const c_char,
    );
}

pub struct RedactingOsLogLayer {
    #[cfg(target_vendor = "apple")]
    logger: *mut c_void,
}

impl RedactingOsLogLayer {
    pub fn new(subsystem: &str, category: &str) -> Self {
        #[cfg(target_vendor = "apple")]
        {
            let subsystem = CString::new(subsystem).expect("invalid os_log subsystem");
            let category = CString::new(category).expect("invalid os_log category");
            let logger = unsafe { os_log_create(subsystem.as_ptr(), category.as_ptr()) };
            Self { logger }
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            let _ = (subsystem, category);
            Self {}
        }
    }
}

// Apple documents os_log objects as thread-safe shared handles.
#[cfg(target_vendor = "apple")]
unsafe impl Send for RedactingOsLogLayer {}
#[cfg(target_vendor = "apple")]
unsafe impl Sync for RedactingOsLogLayer {}

impl<S: Subscriber> Layer<S> for RedactingOsLogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        #[cfg(target_vendor = "apple")]
        {
            let mut fields = BTreeMap::new();
            event.record(&mut FieldVisitor(&mut fields));
            let (public_message, private_metadata) = format_event(
                event.metadata().target(),
                fields.remove("message").unwrap_or_default(),
                fields,
            );
            let public_message = c_string(public_message);
            let private_metadata = c_string(private_metadata);
            unsafe {
                rama_os_log_split(
                    self.logger,
                    os_log_level(*event.metadata().level()),
                    public_message.as_ptr(),
                    private_metadata.as_ptr(),
                );
            }
        }
    }
}

#[cfg(target_vendor = "apple")]
impl Drop for RedactingOsLogLayer {
    fn drop(&mut self) {
        unsafe { os_release(self.logger) }
    }
}

fn c_string(mut value: String) -> CString {
    value.retain(|character| character != '\0');
    CString::new(value).expect("invalid os_log value")
}

fn format_event(
    target: &str,
    message: String,
    fields: BTreeMap<String, String>,
) -> (String, String) {
    let target_is_sensitive = target.ends_with("::demo_trace_traffic");
    let (mut public, mut private) = if target_is_sensitive || message_looks_sensitive(&message) {
        (
            format!("event target={target}"),
            format!("message={message}"),
        )
    } else {
        (message, String::new())
    };

    for (key, value) in fields {
        let output = if target_is_sensitive || is_sensitive_field(&key) {
            &mut private
        } else {
            &mut public
        };
        if !output.is_empty() {
            output.push(' ');
        }
        output.push_str(&key);
        output.push('=');
        output.push_str(&value);
    }

    if public.is_empty() {
        public = format!("event target={target}");
    }
    (public, private)
}

fn is_sensitive_field(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "app"
            | "app_id"
            | "application"
            | "args"
            | "audit_token"
            | "bind_addr"
            | "bundle_id"
            | "bundle_identifier"
            | "endpoint"
            | "err"
            | "error"
            | "host"
            | "hostname"
            | "local"
            | "local_interface_name"
            | "path"
            | "peer"
            | "pid"
            | "process"
            | "process_args"
            | "process_path"
            | "remote"
            | "remote_hostname"
            | "service"
            | "service_name"
            | "signing_id"
            | "uri"
            | "url"
    ) || name.contains("args")
        || name.contains("bundle")
        || name.contains("path")
        || name.contains("signing")
        || name.ends_with("_address")
        || name.ends_with("_endpoint")
        || name.ends_with("_hostname")
        || name.ends_with("_pid")
}

fn message_looks_sensitive(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    if message.len() > 512
        || lower.contains("://")
        || lower.contains('/')
        || lower.contains('@')
        || lower.contains("bundle_id=")
        || lower.contains("hostname=")
        || lower.contains("remote=")
        || lower.contains("signing_id=")
    {
        return true;
    }

    message
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '-' | '_'))
        })
        .any(|token| looks_like_ip_address(token) || looks_like_domain(token))
}

fn looks_like_ip_address(value: &str) -> bool {
    let value = value.trim_matches(|character: char| {
        matches!(character, ',' | ';' | '(' | ')' | '[' | ']' | '"' | '\'')
    });
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let host = value.rsplit_once(':').map_or(value, |(host, _)| host);
    let host = host.trim_matches(|character| matches!(character, '[' | ']'));
    host.parse::<std::net::IpAddr>().is_ok()
}

fn looks_like_domain(value: &str) -> bool {
    let value = value.trim_matches('.');
    let Some((_, suffix)) = value.rsplit_once('.') else {
        return false;
    };
    if suffix.len() < 2
        || !suffix
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    })
}

#[cfg(target_vendor = "apple")]
fn os_log_level(level: Level) -> u8 {
    match level {
        Level::TRACE => 2,
        Level::DEBUG => 1,
        Level::INFO => 0,
        Level::WARN => 16,
        Level::ERROR => 17,
    }
}

#[cfg(target_vendor = "apple")]
struct FieldVisitor<'a>(&'a mut BTreeMap<String, String>);

#[cfg(target_vendor = "apple")]
impl Visit for FieldVisitor<'_> {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::{format_event, message_looks_sensitive};
    use std::collections::BTreeMap;

    #[test]
    fn keeps_operational_text_and_safe_fields_public() {
        let fields = BTreeMap::from([
            ("flow_id".to_owned(), "42".to_owned()),
            ("reason".to_owned(), "peer_eof_left".to_owned()),
        ]);
        let (public, private) = format_event(
            "rama_apple_ne::tproxy",
            "transparent proxy tcp flow closed".to_owned(),
            fields,
        );
        assert_eq!(
            public,
            "transparent proxy tcp flow closed flow_id=42 reason=peer_eof_left"
        );
        assert!(private.is_empty());
    }

    #[test]
    fn separates_sensitive_structured_fields() {
        let fields = BTreeMap::from([
            ("bundle_id".to_owned(), "\"org.example.app\"".to_owned()),
            ("flow_id".to_owned(), "42".to_owned()),
            ("remote".to_owned(), "203.0.113.7:443".to_owned()),
        ]);
        let (public, private) = format_event(
            "rama_apple_ne::tproxy",
            "transparent proxy tcp flow closed".to_owned(),
            fields,
        );
        assert_eq!(public, "transparent proxy tcp flow closed flow_id=42");
        assert!(private.contains("bundle_id=\"org.example.app\""));
        assert!(private.contains("remote=203.0.113.7:443"));
    }

    #[test]
    fn hides_sensitive_unstructured_messages() {
        for message in [
            "connecting to https://example.com/private",
            "remote=203.0.113.7:443 connected",
            "loaded /Users/example/secret.pem",
            "app org.example.product started",
            "peer [2001:db8::1]:443 disconnected",
            "SNI=Some(Domain(chatgpt.com)) is complete",
            "target Address(172.64.155.209) uri Uri(/private)",
        ] {
            assert!(message_looks_sensitive(message), "{message}");
            let (public, private) =
                format_event("rama_apple_ne::tproxy", message.to_owned(), BTreeMap::new());
            assert_eq!(public, "event target=rama_apple_ne::tproxy");
            assert_eq!(private, format!("message={message}"));
        }
    }

    #[test]
    fn hides_traffic_payload_targets_and_large_messages() {
        let (public, private) = format_event(
            "rama_tproxy_example::demo_trace_traffic",
            "websocket payload".to_owned(),
            BTreeMap::from([("status".to_owned(), "ok".to_owned())]),
        );
        assert_eq!(
            public,
            "event target=rama_tproxy_example::demo_trace_traffic"
        );
        assert_eq!(private, "message=websocket payload status=ok");

        assert!(message_looks_sensitive(&"x".repeat(513)));
    }
}
