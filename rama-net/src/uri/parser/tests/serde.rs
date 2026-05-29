//! Serde `Serialize` / `Deserialize` round-trip for [`Uri`].

use crate::uri::Uri;

#[test]
fn serde_round_trip() {
    for input in [
        "/",
        "/foo/bar?q=1#f",
        "*",
        "https://example.com/",
        "https://user:pass@example.com:8443/path?q=1#frag",
        "urn:isbn:0451450523",
        "mailto:user@example.com",
        "ws://example.com/socket",
    ] {
        let uri = Uri::parse(input).expect(input);
        let json = serde_json::to_string(&uri).expect(input);
        assert_eq!(json, format!("\"{input}\""), "serialize: {input}");
        let back: Uri = serde_json::from_str(&json).expect(input);
        assert_eq!(back, uri, "deserialize: {input}");
        assert_eq!(back.to_string(), input, "round-trip Display: {input}");
    }
}

#[test]
fn deserialize_rejects_invalid() {
    // ASCII control byte — graceful parser rejects.
    let err = serde_json::from_str::<Uri>("\"http://exa\\u0001mple.com/\"").unwrap_err();
    assert!(err.to_string().contains("control"), "got: {err}");
}
