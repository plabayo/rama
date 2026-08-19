use bytes::Bytes;
use rama_core::extensions::{Extension, ExtensionsRef as _};
use rama_http_types::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version, request, response,
};
use serde_test::{Configure, Token, assert_tokens};

#[derive(Debug, Extension)]
struct ProcessLocal;

#[derive(Debug)]
struct ComparableRequest(Request<()>);

impl PartialEq for ComparableRequest {
    fn eq(&self, other: &Self) -> bool {
        self.0.method() == other.0.method()
            && self.0.uri() == other.0.uri()
            && self.0.version() == other.0.version()
            && self.0.headers() == other.0.headers()
    }
}

impl serde::Serialize for ComparableRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&self.0, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ComparableRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde::Deserialize::deserialize(deserializer).map(Self)
    }
}

struct HugeLengthHintDeserializer;

struct HugeLengthHintSeq;

impl<'de> serde::de::SeqAccess<'de> for HugeLengthHintSeq {
    type Error = serde::de::value::Error;

    fn next_element_seed<T>(&mut self, _seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        Ok(None)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(usize::MAX)
    }
}

impl<'de> serde::Deserializer<'de> for HugeLengthHintDeserializer {
    type Error = serde::de::value::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_seq(HugeLengthHintSeq)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map struct enum identifier ignored_any
    }

    fn is_human_readable(&self) -> bool {
        true
    }
}

#[test]
fn bytes_roundtrip_through_serde() {
    let bytes = Bytes::from_static(&[0, 0x80, 0xff]);
    let json = serde_json::to_string(&bytes).unwrap();
    assert_eq!(json, "[0,128,255]");
    assert_eq!(serde_json::from_str::<Bytes>(&json).unwrap(), bytes);
}

#[test]
fn header_value_ignores_untrusted_sequence_length_hint() {
    let value =
        <HeaderValue as serde::Deserialize>::deserialize(HugeLengthHintDeserializer).unwrap();
    assert!(value.is_empty());
}

#[test]
fn leaf_types_use_stable_json_representations() {
    assert_eq!(serde_json::to_string(&Method::PATCH).unwrap(), r#""PATCH""#);
    assert_eq!(
        serde_json::to_string(&StatusCode::IM_A_TEAPOT).unwrap(),
        "418"
    );
    assert_eq!(
        serde_json::to_string(&Version::HTTP_2).unwrap(),
        r#""HTTP/2.0""#
    );

    assert_eq!(
        serde_json::from_str::<Method>(r#""CUSTOM""#).unwrap(),
        "CUSTOM"
    );
    assert_eq!(
        serde_json::from_str::<StatusCode>("599").unwrap(),
        StatusCode::from_u16(599).unwrap()
    );
    assert_eq!(
        serde_json::from_str::<Version>(r#""2""#).unwrap(),
        Version::HTTP_2
    );

    serde_json::from_str::<Method>(r#""""#).unwrap_err();
    serde_json::from_str::<StatusCode>("99").unwrap_err();
    serde_json::from_str::<Version>(r#""HTTP/4""#).unwrap_err();
}

#[test]
fn header_value_json_is_readable_when_text_and_lossless_when_opaque() {
    let text = HeaderValue::from_static("text value");
    assert_eq!(serde_json::to_string(&text).unwrap(), r#""text value""#);
    assert_eq!(
        serde_json::from_str::<HeaderValue>(r#""text value""#).unwrap(),
        text
    );

    let opaque = HeaderValue::from_bytes(&[0x80, b' ', 0xff]).unwrap();
    let json = serde_json::to_string(&opaque).unwrap();
    assert_eq!(json, "[128,32,255]");
    assert_eq!(serde_json::from_str::<HeaderValue>(&json).unwrap(), opaque);

    serde_json::from_str::<HeaderValue>(r#""café""#).unwrap_err();
    serde_json::from_str::<HeaderValue>("[10]").unwrap_err();
    let error = serde_json::from_str::<HeaderValue>("{}").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("a valid HTTP header value as text or bytes")
    );
}

#[test]
fn header_value_uses_bytes_in_non_human_readable_formats() {
    assert_tokens(
        &HeaderValue::from_static("text value").compact(),
        &[Token::BorrowedBytes(b"text value")],
    );
}

#[test]
fn header_map_roundtrip_preserves_order_duplicates_casing_and_bytes() {
    let mut headers = HeaderMap::new();
    headers.append("X-First", HeaderValue::from_static("one"));
    headers.append("x-second", HeaderValue::from_bytes(&[0x80]).unwrap());
    headers.append("X-FIRST", HeaderValue::from_static("two"));

    let json = serde_json::to_string(&headers).unwrap();
    let decoded: HeaderMap = serde_json::from_str(&json).unwrap();
    let actual = decoded
        .ordered_iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        [
            ("X-First".to_owned(), b"one".to_vec()),
            ("x-second".to_owned(), vec![0x80]),
            ("X-FIRST".to_owned(), b"two".to_vec()),
        ]
    );
}

#[test]
fn aggregate_types_roundtrip_in_non_human_readable_formats() {
    let request = ComparableRequest(Request::builder().uri("/resource").body(()).unwrap());
    assert_tokens(
        &request.compact(),
        &[
            Token::Struct {
                name: "Request",
                len: 5,
            },
            Token::Str("method"),
            Token::Str("GET"),
            Token::Str("uri"),
            Token::Str("/resource"),
            Token::Str("version"),
            Token::Str("HTTP/1.1"),
            Token::Str("headers"),
            Token::Seq { len: Some(0) },
            Token::SeqEnd,
            Token::Str("body"),
            Token::Unit,
            Token::StructEnd,
        ],
    );
}

#[test]
fn invalid_header_name_is_rejected_during_map_deserialization() {
    let error = serde_json::from_str::<HeaderMap>(r#"[["bad name","value"]]"#).unwrap_err();
    assert!(error.to_string().contains("invalid HTTP header name"));
}

#[test]
fn request_and_parts_roundtrip_omit_process_local_extensions() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/upload?q=1")
        .version(Version::HTTP_2)
        .header("X-Text", "hello")
        .header("X-Opaque", HeaderValue::from_bytes(&[0x80]).unwrap())
        .extension(ProcessLocal)
        .body(vec![1_u8, 2, 3])
        .unwrap();

    let json = serde_json::to_string(&request).unwrap();
    assert!(!json.contains("ProcessLocal"));
    let decoded: Request<Vec<u8>> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.method(), Method::POST);
    assert_eq!(decoded.uri().as_str(), "https://example.com/upload?q=1");
    assert_eq!(decoded.version(), Version::HTTP_2);
    assert_eq!(decoded.headers()["x-opaque"].as_bytes(), &[0x80]);
    assert_eq!(decoded.body(), &[1, 2, 3]);
    assert!(!decoded.extensions().contains::<ProcessLocal>());

    let (parts, _) = decoded.into_parts();
    let parts_json = serde_json::to_string(&parts).unwrap();
    let decoded_parts: request::Parts = serde_json::from_str(&parts_json).unwrap();
    assert_eq!(decoded_parts.method, Method::POST);
    assert!(!decoded_parts.extensions.contains::<ProcessLocal>());
}

#[test]
fn request_roundtrip_preserves_all_request_target_forms() {
    let connect = Request::builder()
        .method(Method::CONNECT)
        .uri(rama_net::uri::Uri::parse_authority_form("example.com:443").unwrap())
        .body(())
        .unwrap();
    let json = serde_json::to_string(&connect).unwrap();
    let decoded: Request<()> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.uri().to_string(), "example.com:443");
    assert!(decoded.uri().scheme().is_none());
    assert_eq!(decoded.uri().host().unwrap().to_string(), "example.com");
    assert_eq!(decoded.uri().port().as_u16(), Some(443));

    let connect_reference = Request::builder()
        .method(Method::CONNECT)
        .uri(rama_net::uri::Uri::parse_reference("/tunnel").unwrap())
        .body(())
        .unwrap();
    let json = serde_json::to_string(&connect_reference).unwrap();
    let decoded: Request<()> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.method(), Method::CONNECT);
    assert_eq!(decoded.uri().to_string(), "/tunnel");

    let options = Request::builder()
        .method(Method::OPTIONS)
        .uri(rama_net::uri::Uri::parse_reference("*").unwrap())
        .body(())
        .unwrap();
    let json = serde_json::to_string(&options).unwrap();
    let decoded: Request<()> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.method(), Method::OPTIONS);
    assert_eq!(decoded.uri().to_string(), "*");
    assert!(decoded.uri().is_asterisk());
    assert!(decoded.uri().path().is_none());

    let relative = Request::builder()
        .uri(rama_net::uri::Uri::parse_reference("../asset?q=1#part").unwrap())
        .body(())
        .unwrap();
    let json = serde_json::to_string(&relative).unwrap();
    let decoded: Request<()> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.uri().to_string(), "../asset?q=1#part");
}

#[test]
fn response_and_parts_roundtrip_omit_process_local_extensions() {
    let response = Response::builder()
        .status(StatusCode::CREATED)
        .version(Version::HTTP_11)
        .header("X-Result", "created")
        .extension(ProcessLocal)
        .body("ok".to_owned())
        .unwrap();

    let json = serde_json::to_string(&response).unwrap();
    assert!(!json.contains("ProcessLocal"));
    let decoded: Response<String> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.status(), StatusCode::CREATED);
    assert_eq!(decoded.version(), Version::HTTP_11);
    assert_eq!(decoded.headers()["x-result"], "created");
    assert_eq!(decoded.body(), "ok");
    assert!(!decoded.extensions().contains::<ProcessLocal>());

    let (parts, _) = decoded.into_parts();
    let parts_json = serde_json::to_string(&parts).unwrap();
    let decoded_parts: response::Parts = serde_json::from_str(&parts_json).unwrap();
    assert_eq!(decoded_parts.status, StatusCode::CREATED);
    assert!(!decoded_parts.extensions.contains::<ProcessLocal>());
}
