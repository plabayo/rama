use rama_core::bytes::Bytes;
use serde_json::{Value, json};

use super::JsonLd;

#[test]
fn serialization_is_script_data_safe_and_roundtrips() {
    let original = json!({
        "closing": "</script><script>alert(1)</script>",
        "comment": "<!-- hidden -->",
        "ordinary": "one < two",
    });

    let document = JsonLd::from_value(&original);

    assert!(!document.as_bytes().contains(&b'<'));
    assert!(document.as_str().contains(r"\u003c/script>"));
    assert_eq!(document.deserialize::<Value>().unwrap(), original);
}

#[test]
fn safe_input_bytes_keep_their_allocation() {
    let bytes = Bytes::from_static(br#"{"@type":"WebSite"}"#);
    let pointer = bytes.as_ptr();

    let document = JsonLd::from_bytes(bytes).unwrap();

    assert_eq!(document.as_bytes().as_ptr(), pointer);
}

#[test]
fn unsafe_input_bytes_are_escaped_without_changing_the_value() {
    let original = json!({"name": "unsafe </script> value"});
    let bytes = Bytes::from_static(br#"{"name":"unsafe </script> value"}"#);

    let document = JsonLd::from_bytes(bytes).unwrap();

    assert!(!document.as_bytes().contains(&b'<'));
    assert_eq!(document.deserialize::<Value>().unwrap(), original);
}

#[test]
fn invalid_json_bytes_are_rejected() {
    JsonLd::from_bytes(Bytes::from_static(br#"{"broken":"#)).unwrap_err();
}

#[test]
fn custom_serialization_errors_are_returned() {
    struct Fails;

    impl serde::Serialize for Fails {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("expected failure"))
        }
    }

    JsonLd::serialize(&Fails).unwrap_err();
}

#[tokio::test]
async fn response_uses_json_ld_content_type_and_prepared_body() {
    use crate::BodyExtractExt;
    use crate::header::CONTENT_TYPE;
    use crate::service::web::response::IntoResponse;

    let document = JsonLd::from_value(&json!({"@type": "WebSite"}));
    let expected = document.as_str().to_owned();
    let response = document.into_response();

    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/ld+json",
    );
    assert_eq!(response.try_into_string().await.unwrap(), expected);
}

#[cfg(feature = "html")]
mod html {
    use rama_core::bytes::ByteStr;

    use crate::protocols::html::IntoHtml;

    use super::super::{ExtractJsonLdError, extract_from_html};
    use super::*;

    #[test]
    fn script_renders_exactly_once_and_escapes_id() {
        let document = JsonLd::from_value(&json!({
            "@context": "https://schema.org",
            "@type": "WebSite",
        }));

        let output = document.script().with_id(r#"site-"<&"#).into_string();

        assert_eq!(output.matches("<script").count(), 1);
        assert_eq!(output.matches("</script>").count(), 1);
        assert!(
            output.starts_with(r#"<script type="application/ld+json" id="site-&quot;&lt;&amp;">"#,)
        );
        assert!(!output.contains(r#"site-"<&"#));
    }

    #[test]
    fn extractor_is_lazy_fallible_and_accepts_html_attribute_variations() {
        let html = concat!(
            "<html><head>",
            "<script data-source=x TYPE='application/ld+json' id='site&amp;graph'>",
            r#"{"@type":"WebSite"}"#,
            "</script>",
            "<script type='application/ld+json'>not-json</script>",
            "</head></html>",
        );

        let mut documents = extract_from_html(html);

        let first = documents.next().unwrap().unwrap();
        assert_eq!(first.id(), Some("site&graph"));
        assert_eq!(first.media_type().essence_str(), "application/ld+json");
        assert_eq!(
            first.deserialize::<Value>().unwrap(),
            json!({"@type": "WebSite"}),
        );
        assert_eq!(&html[first.body_range()], first.body());
        assert_eq!(
            &html[first.element_range()],
            concat!(
                "<script data-source=x TYPE='application/ld+json' id='site&amp;graph'>",
                r#"{"@type":"WebSite"}"#,
                "</script>",
            ),
        );

        assert!(matches!(
            documents.next().unwrap(),
            Err(ExtractJsonLdError::InvalidJson { .. }),
        ));
        assert!(documents.next().is_none());
    }

    #[test]
    fn extractor_handles_multiple_chunks_and_media_type_parameters() {
        let prefix = "x".repeat(5_000);
        let html = prefix
            + concat!(
                "<script type='application/ld+json; profile=\"https://example.com/profile\"'>",
                r#"{"@type":"Thing"}"#,
                "</script>",
            );

        let documents = extract_from_html(&html)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(documents.len(), 1);
        assert_eq!(
            documents[0]
                .media_type()
                .get_param("profile")
                .map(|value| value.as_str()),
            Some("https://example.com/profile"),
        );
    }

    #[test]
    fn extractor_reports_unterminated_script() {
        let html = r#"<script type="application/ld+json">{"@type":"Thing"}"#;
        let mut documents = extract_from_html(html);

        assert!(matches!(
            documents.next().unwrap(),
            Err(ExtractJsonLdError::UnterminatedScript { .. }),
        ));
        assert!(documents.next().is_none());
    }

    #[test]
    fn raw_script_breakout_is_observed_as_invalid_json() {
        let html = concat!(
            r#"<script type="application/ld+json">{"name":"#,
            "</script><img src=x onerror=alert(1)>",
            r#""}</script>"#,
        );

        assert!(matches!(
            extract_from_html(html).next().unwrap(),
            Err(ExtractJsonLdError::InvalidJson { .. }),
        ));
    }

    #[test]
    fn extractor_skips_non_json_ld_scripts() {
        let html = concat!(
            "<script>console.log('hello')</script>",
            r#"<script type="application/json">{"ok":true}</script>"#,
        );

        assert!(extract_from_html(html).next().is_none());
    }

    #[test]
    fn embedded_document_can_be_owned_and_reprepared() {
        let html = r#"<script type="application/ld+json">{"name":"one < two"}</script>"#;
        let embedded = extract_from_html(html).next().unwrap().unwrap();

        let owned = embedded.to_owned().unwrap();

        assert!(!owned.as_bytes().contains(&b'<'));
        assert_eq!(
            owned.deserialize::<Value>().unwrap(),
            json!({"name": "one < two"}),
        );
    }

    #[test]
    fn bytestr_is_the_utf8_backing_type() {
        let body = ByteStr::from_static(r#"{"@type":"Thing"}"#);
        let document = JsonLd::from_bytes(Bytes::from(body)).unwrap();

        assert_eq!(document.as_str(), r#"{"@type":"Thing"}"#);
    }
}
