use super::utils;

use rama::{
    futures::StreamExt,
    http::{
        BodyExtractExt, StatusCode,
        headers::{ContentType, HeaderMapExt},
        mime,
        sse::datastar::{DatastarEvent, ElementPatchMode, Namespace},
    },
};

#[tokio::test]
#[ignore]
async fn test_http_sse_datastar_svg() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_sse_datastar_svg", None);

    let index_response = runner.get("http://127.0.0.1:62059").send().await.unwrap();
    assert_eq!(StatusCode::OK, index_response.status());
    assert!(
        index_response
            .headers()
            .typed_get::<ContentType>()
            .map(|ct| ct.mime().eq(&mime::TEXT_HTML_UTF_8))
            .unwrap_or_default()
    );
    let index_content = index_response.try_into_string().await.unwrap();
    assert!(index_content.contains("@get('/shape')"));
    assert!(index_content.contains("<svg"));
    assert!(index_content.contains("/assets/datastar.js"));

    for expected_element in [
        r##"<rect id="shape""##,
        r##"<polygon id="shape""##,
        r##"<circle id="shape""##,
    ] {
        let mut stream = runner
            .get("http://127.0.0.1:62059/shape")
            .send()
            .await
            .unwrap()
            .into_body()
            .into_event_stream();

        let event: DatastarEvent = stream.next().await.unwrap().unwrap();
        assert_eq!(Some("datastar-patch-elements"), event.event());
        let patch = event.into_data().unwrap().into_patch_elements().unwrap();
        assert_eq!(ElementPatchMode::Outer, patch.mode);
        assert_eq!(Namespace::Svg, patch.namespace);
        assert_eq!(None, patch.selector);
        assert!(
            patch
                .elements
                .as_deref()
                .unwrap_or_default()
                .contains(expected_element)
        );
        assert!(stream.next().await.is_none());
    }
}
