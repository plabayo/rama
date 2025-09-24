use std::time::Duration;

use super::utils;

use rama::http::sse::datastar::ElementPatchMode;
use rama::{Context, futures::StreamExt, http::sse::datastar::DatastarEvent};
use serde_json::json;

#[tokio::test]
#[ignore]
async fn test_http_sse_datastar_test_suite() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_sse_datastar_test_suite", None);

    // get test

    let mut stream = runner
        .get("http://127.0.0.1:62036/test?datastar=%7b%0a++%22events%22%3a+%5b%0a++++%7b%0a++++++%22type%22%3a+%22executeScript%22%2c%0a++++++%22script%22%3a+%22console.log%28%27hello%27%29%3b%22%2c%0a++++++%22eventId%22%3a+%22event1%22%2c%0a++++++%22retryDuration%22%3a+2000%2c%0a++++++%22attributes%22%3a+%7b%0a++++++++%22type%22%3a+%22text%2fjavascript%22%2c%0a++++++++%22blocking%22%3a+false%0a++++++%7d%2c%0a++++++%22autoRemove%22%3a+false%0a++++%7d%0a++%5d%0a%7d")
        .send(Context::default())
        .await
        .unwrap()
        .into_body()
        .into_event_stream();

    let event: DatastarEvent = stream.next().await.unwrap().unwrap();
    assert_eq!(Some("event1"), event.id());
    assert_eq!(Some("datastar-patch-elements"), event.event());
    assert_eq!(Some(Duration::from_secs(2)), event.retry());
    let patch_elements = event.into_data().unwrap().into_patch_elements().unwrap();
    assert_eq!(Some("body"), patch_elements.selector.as_deref());
    assert_eq!(ElementPatchMode::Append, patch_elements.mode);
    assert_eq!(
        Some(r##"<script type="text/javascript" blocking="false">console.log('hello');</script>"##),
        patch_elements.elements.as_deref()
    );

    assert!(stream.next().await.is_none());

    // post test

    let mut stream = runner
        .post("http://127.0.0.1:62036/test")
        .json(&json!({
          "events": [
            {
              "type": "patchElements",
              "elements": "<div>Merge</div>"
            }
          ]
        }))
        .send(Context::default())
        .await
        .unwrap()
        .into_body()
        .into_event_stream();

    let event: DatastarEvent = stream.next().await.unwrap().unwrap();
    assert_eq!(None, event.id());
    assert_eq!(Some("datastar-patch-elements"), event.event());
    assert_eq!(None, event.retry());
    let patch_elements = event.into_data().unwrap().into_patch_elements().unwrap();
    assert_eq!(None, patch_elements.selector.as_deref());
    assert_eq!(ElementPatchMode::Outer, patch_elements.mode);
    assert_eq!(Some("<div>Merge</div>"), patch_elements.elements.as_deref());

    assert!(stream.next().await.is_none());
}
