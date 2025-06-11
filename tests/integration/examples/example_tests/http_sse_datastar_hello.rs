use super::utils;

use rama::{
    Context,
    futures::StreamExt,
    http::{
        BodyExtractExt, StatusCode,
        headers::{ContentType, HeaderMapExt, dep::mime},
        sse::{
            JsonEventData,
            datastar::{DatastarEvent, EventType, MergeFragments, MergeSignals, RemoveFragments},
        },
    },
};

use itertools::Itertools;
use serde::Deserialize;
use serde_json::json;

#[tokio::test]
#[ignore]
async fn test_http_sse_datastar_hello() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_sse_datastar_hello", None);

    // basic html page and script sanity checks,
    // to at least give some basic guarantees for the human experience

    let index_response = runner
        .get("http://127.0.0.1:62031")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, index_response.status());
    assert!(
        index_response
            .headers()
            .typed_get::<ContentType>()
            .map(|ct| ct.mime().eq(&mime::TEXT_HTML_UTF_8))
            .unwrap_or_default()
    );
    let index_content = index_response.try_into_string().await.unwrap();
    assert!(index_content.contains(r##"<h1>🦙💬 "hello 🚀 data-*"</h1>"##));

    let script_rsponse = runner
        .get("http://127.0.0.1:62031/assets/datastar.js")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, script_rsponse.status());
    assert!(
        script_rsponse
            .headers()
            .typed_get::<ContentType>()
            .map(|ct| ct.mime().eq(&mime::APPLICATION_JAVASCRIPT_UTF_8))
            .unwrap_or_default()
    );
    let script_content = script_rsponse.try_into_string().await.unwrap();
    assert!(script_content.contains(r##"// Datastar v1"##));

    // test the actual stream content

    let mut stream = runner
        .get("http://127.0.0.1:62031/hello-world")
        .send(Context::default())
        .await
        .unwrap()
        .into_body()
        .into_string_data_event_stream();

    let mut expected_events: Vec<TestEvent> = vec![
        MergeFragments::new(r##"sse-status"##).into(),
        RemoveFragments::new("#server-warning").into(),
        MergeFragments::new(
            r##"
<div id='message'>Hello, Datastar!</div>
<div id="progress-bar" style="width: 100%"></div>
"##,
        )
        .into(),
        MergeSignals::new(JsonEventData(UpdateSignals { delay: Some(400) })).into(),
        // instant ack (interval == instant at 0)
        MergeFragments::new(r##"sse-status"##).into(),
    ];
    // add all messages (as we expect it come as animated frames due to call of `/start` endpoint)
    // this also includes an update of the signals first, as server is source of truth
    expected_events.push(MergeSignals::new(JsonEventData(UpdateSignals { delay: Some(1) })).into());
    const MESSAGE: &str = "Hello, Datastar!";
    for i in 1..=MESSAGE.len() {
        let text = &MESSAGE[..i];
        let progress = (i as f64) / (MESSAGE.len() as f64) * 100f64;
        expected_events.push(
            MergeFragments::new(format!(
                r##"
<div id='message'>{text}</div>
<div id="progress-bar" style="width: {progress}%"></div>
"##
            ))
            .into(),
        )
    }
    expected_events.reverse();

    // start animation so we get it streamed later
    let response = runner
        .post("http://127.0.0.1:62031/start?datastar=")
        .json(&json!({
            "delay": 1,
        }))
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, response.status());

    while let Some(result) = stream.next().await {
        let event: TestEvent = result.unwrap();
        match expected_events.pop() {
            Some(expected_event) => {
                // merge fragments handled differently
                // as fragments can have meaningless differences in newlines
                if expected_event.event() == Some(EventType::MergeFragments.as_str()) {
                    if event.event() == Some(EventType::MergeSignals.as_str()) {
                        expected_events.push(expected_event);
                        continue;
                    }

                    assert_eq!(expected_event.event(), event.event());
                    assert_eq!(expected_event.id(), event.id());
                    assert_eq!(expected_event.retry(), event.retry());
                    assert_eq!(
                        expected_event.comment().collect_vec(),
                        event.comment().collect_vec()
                    );

                    let expected_data = expected_event
                        .into_data()
                        .unwrap()
                        .into_merge_fragments()
                        .unwrap();
                    let data = event.into_data().unwrap().into_merge_fragments().unwrap();

                    assert_eq!(expected_data.selector, data.selector);
                    assert_eq!(expected_data.merge_mode, data.merge_mode);
                    assert_eq!(expected_data.use_view_transition, data.use_view_transition);

                    if expected_data.fragments.contains("sse-status") {
                        // only check if data also contains, as there
                        // is some data in the fragment that is based on timing
                        assert!(data.fragments.contains("sse-status"));
                    } else {
                        let mut expected_fragments = expected_data.fragments.to_string();
                        expected_fragments.retain(|c| !c.is_whitespace());

                        let mut fragments = data.fragments.to_string();
                        fragments.retain(|c| !c.is_whitespace());

                        assert_eq!(expected_fragments, fragments);
                    }
                } else {
                    assert_eq!(expected_event, event);
                }
            }
            None => panic!("unexpected stream event: {:?} (epxected EOF)", event),
        }
        if expected_events.is_empty() {
            break;
        }
    }

    drop(runner);
    // stream should unexpected EOF now, as we do not gracefully shutdown

    stream.next().await.unwrap().unwrap_err();
}

type TestEvent = DatastarEvent<JsonEventData<UpdateSignals>>;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
struct UpdateSignals {
    delay: Option<u64>,
}
