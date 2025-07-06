use std::time::Instant;

use super::utils;

use rama::{
    Context,
    futures::StreamExt,
    http::{
        BodyExtractExt, StatusCode,
        headers::{ContentType, HeaderMapExt, dep::mime},
        sse::{
            JsonEventData,
            datastar::{DatastarEvent, EventType, PatchElements},
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

    let start_ts = Instant::now();

    // test the actual stream content

    let mut expected_events: Vec<TestEvent> = vec![
        PatchElements::new_remove("#server-warning").into(),
        PatchElements::new(
            r##"
<div id='message'>Hello, Datastar!</div>
<div id="progress-bar" style="width: 100%"></div>
"##,
        )
        .into(),
    ];

    // add all messages (as we expect it come as animated frames due to call of `/start` endpoint)
    // this also includes an update of the signals first, as server is source of truth
    const MESSAGE: &str = "Hello, Datastar!";
    for i in 1..=MESSAGE.len() {
        let text = &MESSAGE[..i];
        let progress = (i as f64) / (MESSAGE.len() as f64) * 100f64;
        expected_events.push(
            PatchElements::new(format!(
                r##"
<div id='message'>{text}</div>
<div id="progress-bar" style="width: {progress}%"></div>
"##
            ))
            .into(),
        )
    }
    expected_events.reverse();

    let mut sse_status_counter = 0;
    let mut signal_counter = 0;

    let mut stream = runner
        .get("http://127.0.0.1:62031/hello-world")
        .send(Context::default())
        .await
        .unwrap()
        .into_body()
        .into_event_stream();

    // start animation so we get it streamed in next response
    let response = runner
        .post("http://127.0.0.1:62031/start?datastar=")
        .json(&json!({
            "delay": 1,
        }))
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, response.status());

    let mut index = 0;
    while let Some(result) = stream.next().await {
        let event: TestEvent = result.unwrap();
        index += 1;
        println!("#{index}> >>RECVD: {event:?}");

        if event.event() == Some(EventType::PatchSignals.as_str()) {
            // check separately for out of order stuff that's not important to this test

            let data = event.into_data().unwrap().into_patch_signals().unwrap();
            assert!(!data.only_if_missing);

            if signal_counter == 0 {
                // depending on how it was executed can already be 1 or still 400.
                assert!([400, 1].contains(&data.signals.delay.unwrap()));
            } else {
                assert_eq!(1, data.signals.delay.unwrap());
            }

            signal_counter += 1;
            continue;
        }

        if event
            .data()
            .cloned()
            .and_then(|d| d.into_patch_elements().ok())
            .map(|d| d.elements.unwrap_or_default().contains("sse-status"))
            .unwrap_or_default()
        {
            sse_status_counter += 1;
            continue;
        }

        match expected_events.pop() {
            Some(expected_event) => {
                // merge elements handled differently
                // as elements can have meaningless differences in newlines
                if expected_event.event() == Some(EventType::PatchElements.as_str()) {
                    assert_eq!(
                        expected_event.event(),
                        event.event(),
                        "event #{index}: {event:?}"
                    );
                    assert_eq!(expected_event.id(), event.id(), "event #{index}: {event:?}");
                    assert_eq!(
                        expected_event.retry(),
                        event.retry(),
                        "event #{index}: {event:?}"
                    );
                    assert_eq!(
                        expected_event.comment().collect_vec(),
                        event.comment().collect_vec(),
                        "event #{index}: {event:?}"
                    );

                    let expected_data = expected_event
                        .into_data()
                        .unwrap()
                        .into_patch_elements()
                        .unwrap();
                    let data = event.into_data().unwrap().into_patch_elements().unwrap();

                    assert_eq!(expected_data.selector, data.selector);
                    assert_eq!(expected_data.mode, data.mode);
                    assert_eq!(expected_data.use_view_transition, data.use_view_transition);

                    if expected_data
                        .elements
                        .as_deref()
                        .unwrap_or_default()
                        .contains("sse-status")
                    {
                        // only check if data also contains, as there
                        // is some data in the element that is based on timing
                        assert!(
                            data.elements
                                .as_deref()
                                .unwrap_or_default()
                                .contains("sse-status"),
                            "event #{index}: data = {data:?}"
                        );
                    } else {
                        let mut expected_elements = expected_data
                            .elements
                            .as_deref()
                            .unwrap_or_default()
                            .to_owned();
                        expected_elements.retain(|c| !c.is_whitespace());

                        let mut elements = data.elements.as_deref().unwrap_or_default().to_owned();
                        elements.retain(|c| !c.is_whitespace());

                        assert_eq!(expected_elements, elements, "event #{index}");
                    }
                } else {
                    assert_eq!(expected_event, event);
                }
            }
            None => panic!("unexpected stream event: {event:?} (epxected EOF)"),
        }

        if expected_events.is_empty() {
            break;
        }
    }

    drop(runner);
    // stream should unexpected EOF now, as we do not gracefully shutdown

    stream.next().await.unwrap().unwrap_err();

    assert_eq!(2, signal_counter);

    let expected_sse_status_counter = 2 + (start_ts.elapsed().as_secs() / 3);
    let diff = expected_sse_status_counter.saturating_sub(sse_status_counter);
    assert!(diff <= 1 || sse_status_counter.saturating_sub(expected_sse_status_counter) <= 1);
}

type TestEvent = DatastarEvent<JsonEventData<UpdateSignals>>;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
struct UpdateSignals {
    delay: Option<u64>,
}
