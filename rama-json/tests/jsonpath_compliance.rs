use rama_json::capture::{CaptureHandler, CapturedValue, JsonCapturer};
use rama_json::path::JsonPath;
use rama_json::select::ValuePath;
use rama_json::{JsonError, JsonErrorKind};
use rama_utils::octets::mib;
use serde::Deserialize;
use serde_json::Value;
use serde_json::value::RawValue;

const CTS_JSON: &str = include_str!("jsonpath-compliance/cts.json");

#[derive(Debug, Deserialize)]
struct Cts<'a> {
    #[serde(borrow)]
    tests: Vec<CtsCase<'a>>,
}

#[derive(Debug, Deserialize)]
struct CtsCase<'a> {
    name: String,
    selector: String,
    #[serde(default, borrow)]
    document: Option<&'a RawValue>,
    #[serde(default)]
    result: Option<Vec<Value>>,
    #[serde(default)]
    results: Option<Vec<Vec<Value>>>,
    #[serde(default)]
    result_paths: Option<Vec<String>>,
    #[serde(default)]
    results_paths: Option<Vec<Vec<String>>>,
    #[serde(default)]
    invalid_selector: bool,
}

#[derive(Debug, PartialEq)]
struct Hit {
    path: ValuePath,
    value: Value,
}

#[derive(Debug, Default)]
struct Collector {
    hits: Vec<Hit>,
}

impl CaptureHandler for Collector {
    fn handle_capture(&mut self, value: CapturedValue<'_>) -> Result<(), JsonError> {
        self.hits.push(Hit {
            path: value.path().clone(),
            value: value.deserialize()?,
        });
        Ok(())
    }
}

#[test]
fn jsonpath_cts_supported_streaming_subset() -> Result<(), String> {
    let cts: Cts<'_> = serde_json::from_str(CTS_JSON).map_err(|err| err.to_string())?;
    let mut exercised = 0;
    let mut skipped_streaming_gaps = 0;

    for case in &cts.tests {
        if case.invalid_selector {
            continue;
        }

        let path = match case.selector.parse::<JsonPath>() {
            Ok(path) => path,
            Err(err) if is_known_streaming_gap(case, &err) => {
                skipped_streaming_gaps += 1;
                continue;
            }
            Err(err) => {
                return Err(format!(
                    "valid CTS selector {:?} ({}) was rejected: {err}",
                    case.selector, case.name
                ));
            }
        };

        let Some(document) = case.document else {
            return Err(format!("CTS case {} has no document", case.name));
        };
        let actual = capture(document.get().as_bytes(), path)
            .map_err(|err| format!("CTS case {} failed during capture: {err}", case.name))?;

        if is_streaming_order_gap(case, &actual) {
            skipped_streaming_gaps += 1;
            continue;
        }

        assert_case_matches(case, &actual)?;
        exercised += 1;
    }

    assert!(
        exercised > 100,
        "CTS supported subset was unexpectedly small"
    );
    assert!(
        skipped_streaming_gaps > 0,
        "CTS did not exercise any explicit streaming gaps"
    );
    Ok(())
}

#[test]
fn jsonpath_cts_invalid_selectors_are_rejected() -> Result<(), String> {
    let cts: Cts<'_> = serde_json::from_str(CTS_JSON).map_err(|err| err.to_string())?;
    let mut invalid = 0;

    for case in &cts.tests {
        if !case.invalid_selector {
            continue;
        }
        invalid += 1;
        assert!(
            case.selector.parse::<JsonPath>().is_err(),
            "invalid CTS selector {:?} ({}) parsed successfully",
            case.selector,
            case.name
        );
    }

    assert!(invalid > 50, "CTS invalid selector coverage changed");
    Ok(())
}

fn capture(document: &[u8], path: JsonPath) -> Result<Vec<Hit>, JsonError> {
    let selectors = [path];
    let mut capturer = JsonCapturer::new(selectors, mib(8), Collector::default());
    capturer.write(document)?;
    capturer.end()?;
    Ok(capturer.into_handler().hits)
}

fn assert_case_matches(case: &CtsCase<'_>, actual: &[Hit]) -> Result<(), String> {
    if let Some(expected) = &case.result {
        let Some(expected_paths) = case.result_paths.as_deref() else {
            return Err(format!("CTS case {} has no result_paths", case.name));
        };
        return assert_hits_match(case, actual, expected, expected_paths);
    }

    let Some(expected_results) = case.results.as_deref() else {
        return Err(format!("CTS case {} has no results", case.name));
    };
    let Some(expected_paths) = case.results_paths.as_deref() else {
        return Err(format!("CTS case {} has no results_paths", case.name));
    };

    assert_eq!(
        expected_results.len(),
        expected_paths.len(),
        "CTS case {} has mismatched result alternatives",
        case.name
    );

    if expected_results
        .iter()
        .zip(expected_paths)
        .any(|(values, paths)| hits_match(actual, values, paths))
    {
        return Ok(());
    }

    Err(format!(
        "CTS case {} ({:?}) produced unexpected hits: {actual:?}",
        case.name, case.selector
    ))
}

fn assert_hits_match(
    case: &CtsCase<'_>,
    actual: &[Hit],
    expected_values: &[Value],
    expected_paths: &[String],
) -> Result<(), String> {
    if hits_match(actual, expected_values, expected_paths) {
        return Ok(());
    }
    Err(format!(
        "CTS case {} ({:?}) produced unexpected hits: {actual:?}; expected values \
         {expected_values:?} at paths {expected_paths:?}",
        case.name, case.selector
    ))
}

fn hits_match(actual: &[Hit], expected_values: &[Value], expected_paths: &[String]) -> bool {
    if actual.len() != expected_values.len() || actual.len() != expected_paths.len() {
        return false;
    }

    actual.iter().zip(expected_values).zip(expected_paths).all(
        |((hit, expected_value), expected_path)| {
            hit.value == *expected_value && path_matches(&hit.path, expected_path)
        },
    )
}

fn path_matches(actual: &ValuePath, expected_path: &str) -> bool {
    expected_path
        .parse::<JsonPath>()
        .is_ok_and(|expected| expected.matches_path(actual.segments()))
}

fn is_known_streaming_gap(case: &CtsCase<'_>, err: &JsonError) -> bool {
    match err.kind() {
        JsonErrorKind::UnsupportedJsonPath("filter selectors") => case.selector.contains('?'),
        JsonErrorKind::UnsupportedJsonPath(feature) if feature.contains("negative") => {
            case.selector.contains('-')
        }
        _ => false,
    }
}

fn is_streaming_order_gap(case: &CtsCase<'_>, actual: &[Hit]) -> bool {
    (selector_list_can_reorder(&case.selector) || capture_delays_container_order(actual))
        && values_match_any_alternative(case, actual)
}

fn capture_delays_container_order(actual: &[Hit]) -> bool {
    actual
        .iter()
        .any(|hit| matches!(hit.value, Value::Array(_) | Value::Object(_)))
}

fn values_match_any_alternative(case: &CtsCase<'_>, actual: &[Hit]) -> bool {
    if let Some(expected) = &case.result {
        return values_match_ignoring_order(actual, expected);
    }

    case.results.as_deref().is_some_and(|results| {
        results
            .iter()
            .any(|expected| values_match_ignoring_order(actual, expected))
    })
}

fn values_match_ignoring_order(actual: &[Hit], expected: &[Value]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut matched = vec![false; expected.len()];
    'actual: for hit in actual {
        for (index, expected_value) in expected.iter().enumerate() {
            if !matched[index] && hit.value == *expected_value {
                matched[index] = true;
                continue 'actual;
            }
        }
        return false;
    }
    true
}

fn selector_list_can_reorder(selector: &str) -> bool {
    let mut in_string = None;
    let mut escaped = false;
    let mut bracket_depth = 0usize;

    for c in selector.chars() {
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == quote {
                in_string = None;
            }
            continue;
        }

        match c {
            '\'' | '"' => in_string = Some(c),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if bracket_depth > 0 => return true,
            _ => {}
        }
    }

    false
}
