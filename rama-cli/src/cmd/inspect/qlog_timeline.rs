//! qlog files into the shared [`Timeline`] view model.
//!
//! The reader keeps event bodies as JSON, so this renders them generically:
//! an event this build has never heard of still shows its name, its group and
//! every field it carries.

use std::{collections::BTreeMap, io::BufRead, time::Duration};

use rama::{
    error::BoxError,
    inspect::timeline::{Connection, Entry, Field, Level, Section, Timeline},
    quic::qlog::reader::{self, Event, FileSchema, QlogFile, ReadLimits},
    utils::str::arcstr::ArcStr,
};

use super::{Limits, util};

use serde_json::{Map, Value};

/// Deepest nesting rendered as separate fields; below that a value is shown as JSON.
const MAX_FIELD_DEPTH: usize = 3;

pub(super) fn decode(
    input: impl BufRead,
    source: &str,
    limits: Limits,
) -> Result<Timeline, BoxError> {
    // Events are rendered as they are decoded: an entry keeps the few strings it
    // shows, and the event's JSON is dropped instead of being held for the whole
    // session next to the entry built from it.
    let mut groups = Groups::default();
    let mut entries = Vec::new();
    let mut earliest_ms = f64::INFINITY;
    let file = reader::read_streaming(
        input,
        ReadLimits {
            max_events: limits.max_records,
            max_record_bytes: limits.max_bytes,
            max_contained_bytes: limits.max_bytes,
            ..Default::default()
        },
        |event| {
            earliest_ms = earliest_ms.min(event.time_ms);
            let connection = groups.index_of(&event);
            entries.push(event_entry(&event, connection, limits));
            Ok(())
        },
    )?;
    groups.name(&file);

    let schema = match file.schema {
        FileSchema::Contained => "contained",
        FileSchema::Sequential => "json-seq",
    };
    let mut timeline = Timeline::new(format!("qlog draft-14 ({schema})"), source);
    // Every trace shares the timeline's origin, so an absolute epoch is only
    // meaningful when the file agrees on one.
    let mut epochs = file.traces.iter().filter_map(|trace| trace.epoch);
    timeline.epoch = match (epochs.next(), epochs.next()) {
        (Some(epoch), None) => Some(epoch),
        _ => None,
    };
    timeline.summary = vec![
        Field::new("file schema", file.schema.urn()),
        Field::new(
            "title",
            file.title.clone().unwrap_or(Section::UNAVAILABLE.into()),
        ),
        Field::new("traces", file.traces.len().to_string()),
        Field::new("events", entries.len().to_string()),
        Field::new(
            "reference clock",
            file.traces
                .first()
                .and_then(|trace| trace.clock_type.clone())
                .unwrap_or(Section::UNAVAILABLE.into()),
        ),
        Field::new(
            "epoch",
            timeline.epoch.map_or_else(
                || ArcStr::from("unknown (monotonic reference)"),
                |epoch| epoch.to_string().into(),
            ),
        ),
    ];
    if let Some(description) = file.description.clone() {
        timeline
            .summary
            .push(Field::new("description", description));
    }

    // Times are relative to each trace's own reference; anchor the timeline at the
    // earliest event so several traces line up on one axis. Entries are rendered
    // against zero as they stream in and shifted here, in one pass.
    if earliest_ms.is_finite() && earliest_ms > 0.0 {
        let origin = Duration::try_from_secs_f64(earliest_ms / 1000.0).unwrap_or(Duration::ZERO);
        for entry in &mut entries {
            entry.start = entry.start.saturating_sub(origin);
        }
    }
    timeline.connections = groups.finish();
    timeline.set_entries(entries);
    Ok(timeline)
}

/// One file can hold several traces, and one trace several connection groups.
///
/// Groups are keyed as events stream past; their trace metadata is filled in
/// afterwards, since a streaming read only knows the traces once it is done.
#[derive(Debug, Default)]
struct Groups {
    index: BTreeMap<(usize, ArcStr), usize>,
    groups: Vec<(usize, ArcStr, usize)>,
    connections: Vec<Connection>,
}

impl Groups {
    fn index_of(&mut self, event: &Event) -> Option<usize> {
        let group = event
            .group_id
            .clone()
            .unwrap_or_else(|| format!("trace {}", event.trace).into());
        let index = *self
            .index
            .entry((event.trace, group.clone()))
            .or_insert_with(|| {
                self.groups.push((event.trace, group, 0));
                self.groups.len() - 1
            });
        if let Some((_, _, count)) = self.groups.get_mut(index) {
            *count += 1;
        }
        Some(index)
    }

    fn name(&mut self, file: &QlogFile) {
        let several = file.traces.len() > 1;
        self.connections = self
            .groups
            .iter()
            .map(|(trace_index, group, count)| {
                let trace = file.traces.get(*trace_index);
                let mut fields = vec![Field::new("group id", group.clone())];
                if several {
                    fields.push(Field::new("trace", trace_index.to_string()));
                }
                if let Some(trace) = trace {
                    if let Some(title) = &trace.title {
                        fields.push(Field::new("trace title", title.clone()));
                    }
                    if let Some(kind) = &trace.vantage_point.kind {
                        fields.push(Field::new("vantage point", kind.clone()));
                    }
                    if let Some(name) = &trace.vantage_point.name {
                        fields.push(Field::new("vantage point name", name.clone()));
                    }
                    for schema in &trace.event_schemas {
                        fields.push(Field::new("event schema", schema.clone()));
                    }
                }
                fields.push(Field::new("events", count.to_string()));
                Connection {
                    id: group.clone(),
                    label: match (several, trace.and_then(|trace| trace.title.as_ref())) {
                        (true, Some(title)) => format!("{title} · {group}").into(),
                        _ => group.clone(),
                    },
                    fields,
                }
            })
            .collect();
    }

    fn finish(self) -> Vec<Connection> {
        self.connections
    }
}

fn event_entry(event: &Event, connection: Option<usize>, limits: Limits) -> Entry {
    let (namespace, kind) = event
        .name
        .split_once(':')
        .unwrap_or(("qlog", event.name.as_str()));

    let mut entry = Entry::new(millis(event.time_ms), kind.to_owned());
    entry.connection = connection;
    entry.badge = Some(namespace.into());
    entry.level = level_of(kind);
    entry.detail = summarize(&event.data);

    let mut sections = vec![Section::fields(
        "event",
        vec![
            Field::new("name", event.name.clone()),
            Field::new("time", format!("{} ms", event.time_ms)),
            Field::new(
                "group id",
                event
                    .group_id
                    .clone()
                    .unwrap_or(Section::UNAVAILABLE.into()),
            ),
            Field::new(
                "path",
                event.path.clone().unwrap_or(Section::UNAVAILABLE.into()),
            ),
        ],
    )];
    sections.push(match &event.data {
        Value::Object(data) if !data.is_empty() => {
            Section::fields("data", json_fields(data, limits))
        }
        Value::Null => Section::unavailable("data", "event carries no data"),
        other => Section::text("data", util::preview(&other.to_string(), limits.max_body)),
    });
    if !event.extra.is_empty() {
        sections.push(Section::fields(
            "other members",
            json_fields(&event.extra, limits),
        ));
    }
    entry.sections = sections;
    entry
}

fn millis(time_ms: f64) -> Duration {
    Duration::try_from_secs_f64(time_ms / 1000.0).unwrap_or(Duration::ZERO)
}

/// Heuristic severity for an unknown event vocabulary: qlog names the outcome
/// in the event type itself.
fn level_of(kind: &str) -> Level {
    if kind.contains("error") || kind.contains("closed") || kind.contains("abort") {
        Level::Failure
    } else if kind.contains("lost") || kind.contains("dropped") || kind.contains("discarded") {
        Level::Warning
    } else if kind.contains("created") || kind.contains("started") || kind.contains("complete") {
        Level::Success
    } else {
        Level::Info
    }
}

/// A one-line gist of an event body: its first few scalar members.
fn summarize(data: &Value) -> Option<ArcStr> {
    let data = data.as_object()?;
    let summary = data
        .iter()
        .filter_map(|(key, value)| Some(format!("{key}={}", scalar(value)?)))
        .take(3)
        .collect::<Vec<_>>()
        .join(" ");
    (!summary.is_empty()).then(|| summary.into())
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

/// Flatten a JSON object into fields, keeping deeply nested values as JSON text.
fn json_fields(object: &Map<String, Value>, limits: Limits) -> Vec<Field> {
    let mut fields = Vec::with_capacity(object.len());
    flatten(object, &mut String::new(), 1, limits, &mut fields);
    fields
}

fn flatten(
    object: &Map<String, Value>,
    prefix: &mut String,
    depth: usize,
    limits: Limits,
    fields: &mut Vec<Field>,
) {
    for (key, value) in object {
        let restore = prefix.len();
        if !prefix.is_empty() {
            prefix.push('.');
        }
        prefix.push_str(key);
        match value {
            Value::Object(nested) if depth < MAX_FIELD_DEPTH && !nested.is_empty() => {
                flatten(nested, prefix, depth + 1, limits, fields);
            }
            Value::String(text) => {
                fields.push(Field::new(
                    prefix.as_str(),
                    util::preview(text, limits.max_body),
                ));
            }
            other => {
                fields.push(Field::new(
                    prefix.as_str(),
                    util::preview(&other.to_string(), limits.max_body),
                ));
            }
        }
        prefix.truncate(restore);
    }
}
