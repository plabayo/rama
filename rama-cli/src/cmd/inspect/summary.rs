//! Plain-text rendering of a decoded capture, for a pipe or a non-terminal stdout.

use std::fmt::Write as _;

use rama::inspect::timeline::View;

use super::util;

/// Print the capture's summary, its connections and its timeline rows.
pub(super) fn print(view: &View) {
    print!("{}", render(view));
}

pub(super) fn render(view: &View) -> String {
    let timeline = view.timeline();
    let mut out = format!("{} · {}\n", timeline.format, timeline.source);
    for field in &timeline.summary {
        _ = writeln!(out, "  {}: {}", field.name, field.value);
    }

    if !timeline.connections.is_empty() {
        _ = writeln!(out, "\nconnections ({}):", timeline.connections.len());
        for (index, connection) in timeline.connections.iter().enumerate() {
            let fields = connection
                .fields
                .iter()
                .map(|field| format!("{}: {}", field.name, field.value))
                .collect::<Vec<_>>()
                .join(", ");
            _ = writeln!(out, "  [{index}] {} — {fields}", connection.label);
        }
    }

    _ = writeln!(out, "\nentries ({}):", view.len());
    for entry in view.visible() {
        _ = writeln!(
            out,
            "  {:>10} {:>10}  {:<3} {:<6} {}{}",
            util::duration(entry.start),
            util::duration(entry.duration),
            entry
                .connection
                .map(|index| format!("[{index}]"))
                .unwrap_or_default(),
            entry.badge.as_deref().unwrap_or(""),
            entry.label,
            entry
                .detail
                .as_ref()
                .map(|detail| format!("  {detail}"))
                .unwrap_or_default(),
        );
    }
    out
}
