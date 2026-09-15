use super::*;

fn entry(start_ms: u64, duration_ms: u64, label: &str) -> Entry {
    let mut entry = Entry::new(Duration::from_millis(start_ms), label);
    entry.duration = Duration::from_millis(duration_ms);
    entry
}

fn timeline() -> Timeline {
    let mut timeline = Timeline::new("TEST", "capture.test");
    timeline.connections = vec![
        Connection {
            id: "c0".into(),
            label: "conn 0".into(),
            fields: Vec::new(),
        },
        Connection {
            id: "c1".into(),
            label: "conn 1".into(),
            fields: Vec::new(),
        },
    ];
    let mut second = entry(200, 50, "second");
    second.connection = Some(1);
    let mut first = entry(0, 100, "first");
    first.connection = Some(0);
    first.sections = vec![Section::text("body", "hidden treasure")];
    let mut third = entry(100, 0, "third");
    third.connection = Some(0);
    third.detail = Some("teapot".into());
    // deliberately out of order: the timeline sorts.
    timeline.set_entries(vec![second, third, first]);
    timeline
}

#[test]
fn entries_are_sorted_by_start_and_span_covers_the_last_end() {
    let timeline = timeline();
    let labels: Vec<_> = timeline
        .entries()
        .iter()
        .map(|entry| entry.label.as_str())
        .collect();
    assert_eq!(labels, ["first", "third", "second"]);
    assert_eq!(timeline.span(), Duration::from_millis(250));
}

#[test]
fn timestamp_at_needs_an_epoch() {
    let mut timeline = timeline();
    assert!(timeline.timestamp_at(Duration::from_millis(10)).is_none());

    timeline.epoch = Some("2026-09-14T10:00:00Z".parse().unwrap());
    let at = timeline.timestamp_at(Duration::from_millis(1500)).unwrap();
    assert_eq!(at.to_string(), "2026-09-14T10:00:01.5Z");
}

#[test]
fn filter_matches_label_detail_and_section_text() {
    let mut view = View::new(timeline());
    assert_eq!(view.len(), 3);

    view.set_filter("TREASURE");
    assert_eq!(view.len(), 1);
    assert_eq!(view.selected().unwrap().label, "first");

    view.set_filter("teapot");
    assert_eq!(view.len(), 1);
    assert_eq!(view.selected().unwrap().label, "third");

    view.set_filter("nothing here");
    assert!(view.is_empty());
    assert!(view.selected().is_none());

    view.set_filter("");
    assert_eq!(view.len(), 3);
}

#[test]
fn filter_keeps_the_selected_entry_when_it_survives() {
    let mut view = View::new(timeline());
    view.select_last();
    assert_eq!(view.selected().unwrap().label, "second");

    view.set_filter("second");
    assert_eq!(view.selected().unwrap().label, "second");
    assert_eq!(view.cursor(), 0);
}

#[test]
fn connection_scope_cycles_through_all_connections() {
    let mut view = View::new(timeline());
    assert_eq!(view.connection(), None);

    view.cycle_connection();
    assert_eq!(view.connection(), Some(0));
    assert_eq!(view.len(), 2);

    view.cycle_connection();
    assert_eq!(view.connection(), Some(1));
    assert_eq!(view.len(), 1);
    assert_eq!(view.selected().unwrap().label, "second");

    view.cycle_connection();
    assert_eq!(view.connection(), None);
    assert_eq!(view.len(), 3);
}

#[test]
fn selection_is_clamped_at_both_ends() {
    let mut view = View::new(timeline());
    assert_eq!(view.cursor(), 0);
    view.select_prev();
    assert_eq!(view.cursor(), 0);

    view.select_next();
    view.select_next();
    view.select_next();
    assert_eq!(view.cursor(), 2);

    view.select_first();
    assert_eq!(view.cursor(), 0);
    view.select_last();
    assert_eq!(view.cursor(), 2);
}

#[test]
fn bar_maps_entries_onto_the_visible_window() {
    let view = View::new(timeline());
    assert_eq!(view.window(), (Duration::ZERO, Duration::from_millis(250)));

    let first = &view.timeline().entries()[0];
    let (start, end) = view.bar(first).unwrap();
    assert!(start.abs() < f64::EPSILON, "start: {start}");
    assert!((end - 0.4).abs() < 1e-9, "end: {end}");
}

#[test]
fn zoom_centres_on_the_selection_and_pan_stays_inside_the_capture() {
    let mut view = View::new(timeline());
    view.select_last(); // "second", starting at 200ms
    view.zoom(0.2);
    let (start, end) = view.window();
    assert_eq!(end.saturating_sub(start), Duration::from_millis(50));
    assert!(start >= Duration::from_millis(175), "start: {start:?}");

    // an entry outside the window has no bar
    let first = &view.timeline().entries()[0];
    assert!(view.bar(first).is_none());

    view.pan(-10.0);
    assert_eq!(view.window().0, Duration::ZERO);
    view.pan(10.0);
    assert_eq!(view.window().1, Duration::from_millis(250));

    view.reset_window();
    assert_eq!(view.window(), (Duration::ZERO, Duration::from_millis(250)));
}

#[test]
fn zooming_an_empty_timeline_keeps_a_usable_window() {
    let mut view = View::new(Timeline::new("TEST", "empty.test"));
    view.zoom(0.1);
    let (start, end) = view.window();
    assert_eq!(start, Duration::ZERO);
    assert_eq!(end, Duration::from_millis(1));
    assert!(view.selected().is_none());
}
