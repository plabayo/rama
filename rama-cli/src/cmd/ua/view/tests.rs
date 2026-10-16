use super::*;
use rama::{
    ua::profile::{format::input::UserAgentProfileInput, model::identity::ProfileKey},
    utils::fs::TempDir,
};
use ratatui::{Terminal, backend::TestBackend};

#[test]
fn viewer_loads_partial_profiles_and_escapes_terminal_controls() {
    let directory = TempDir::new().unwrap();
    let file = directory.path().join("profiles.json");
    std::fs::write(
        &file,
        serde_json::to_vec(&[UserAgentProfileInput::new("library/1.2\u{1b}[31m")]).unwrap(),
    )
    .unwrap();
    let rows = file_rows(file.clone(), false).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].label.contains('\u{1b}'));
    assert!(!rows[0].details.contains('\u{1b}'));
    assert!(rows[0].details.contains("none observed"));
    assert!(
        rows[0]
            .details
            .contains("original sample counts and freshness are unknown")
    );
    std::fs::write(&file, br#"[{"uastr":"library","h1_settings":"invalid"}]"#).unwrap();
    file_rows(file, false).unwrap_err();
}

#[test]
fn viewer_filter_selection_and_resize_handle_empty_results() {
    let rows = ["alpha-library", "beta-library"]
        .map(|name| Row::from_profile(&UserAgentProfile::new(ProfileKey::new(name))).unwrap())
        .into_iter()
        .collect();
    let mut app = App::new(rows, "test input".to_owned());
    let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
    assert!(!app.key(key(KeyCode::Down)));
    assert_eq!(app.selected, 1);
    app.key(key(KeyCode::Char('/')));
    for ch in "beta".chars() {
        app.key(key(KeyCode::Char(ch)));
    }
    assert_eq!(app.visible, [1]);
    app.key(key(KeyCode::Enter));
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("beta-library"));
    assert!(text.contains("Observed data"));
    app.filter = "no such profile".to_owned();
    app.filter();
    for code in [KeyCode::Down, KeyCode::Up, KeyCode::End, KeyCode::PageDown] {
        app.key(key(code));
    }
    assert!(app.visible.is_empty());
    for (width, height) in [(1, 1), (8, 3), (60, 12), (120, 24)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
    }
    app.key(key(KeyCode::Esc));
    assert_eq!(app.visible, [0, 1]);
    assert_eq!(app.scroll, 0);
    assert!(app.key(key(KeyCode::Char('q'))));
}

#[test]
fn viewer_summary_budget_rejects_growth_without_retaining_a_partial_row() {
    let row = Row {
        label: "a".into(),
        details: "bc".into(),
    };
    let mut rows = Vec::new();
    let mut remaining = 2;
    push_row(&mut rows, &mut remaining, row).unwrap_err();
    assert!(rows.is_empty());
    assert_eq!(remaining, 2);
}
