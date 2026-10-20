//! Display untrusted labels and diagnostics without terminal or direction controls.

use rama::utils::octets::kib;

pub(crate) fn display_text(value: &str) -> String {
    let mut text = String::new();
    for ch in value.chars().take(kib(8)) {
        if ch.is_control()
            || matches!(ch,
            '\u{00ad}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}'
            | '\u{feff}' | '\u{fff9}'..='\u{fffb}')
        {
            text.extend(ch.escape_default());
        } else {
            text.push(ch);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_escape_terminal_sequences_and_invisible_direction_controls() {
        let input =
            "client\u{1b}]8;;https://example.test\u{7}\u{202e}exe\u{2066}\u{200b}\u{2028}\u{2029}";
        let output = display_text(input);
        assert!(output.is_ascii());
        assert!(!output.chars().any(char::is_control));
        for code in ["1b", "7", "202e", "2066", "200b", "2028", "2029"] {
            assert!(output.contains(&format!("\\u{{{code}}}")));
        }
        assert_eq!(display_text("Chrome – 日本語"), "Chrome – 日本語");
        assert_eq!(display_text(&"a".repeat(kib(8) + 1)).len(), kib(8));
    }
}
