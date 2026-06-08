//! Tests for the core tokenizer.
//!
//! Two properties anchor correctness:
//!   * **identity** — concatenating every token's `raw()` reproduces the
//!     input byte-for-byte (the rewriter passthrough guarantee);
//!   * **structure** — the sequence of token events for curated inputs.
//!
//! The html5lib conformance corpus is wired in a later slice (alongside
//! streaming); anything a fuzzer surfaces should land here as a regression.

use super::{
    Cdata, Comment, Doctype, EndTag, LocalNameHash, StartTag, Text, TokenSink, Tokenizer, tokenize,
};

/// Sink that re-serializes every token's raw bytes, for the identity check.
#[derive(Default)]
struct Identity {
    out: Vec<u8>,
}

impl TokenSink for Identity {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        self.out.extend_from_slice(tag.raw());
    }
    fn end_tag(&mut self, tag: &EndTag<'_>) {
        self.out.extend_from_slice(tag.raw());
    }
    fn text(&mut self, text: &Text<'_>) {
        self.out.extend_from_slice(text.raw());
    }
    fn comment(&mut self, comment: &Comment<'_>) {
        self.out.extend_from_slice(comment.raw());
    }
    fn cdata(&mut self, cdata: &Cdata<'_>) {
        self.out.extend_from_slice(cdata.raw());
    }
    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.out.extend_from_slice(doctype.raw());
    }
}

fn assert_identity(input: &[u8]) {
    let mut sink = Identity::default();
    tokenize(input, &mut sink).expect("not ambiguous");
    assert_eq!(
        sink.out,
        input,
        "identity failed for {:?}",
        String::from_utf8_lossy(input)
    );
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Start {
        name: String,
        attrs: Vec<(String, Option<String>)>,
        self_closing: bool,
    },
    End(String),
    Text(String),
    Comment(String),
    Cdata(String),
    Doctype(Option<String>),
}

#[derive(Default)]
struct Collect {
    events: Vec<Event>,
}

fn s(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl TokenSink for Collect {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        let attrs = tag
            .attributes()
            .map(|a| (s(a.name()), a.has_value().then(|| s(a.value()))))
            .collect();
        self.events.push(Event::Start {
            name: s(tag.name()),
            attrs,
            self_closing: tag.is_self_closing(),
        });
    }
    fn end_tag(&mut self, tag: &EndTag<'_>) {
        self.events.push(Event::End(s(tag.name())));
    }
    fn text(&mut self, text: &Text<'_>) {
        self.events.push(Event::Text(s(text.as_bytes())));
    }
    fn comment(&mut self, comment: &Comment<'_>) {
        self.events.push(Event::Comment(s(comment.data())));
    }
    fn cdata(&mut self, cdata: &Cdata<'_>) {
        self.events.push(Event::Cdata(s(cdata.data())));
    }
    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.events.push(Event::Doctype(doctype.name().map(s)));
    }
}

fn events(input: &[u8]) -> Vec<Event> {
    let mut sink = Collect::default();
    tokenize(input, &mut sink).expect("not ambiguous");
    sink.events
}

fn start(name: &str, attrs: &[(&str, Option<&str>)], self_closing: bool) -> Event {
    Event::Start {
        name: name.to_owned(),
        attrs: attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(ToOwned::to_owned)))
            .collect(),
        self_closing,
    }
}

// --- identity -----------------------------------------------------------

#[test]
fn identity_corpus() {
    for input in [
        &b""[..],
        b"hello world",
        b"<p>hello</p>",
        b"<a href=\"/x\" data-y='z' disabled>link</a>",
        b"<br/>",
        b"<img src=foo.png alt=An\tImage>",
        b"<!-- a comment -->",
        b"<!DOCTYPE html>",
        b"<!doctype HTML>",
        b"text <b>bold</b> & more <i>x</i>",
        b"a < b and c > d",                             // stray angle brackets
        b"<",                                           // lone '<' at EOF
        b"<3 hearts",                                   // '<' + digit is text
        b"</>",                                         // empty end tag
        b"<?php echo 1 ?>",                             // bogus comment
        b"<!bogus>",                                    // bogus comment
        b"<![CDATA[x]]>",                               // CDATA-as-bogus-comment in HTML
        b"<div class=\"a > b\">x</div>",                // '>' inside quotes
        b"<unterminated attr=\"oops",                   // unterminated quoted value
        b"<tag",                                        // unterminated tag
        b"<!-- unterminated comment",                   // unterminated comment
        b"<p\n  id = main\n>x</p>",                     // whitespace around '='
        b"<UL><LI>A<LI>B</UL>",                         // uppercase, optional end tags
        br#"<script>var x = "</p>"; a<b;</script>"#,    // script: inner markup is text
        b"<script><!--<script>a</script>-->b</script>", // nested script escape
        b"<style>.a{color:red}</style>",                // rawtext
        b"<textarea><p>hi</textarea>",                  // rcdata
        b"<plaintext>a<b>c</plaintext>d",               // plaintext to EOF
        b"<SCRIPT>x</ScRiPt>",                          // case-insensitive end tag
        b"<style></styles></style>",                    // non-matching end tag is text
        b"<script>alert(1)",                            // unterminated raw text
        "<p>caf\u{e9} \u{1f600}</p>".as_bytes(),        // non-ascii text
    ] {
        assert_identity(input);
    }
}

// --- structure ----------------------------------------------------------

#[test]
fn structure_basic() {
    assert_eq!(
        events(b"<p>hello</p>"),
        vec![
            start("p", &[], false),
            Event::Text("hello".to_owned()),
            Event::End("p".to_owned()),
        ]
    );
}

#[test]
fn structure_attributes() {
    assert_eq!(
        events(b"<a href=\"/x\" data-y='z' checked rel=next>"),
        vec![start(
            "a",
            &[
                ("href", Some("/x")),
                ("data-y", Some("z")),
                ("checked", None),
                ("rel", Some("next")),
            ],
            false,
        )]
    );
}

#[test]
fn structure_self_closing_and_case() {
    assert_eq!(events(b"<BR/>"), vec![start("BR", &[], true)]);
    assert_eq!(
        events(b"<Div Id=Main></Div>"),
        vec![
            start("Div", &[("Id", Some("Main"))], false),
            Event::End("Div".to_owned()),
        ]
    );
}

#[test]
fn structure_comment_and_doctype() {
    assert_eq!(
        events(b"<!-- hi -->"),
        vec![Event::Comment(" hi ".to_owned())]
    );
    assert_eq!(events(b"<!---->"), vec![Event::Comment(String::new())]);
    assert_eq!(
        events(b"<!DOCTYPE html>"),
        vec![Event::Doctype(Some("html".to_owned()))]
    );
    assert_eq!(events(b"<!DOCTYPE>"), vec![Event::Doctype(None)]);
}

#[test]
fn structure_text_runs_merge() {
    // A stray '<' stays within a single text run.
    assert_eq!(events(b"a < b"), vec![Event::Text("a < b".to_owned())]);
}

#[test]
fn structure_bogus_comment() {
    assert_eq!(events(b"</>"), vec![Event::Comment(String::new())]);
    assert_eq!(events(b"<!x>"), vec![Event::Comment("x".to_owned())]);
}

// --- text modes ---------------------------------------------------------

#[test]
fn text_mode_script_inner_markup_is_text() {
    assert_eq!(
        events(br#"<script>var x = "</p>"; a<b;</script>"#),
        vec![
            start("script", &[], false),
            Event::Text(r#"var x = "</p>"; a<b;"#.to_owned()),
            Event::End("script".to_owned()),
        ]
    );
}

#[test]
fn text_mode_script_nested_escape() {
    // The terminating `</script>` is the last one (after `-->`).
    assert_eq!(
        events(b"<script><!--<script>a</script>-->b</script>"),
        vec![
            start("script", &[], false),
            Event::Text("<!--<script>a</script>-->b".to_owned()),
            Event::End("script".to_owned()),
        ]
    );
}

#[test]
fn text_mode_rawtext_rcdata() {
    assert_eq!(
        events(b"<style>.a{color:red}</style>"),
        vec![
            start("style", &[], false),
            Event::Text(".a{color:red}".to_owned()),
            Event::End("style".to_owned()),
        ]
    );
    assert_eq!(
        events(b"<textarea><p>hi</textarea>"),
        vec![
            start("textarea", &[], false),
            Event::Text("<p>hi".to_owned()),
            Event::End("textarea".to_owned()),
        ]
    );
    assert_eq!(
        events(b"<title>a<b>c</title>"),
        vec![
            start("title", &[], false),
            Event::Text("a<b>c".to_owned()),
            Event::End("title".to_owned()),
        ]
    );
}

#[test]
fn text_mode_end_tag_matching() {
    // `</styles>` is not an appropriate end tag for `<style>`.
    assert_eq!(
        events(b"<style></styles></style>"),
        vec![
            start("style", &[], false),
            Event::Text("</styles>".to_owned()),
            Event::End("style".to_owned()),
        ]
    );
    // case-insensitive name match
    assert_eq!(
        events(b"<SCRIPT>x</ScRiPt>"),
        vec![
            start("SCRIPT", &[], false),
            Event::Text("x".to_owned()),
            Event::End("ScRiPt".to_owned()),
        ]
    );
}

#[test]
fn text_mode_plaintext_runs_to_eof() {
    assert_eq!(
        events(b"<plaintext>a<b>c</plaintext>d"),
        vec![
            start("plaintext", &[], false),
            Event::Text("a<b>c</plaintext>d".to_owned()),
        ]
    );
}

#[test]
fn text_mode_unterminated_runs_to_eof() {
    assert_eq!(
        events(b"<script>alert(1)"),
        vec![
            start("script", &[], false),
            Event::Text("alert(1)".to_owned()),
        ]
    );
}

// --- streaming / chunk-invariance ---------------------------------------

/// Coalesces adjacent `Text` events (text may be delivered in pieces while
/// streaming; only its coalesced content is invariant).
fn coalesce(events: Vec<Event>) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::new();
    for event in events {
        match event {
            Event::Text(cur) => {
                if let Some(Event::Text(prev)) = out.last_mut() {
                    prev.push_str(&cur);
                } else {
                    out.push(Event::Text(cur));
                }
            }
            other => out.push(other),
        }
    }
    out
}

fn oneshot_events(input: &[u8]) -> Vec<Event> {
    let mut sink = Collect::default();
    Tokenizer::new()
        .with_strict(false)
        .tokenize(input, &mut sink)
        .expect("lenient");
    sink.events
}

fn streamed_events(input: &[u8], split: usize) -> Vec<Event> {
    let split = split.min(input.len());
    let mut sink = Collect::default();
    let mut tk = Tokenizer::new().with_strict(false);
    tk.write(&input[..split], &mut sink).expect("lenient");
    tk.write(&input[split..], &mut sink).expect("lenient");
    tk.end(&mut sink).expect("lenient");
    sink.events
}

fn streamed_identity(input: &[u8], split: usize) -> Vec<u8> {
    let split = split.min(input.len());
    let mut sink = Identity::default();
    let mut tk = Tokenizer::new().with_strict(false);
    tk.write(&input[..split], &mut sink).expect("lenient");
    tk.write(&input[split..], &mut sink).expect("lenient");
    tk.end(&mut sink).expect("lenient");
    sink.out
}

#[test]
fn chunk_invariance() {
    let inputs: &[&[u8]] = &[
        b"<p class=\"x\">hi <b>there</b></p>",
        b"text <!-- a comment --> more",
        b"<a href=\"a>b\" data-y='z'>link</a>",
        b"<script><!--<script>x</script>-->y</script>tail",
        b"<style>.a{color:red}</style>",
        b"<textarea><p>raw</textarea>",
        b"<!DOCTYPE html><html><body>x</body></html>",
        b"<svg><![CDATA[a<b]]></svg>",
        b"a < b & c > d",
        b"<div/><br/>",
        b"<!bogus><?pi?></>",
        b"<UL><LI>a<LI>b</UL>",
        // Regressions (fuzzer-found): a `\"` that is NOT an attribute value
        // must not be treated as a quoted region by the completeness check.
        b"<a \"x>y\">z",
        b"<a b=\"x>y\">z",
        b"<a<b \"c>d</a<b>",
    ];

    for input in inputs {
        let expected = coalesce(oneshot_events(input));
        for split in 0..=input.len() {
            assert_eq!(
                coalesce(streamed_events(input, split)),
                expected,
                "event mismatch splitting {:?} at {split}",
                String::from_utf8_lossy(input)
            );
            assert_eq!(
                streamed_identity(input, split),
                *input,
                "identity mismatch splitting {:?} at {split}",
                String::from_utf8_lossy(input)
            );
        }
    }
}

#[test]
fn streaming_many_small_writes() {
    // Feeding one byte at a time must match one-shot tokenization.
    let input = b"<p id=main>hello <em>world</em></p>";
    let mut sink = Collect::default();
    let mut tk = Tokenizer::new();
    for byte in input {
        tk.write(std::slice::from_ref(byte), &mut sink)
            .expect("not ambiguous");
    }
    tk.end(&mut sink).expect("not ambiguous");
    assert_eq!(coalesce(sink.events), coalesce(events(input)));
}

#[test]
fn tokenizer_is_reusable_after_end() {
    let mut tk = Tokenizer::new();
    let mut first = Collect::default();
    tk.tokenize(b"<a>1</a>", &mut first).expect("ok");
    let mut second = Collect::default();
    tk.tokenize(b"<b>2</b>", &mut second).expect("ok");
    assert_eq!(first.events, events(b"<a>1</a>"));
    assert_eq!(second.events, events(b"<b>2</b>"));
}

// --- name hashing -------------------------------------------------------

#[test]
fn local_name_hash_basics() {
    // ASCII case-insensitive, and `of` agrees with the `const` constructor.
    assert_eq!(LocalNameHash::of(b"DIV"), LocalNameHash::of(b"div"));
    assert_eq!(
        LocalNameHash::of(b"script"),
        LocalNameHash::from_static(b"script")
    );
    assert!(LocalNameHash::of(b"").is_none());
    assert!(!LocalNameHash::of(b"div").is_none());
}

#[test]
fn known_tags_are_collision_free() {
    // The tree-builder simulator (next slice) dispatches text modes on these.
    let tags: [&[u8]; 8] = [
        b"script",
        b"style",
        b"textarea",
        b"title",
        b"plaintext",
        b"iframe",
        b"xmp",
        b"noscript",
    ];
    for (i, a) in tags.iter().enumerate() {
        for b in tags.iter().skip(i + 1) {
            assert_ne!(LocalNameHash::of(a), LocalNameHash::of(b), "{a:?} vs {b:?}");
        }
    }
}

#[test]
fn tag_name_hashes_are_exposed() {
    #[derive(Default)]
    struct Hashes {
        start: Option<LocalNameHash>,
        end: Option<LocalNameHash>,
    }
    impl TokenSink for Hashes {
        fn start_tag(&mut self, tag: &StartTag<'_>) {
            self.start = Some(tag.name_hash());
        }
        fn end_tag(&mut self, tag: &EndTag<'_>) {
            self.end = Some(tag.name_hash());
        }
    }
    let mut sink = Hashes::default();
    tokenize(b"<Div></DIV>", &mut sink).expect("not ambiguous");
    assert_eq!(sink.start, Some(LocalNameHash::of(b"div")));
    assert_eq!(sink.end, Some(LocalNameHash::of(b"div")));
}

// --- robustness ---------------------------------------------------------

#[test]
fn never_panics_on_garbage() {
    for input in [
        &b""[..],
        b"<",
        b"<!",
        b"</",
        b"<!-",
        b"<!--",
        b"<a b=",
        b"<a b='",
        b"<<<>>>",
        b"<\xff\xfe>",
        b"<!DOCTYPE",
        b"<![",
    ] {
        let mut sink = Identity::default();
        tokenize(input, &mut sink).expect("not ambiguous");
        // identity must hold even for malformed input
        assert_eq!(sink.out, input);
    }
}

// --- foreign content (SVG / MathML) -------------------------------------

#[test]
fn foreign_cdata_is_real_in_svg() {
    // Inside SVG, `<![CDATA[ … ]]>` is character data and its `<` is not markup.
    assert_eq!(
        events(b"<svg><![CDATA[x<y]]></svg>"),
        vec![
            start("svg", &[], false),
            Event::Cdata("x<y".to_owned()),
            Event::End("svg".to_owned()),
        ]
    );
    assert_eq!(
        events(b"<math><![CDATA[a]]></math>"),
        vec![
            start("math", &[], false),
            Event::Cdata("a".to_owned()),
            Event::End("math".to_owned()),
        ]
    );
}

#[test]
fn cdata_is_bogus_comment_in_html() {
    // Outside foreign content, `<![CDATA[ … ]]>` is a bogus comment.
    assert_eq!(
        events(b"<![CDATA[x]]>"),
        vec![Event::Comment("[CDATA[x]]".to_owned())]
    );
}

#[test]
fn svg_html_integration_point_restores_html_rules() {
    // Inside an SVG HTML-integration point, CDATA reverts to a bogus comment.
    assert_eq!(
        events(b"<svg><foreignObject><![CDATA[x]]></foreignObject></svg>"),
        vec![
            start("svg", &[], false),
            start("foreignObject", &[], false),
            Event::Comment("[CDATA[x]]".to_owned()),
            Event::End("foreignObject".to_owned()),
            Event::End("svg".to_owned()),
        ]
    );
}

#[test]
fn foreign_content_identity() {
    for input in [
        &b"<svg><![CDATA[x<y]]></svg>"[..],
        b"<math><![CDATA[a]]></math>",
        b"<svg><foreignObject><![CDATA[x]]></foreignObject></svg>",
        b"<svg><rect width=\"1\"/></svg>",
    ] {
        assert_identity(input);
    }
}

#[test]
fn ambiguous_context_bails_in_strict_mode() {
    // `<style>` inside `<select>` is non-conforming and ambiguous to a
    // streaming parser: strict mode aborts, lenient (the default) tokenizes.
    let input = b"<select><style>x</style></select>";

    let mut strict = Collect::default();
    assert!(
        Tokenizer::new()
            .with_strict(true)
            .tokenize(input, &mut strict)
            .is_err()
    );

    let mut lenient = Collect::default();
    tokenize(input, &mut lenient).expect("lenient never bails");
    assert!(!lenient.events.is_empty());

    // `<script>` is allowed in `<select>`, so it never bails.
    let mut ok = Collect::default();
    tokenize(b"<select><script>x</script></select>", &mut ok).expect("script in select is fine");
}
