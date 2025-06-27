use crate::sse::{
    Event, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType, parser::is_lf,
};
use mime::Mime;
use rama_core::telemetry::tracing;
use rama_error::{ErrorContext, OpaqueError};
use smol_str::SmolStr;
use std::{borrow::Cow, str::FromStr};

/// [`ExecuteScript`] executes JavaScript in the browser
///
/// See the [Datastar documentation](https://data-star.dev/reference/sse_events#datastar-execute-script).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecuteScript {
    /// `script` is a string that represents the JavaScript to be executed by the browser.
    pub script: Cow<'static, str>,
    /// Whether to remove the script after execution.
    ///
    /// If not provided the Datastar client side will default to `true`.
    pub auto_remove: Option<bool>,
    /// A list of attributes to add to the script element.
    ///
    /// If not provided the Datastar client side will default to `type module`.
    ///
    /// Each item in the array ***must*** be a string in the format `key value`,
    /// boolean value used in cased of boolean attributes.
    pub attributes: Option<Vec<ScriptAttribute>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Valid attributes for scripts that can be attached to a [`ExecuteScript`].
pub enum ScriptAttribute {
    /// Any valid URL or relative path to a .js file.
    ///
    /// If omitted, the script content is inline.
    Src(String),
    /// Type of script.
    Type(ScriptType),
    /// Script is fetched and executed as soon as possible (non-blocking).
    Async,
    /// Script is fetched asynchronously but executed after HTML parsing completes.
    Defer,
    /// Used to deliver fallback scripts to older browsers.
    NoModule,
    /// A valid SRI hash.
    ///
    /// Cfr: <https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity>
    Integrity(String),
    /// CORS request
    CrossOrigin(CrossOriginKind),
    /// Controls what Referer is sent when fetching the script.
    ReferrerPolicy(ReferrerPolicy),
    /// Largely ignored by modern browsers; use UTF-8 everywhere.
    Charset(SmolStr),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
/// Possible values for [`ScriptAttribute::Type`].
pub enum ScriptType {
    #[default]
    /// ES Modules, enables top-level import/export.
    Module,
    /// Only for import maps (not script logic).
    ImportMap,
    /// [`mime::TEXT_JAVASCRIPT`] is the default for scripts,
    /// but [`ScriptType::Module`] is the default value in a datastar context.
    Mime(Mime),
}

rama_utils::macros::enums::enum_builder! {
    /// Possible values for [`ScriptAttribute::CrossOrigin`].
    @String
    pub enum CrossOriginKind {
        /// No credentials (cookies, headers).
        Anonymous => "anonymous",
        /// Include credentials.
        UseCredentials => "use-credentials",
    }
}

rama_utils::macros::enums::enum_builder! {
    /// Possible values for [`ScriptAttribute::ReferrerPolicy`].
    @String
    pub enum ReferrerPolicy {
        NoReferrer => "no-referrer",
        NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
        Origin => "origin",
        OriginWhenCrossOrigin => "origin-when-cross-origin",
        SameOrigin => "same-origin",
        StrictOrigin => "strict-origin",
        StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
        UnsafeUrl => "unsafe-url",
    }
}

impl ExecuteScript {
    pub const TYPE: EventType = EventType::ExecuteScript;

    /// Create a new [`ExecuteScript`] data blob.
    pub fn new(script: impl Into<Cow<'static, str>>) -> Self {
        Self {
            script: script.into(),
            auto_remove: None,
            attributes: None,
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<ExecuteScript> {
        Event::new()
            .try_with_event(Self::TYPE.as_smol_str())
            .unwrap()
            .with_retry(super::consts::DEFAULT_DATASTAR_DURATION)
            .with_data(self)
    }

    /// Consume `self` as a [`super::DatastarEvent`].
    pub fn into_datastar_event<T>(self) -> super::DatastarEvent<T> {
        Event::new()
            .try_with_event(Self::TYPE.as_smol_str())
            .unwrap()
            .with_retry(super::consts::DEFAULT_DATASTAR_DURATION)
            .with_data(super::EventData::ExecuteScript(self))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether to remove the script after execution.
        pub fn auto_remove(mut self, auto_remove: bool) -> Self {
            self.auto_remove = Some(auto_remove);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a single attribute to add to the script element.
        ///
        /// This overwrites any previously added script attribute.
        pub fn attribute(mut self, attribute: ScriptAttribute) -> Self {
            self.attributes = Some(vec![attribute]);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a list of attributes to add to the script element.
        pub fn attributes(mut self, attributes: impl IntoIterator<Item = ScriptAttribute>) -> Self {
            self.attributes = Some(attributes.into_iter().collect());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add an additional attribute
        pub fn additional_attribute(mut self, attribute: ScriptAttribute) -> Self {
            let attributes = self.attributes.get_or_insert_default();
            attributes.push(attribute);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a list of attributes to add to the script element.
        pub fn additional_attributes(mut self, attributes: impl IntoIterator<Item = ScriptAttribute>) -> Self {
            let this = self.attributes.get_or_insert_default();
            this.extend(attributes);
            self
        }
    }
}

impl From<ExecuteScript> for Event<ExecuteScript> {
    fn from(value: ExecuteScript) -> Self {
        value.into_sse_event()
    }
}

impl<T> From<ExecuteScript> for super::DatastarEvent<T> {
    fn from(value: ExecuteScript) -> Self {
        value.into_datastar_event()
    }
}

impl EventDataWrite for ExecuteScript {
    #[allow(clippy::write_with_newline)]
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        let mut script_lines = self.script.lines();
        let mut next_script_line = script_lines
            .next()
            .context("ExecuteScript: no script lines found")?;
        for script_line in script_lines {
            write!(w, "script {next_script_line}\n").context("ExecuteScript: write script line")?;
            next_script_line = script_line;
        }
        write!(w, "script {next_script_line}").context("ExecuteScript: write last script line")?;

        if let Some(auto_remove) = self.auto_remove {
            write!(w, "\nautoRemove {auto_remove}").context("ExecuteScript: write autoRemove")?;
        }

        if let Some(ref attributes) = self.attributes
            && (attributes.len() != 1
                || !matches!(attributes[0], ScriptAttribute::Type(ScriptType::Module)))
        {
            for attribute in attributes {
                w.write_all(b"\nattributes ")
                    .context("ExecuteScript: write attribute line keyword")?;
                match attribute {
                    ScriptAttribute::Src(src) => {
                        write!(w, "src {src}").context("ExecuteScript: write attribute: src")?
                    }
                    ScriptAttribute::Type(script_type) => match script_type {
                        ScriptType::Module => w
                            .write_all(b"type module")
                            .context("ExecuteScript: write attribute: type=module")?,
                        ScriptType::ImportMap => w
                            .write_all(b"type importmap")
                            .context("ExecuteScript: write attribute: type=importmap")?,
                        ScriptType::Mime(mime) => write!(w, "type {mime}")
                            .context("ExecuteScript: write attribute: type=<mime>")?,
                    },
                    ScriptAttribute::Async => {
                        w.write_all(b"async true")
                            .context("ExecuteScript: write attribute: async=true")?;
                    }
                    ScriptAttribute::Defer => {
                        w.write_all(b"defer true")
                            .context("ExecuteScript: write attribute: defer=true")?;
                    }
                    ScriptAttribute::NoModule => {
                        w.write_all(b"nomodule true")
                            .context("ExecuteScript: write attribute: nomodule=true")?;
                    }
                    ScriptAttribute::Integrity(integrity) => write!(w, "integrity {integrity}")
                        .context("ExecuteScript: write attribute: integrity")?,
                    ScriptAttribute::CrossOrigin(kind) => write!(w, "crossorigin {kind}")
                        .context("ExecuteScript: write attribute: crossorigin")?,
                    ScriptAttribute::ReferrerPolicy(policy) => write!(w, "referrerpolicy {policy}")
                        .context("ExecuteScript: write attribute: referrerpolicy")?,
                    ScriptAttribute::Charset(charset) => write!(w, "charset {charset}")
                        .context("ExecuteScript: write attribute: charset")?,
                }
            }
        }

        Ok(())
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`ExecuteScript`].
#[derive(Debug)]
pub struct ExecuteScriptReader(Option<ExecuteScript>);

impl EventDataRead for ExecuteScript {
    type Reader = ExecuteScriptReader;

    fn line_reader() -> Self::Reader {
        ExecuteScriptReader(None)
    }
}

impl EventDataLineReader for ExecuteScriptReader {
    type Data = ExecuteScript;

    fn read_line(&mut self, line: &str) -> Result<(), OpaqueError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        };

        let execute_script = self
            .0
            .get_or_insert_with(|| ExecuteScript::new(Cow::Owned(Default::default())));

        let (keyword, value) = line
            .split_once(' ')
            // in case of empty value
            .unwrap_or((line, ""));

        if keyword.eq_ignore_ascii_case("script") {
            let script = execute_script.script.to_mut();
            script.push_str(value);
            script.push('\n');
        } else if keyword.eq_ignore_ascii_case("autoRemove") {
            execute_script.auto_remove = Some(
                value
                    .parse()
                    .context("ExecuteScriptReader: parse autoRemove")?,
            );
        } else if keyword.eq_ignore_ascii_case("attributes") {
            let (r#type, value) = value
                .trim()
                .split_once(' ')
                .context("invalid execute script attribute line: missing type separator")?;
            if r#type.eq_ignore_ascii_case("src") {
                execute_script
                    .attributes
                    .get_or_insert_default()
                    .push(ScriptAttribute::Src(value.to_owned()));
            } else if r#type.eq_ignore_ascii_case("type") {
                let value = value.trim();
                execute_script
                    .attributes
                    .get_or_insert_default()
                    .push(ScriptAttribute::Type(
                        if value.eq_ignore_ascii_case("module") {
                            ScriptType::Module
                        } else if value.eq_ignore_ascii_case("importmap") {
                            ScriptType::ImportMap
                        } else {
                            let mime = Mime::from_str(value)
                                .context("script attribute line: parse mime type")?;
                            ScriptType::Mime(mime)
                        },
                    ));
            } else if r#type.eq_ignore_ascii_case("async") {
                let value: bool = value
                    .parse()
                    .context("script attribute line: parse async boolean indicator")?;
                if value {
                    execute_script
                        .attributes
                        .get_or_insert_default()
                        .push(ScriptAttribute::Async);
                }
            } else if r#type.eq_ignore_ascii_case("defer") {
                let value: bool = value
                    .parse()
                    .context("script attribute line: parse defer boolean indicator")?;
                if value {
                    execute_script
                        .attributes
                        .get_or_insert_default()
                        .push(ScriptAttribute::Defer);
                }
            } else if r#type.eq_ignore_ascii_case("noModule") {
                let value: bool = value
                    .parse()
                    .context("script attribute line: parse noModule boolean indicator")?;
                if value {
                    execute_script
                        .attributes
                        .get_or_insert_default()
                        .push(ScriptAttribute::NoModule);
                }
            } else if r#type.eq_ignore_ascii_case("integrity") {
                execute_script
                    .attributes
                    .get_or_insert_default()
                    .push(ScriptAttribute::Integrity(value.to_owned()));
            } else if r#type.eq_ignore_ascii_case("crossOrigin") {
                execute_script.attributes.get_or_insert_default().push(
                    ScriptAttribute::CrossOrigin(
                        value
                            .parse()
                            .context("script attribute line: parse cross-origin value")?,
                    ),
                );
            } else if r#type.eq_ignore_ascii_case("referrerPolicy") {
                execute_script.attributes.get_or_insert_default().push(
                    ScriptAttribute::ReferrerPolicy(
                        value
                            .parse()
                            .context("script attribute line: parse referrer-policy value")?,
                    ),
                );
            } else {
                tracing::debug!(
                    "ExecuteScriptReader: ignore unknown execute script attribute line: keyword = {}; type = {}; value = {}",
                    keyword,
                    r#type,
                    value,
                );
            }
        } else {
            tracing::debug!(
                "ExecuteScriptReader: ignore unknown execute script line: keyword = {}; value = {}",
                keyword,
                value,
            );
        }

        Ok(())
    }

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, OpaqueError> {
        let mut execute_script = match self.0.take() {
            Some(execute_script) => execute_script,
            None => return Ok(None),
        };

        if !event
            .and_then(|e| {
                e.parse::<EventType>()
                    .ok()
                    .map(|t| t == EventType::ExecuteScript)
            })
            .unwrap_or_default()
        {
            return Err(OpaqueError::from_display(
                "ExecuteScriptReader: unexpected event type: expected: datastar-execute-script",
            ));
        }

        if execute_script
            .script
            .chars()
            .next_back()
            .map(is_lf)
            .unwrap_or_default()
        {
            execute_script.script.to_mut().pop();
        }
        if execute_script.script.is_empty() {
            return Err(OpaqueError::from_display(
                "execute script contains no script",
            ));
        }

        Ok(Some(execute_script))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_execute_script(input: &str) -> ExecuteScript {
        let mut reader = ExecuteScript::line_reader();
        for line in input.lines() {
            reader.read_line(line).unwrap();
        }
        reader
            .data(Some("datastar-execute-script"))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn test_deserialize_minimal() {
        let data = read_execute_script(r##"script console.log('Hello, world!')"##);
        assert_eq!(data.script, r##"console.log('Hello, world!')"##);
        assert_eq!(data.auto_remove, None);
        assert_eq!(data.attributes, None);
    }

    #[test]
    fn test_serialize_deserialize_reflect() {
        let expected_data = ExecuteScript::new(
            r##"console.log('Hello, world!')\nconsole.log('A second greeting')"##,
        )
        .with_auto_remove(false)
        .with_attributes([
            ScriptAttribute::Type(ScriptType::Module),
            ScriptAttribute::Defer,
        ]);

        let mut buf = Vec::new();
        expected_data.write_data(&mut buf).unwrap();

        let input = String::from_utf8(buf).unwrap();
        let data = read_execute_script(&input);

        assert_eq!(expected_data, data);
    }

    #[test]
    fn test_serialize_deserialize_reflect_with_auto_remove() {
        let expected_data = ExecuteScript::new(
            r##"console.log('Hello, world!')\nconsole.log('A second greeting')"##,
        )
        .with_auto_remove(true)
        .with_attribute(ScriptAttribute::Async);

        let mut buf = Vec::new();
        expected_data.write_data(&mut buf).unwrap();

        let input = String::from_utf8(buf).unwrap();
        let data = read_execute_script(&input);

        assert_eq!(expected_data, data);
    }
}
