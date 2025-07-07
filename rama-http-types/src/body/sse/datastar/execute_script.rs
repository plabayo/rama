use crate::sse::{
    Event, EventDataWrite,
    datastar::{ElementPatchMode, EventType},
};
use mime::Mime;
use rama_error::{ErrorContext, OpaqueError};
use smol_str::SmolStr;
use std::borrow::Cow;

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
    /// Any other custom script attribute
    Custom { key: String, value: Option<String> },
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
    pub const TYPE: EventType = EventType::PatchElements;

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
            .with_data(self)
    }

    /// Consume `self` as a [`super::DatastarEvent`].
    pub fn into_datastar_event<T>(self) -> super::DatastarEvent<T> {
        Event::new()
            .try_with_event(Self::TYPE.as_smol_str())
            .unwrap()
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

        write!(w, "selector body\nmode {}\n", ElementPatchMode::Append)
            .context("write hardcoded selector and mode for execute script sugar")?;

        w.write_all(b"elements <script")
            .context("write opening of opening tag <script")?;

        if let Some(ref attributes) = self.attributes
            && (attributes.len() != 1
                || !matches!(attributes[0], ScriptAttribute::Type(ScriptType::Module)))
        {
            for attribute in attributes {
                match attribute {
                    ScriptAttribute::Src(src) => write!(w, r##" src="{src}""##)
                        .context("ExecuteScript: write attribute: src")?,
                    ScriptAttribute::Type(script_type) => match script_type {
                        ScriptType::Module => w
                            .write_all(b" type=\"module\"")
                            .context("ExecuteScript: write attribute: type=module")?,
                        ScriptType::ImportMap => w
                            .write_all(b" type=\"importmap\"")
                            .context("ExecuteScript: write attribute: type=importmap")?,
                        ScriptType::Mime(mime) => write!(w, r##"type="{mime}""##)
                            .context("ExecuteScript: write attribute: type=<mime>")?,
                    },
                    ScriptAttribute::Async => {
                        w.write_all(b" async")
                            .context("ExecuteScript: write attribute: async=true")?;
                    }
                    ScriptAttribute::Defer => {
                        w.write_all(b" defer")
                            .context("ExecuteScript: write attribute: defer=true")?;
                    }
                    ScriptAttribute::NoModule => {
                        w.write_all(b" nomodule")
                            .context("ExecuteScript: write attribute: nomodule=true")?;
                    }
                    ScriptAttribute::Integrity(integrity) => {
                        write!(w, r##" integrity="{integrity}""##)
                            .context("ExecuteScript: write attribute: integrity")?
                    }
                    ScriptAttribute::CrossOrigin(kind) => {
                        write!(w, r##" crossorigin="{kind}""##)
                            .context("ExecuteScript: write attribute: crossorigin")?
                    }
                    ScriptAttribute::ReferrerPolicy(policy) => {
                        write!(w, r##" referrerpolicy="{policy}""##)
                            .context("ExecuteScript: write attribute: referrerpolicy")?
                    }
                    ScriptAttribute::Charset(charset) => write!(w, r##" charset="{charset}""##)
                        .context("ExecuteScript: write attribute: charset")?,
                    ScriptAttribute::Custom { key, value } => match value {
                        Some(value) => write!(w, r##" key="{value}""##),
                        None => write!(w, " {key}"),
                    }
                    .context("ExecuteScript: write custom attribute")?,
                }
            }
        }

        if self.auto_remove.unwrap_or(true) {
            write!(w, r##" data-effect="el.remove()""##)
                .context("ExecuteScript: write autoRemove")?;
        }

        write!(w, ">\n").context("ExecuteScript: write closing tag of <script>")?;

        for script_line in script_lines {
            write!(w, "elements {next_script_line}\n")
                .context("ExecuteScript: write script line")?;
            next_script_line = script_line;
        }
        write!(w, "elements {next_script_line}\n")
            .context("ExecuteScript: write last script line")?;
        write!(w, "elements </script>").context("ExecuteScript: write closing tag </script>")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sse::{EventDataLineReader, EventDataRead, datastar::PatchElements};

    fn assert_sugar_is_valid_patch_element(data: String) {
        let mut reader = PatchElements::line_reader();
        for line in data.lines() {
            reader.read_line(line).unwrap();
        }
        reader
            .data(Some(EventType::PatchElements.as_str()))
            .unwrap()
            .unwrap();
    }

    #[test]
    fn test_execute_script_sugar_simple() {
        let mut output_sugar = Vec::new();
        ExecuteScript::new("console.alert('hello!');")
            .write_data(&mut output_sugar)
            .expect("write data");

        let mut output_expected = Vec::new();
        PatchElements::new(
            "<script data-effect=\"el.remove()\">\nconsole.alert('hello!');\n</script>",
        )
        .with_mode(ElementPatchMode::Append)
        .with_selector("body")
        .write_data(&mut output_expected)
        .expect("write data");

        let sugar = String::from_utf8(output_sugar).unwrap();
        let expected = String::from_utf8(output_expected).unwrap();
        assert_eq!(sugar, expected);
        assert_sugar_is_valid_patch_element(sugar);
    }

    #[test]
    fn test_execute_script_sugar_complex() {
        let mut output_sugar = Vec::new();
        ExecuteScript::new(
            r##"const url = "https://example.org/products.json";
try {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Response status: ${response.status}`);
    }

    const json = await response.json();
    console.log(json);
} catch (error) {
    console.error(error.message);
}"##,
        )
        .with_auto_remove(false)
        .with_attribute(ScriptAttribute::Async)
        .with_additional_attribute(ScriptAttribute::Charset(SmolStr::new_static("utf-8")))
        .write_data(&mut output_sugar)
        .expect("write data");

        let mut output_expected = Vec::new();
        PatchElements::new(
            r##"<script async charset="utf-8">
const url = "https://example.org/products.json";
try {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Response status: ${response.status}`);
    }

    const json = await response.json();
    console.log(json);
} catch (error) {
    console.error(error.message);
}
</script>"##,
        )
        .with_mode(ElementPatchMode::Append)
        .with_selector("body")
        .write_data(&mut output_expected)
        .expect("write data");

        let sugar = String::from_utf8(output_sugar).unwrap();
        let expected = String::from_utf8(output_expected).unwrap();
        assert_eq!(sugar, expected);
        assert_sugar_is_valid_patch_element(sugar);
    }
}
