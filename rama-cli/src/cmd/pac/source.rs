use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    utils::str::decode_utf8_or_latin1_owned,
};

#[derive(Debug, Clone)]
pub(super) struct LoadedSource {
    source: String,
    origin: SourceOrigin,
}

#[derive(Debug, Clone)]
enum SourceOrigin {
    File(PathBuf),
    Inline,
    Stdin,
}

impl LoadedSource {
    pub(super) fn load<R>(
        positional: Option<String>,
        file: Option<PathBuf>,
        inline: Option<String>,
        force_stdin: bool,
        stdin: &mut R,
    ) -> Result<Self, BoxError>
    where
        R: Read,
    {
        match (positional, file, inline, force_stdin) {
            (Some(value), None, None, false) if value == "-" => Self::from_stdin(stdin),
            (Some(value), None, None, false) => Self::from_positional(value),
            (None, Some(path), None, false) => Self::from_file(path),
            (None, None, Some(source), false) => Self::from_inline(source),
            (None, None, None, _) => Self::from_stdin(stdin),
            _ => Err(BoxError::from_static_str(
                "PAC source must be supplied exactly once",
            )),
        }
    }

    fn from_positional(value: String) -> Result<Self, BoxError> {
        let path = Path::new(&value);
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => Self::from_file(path.to_owned()),
            Ok(_) => Err(
                BoxError::from_static_str("PAC source path is not a regular file")
                    .context_debug_field("path", path.to_owned()),
            ),
            Err(err) if err.kind() == io::ErrorKind::NotFound && !looks_like_path(&value) => {
                Self::from_inline(value)
            }
            Err(err) => Err(err)
                .context("inspect PAC source path")
                .with_context_debug_field("path", || path.to_owned()),
        }
    }

    pub(super) fn from_file(path: PathBuf) -> Result<Self, BoxError> {
        let bytes = fs::read(&path)
            .context("read PAC source file")
            .with_context_debug_field("path", || path.clone())?;
        Ok(Self {
            source: decode_utf8_or_latin1_owned(bytes),
            origin: SourceOrigin::File(path),
        })
    }

    fn from_inline(source: String) -> Result<Self, BoxError> {
        if source.is_empty() {
            return Err(BoxError::from_static_str("PAC source is empty"));
        }
        Ok(Self {
            source,
            origin: SourceOrigin::Inline,
        })
    }

    fn from_stdin<R: Read>(stdin: &mut R) -> Result<Self, BoxError> {
        let mut bytes = Vec::new();
        stdin
            .read_to_end(&mut bytes)
            .context("read PAC source from stdin")?;
        if bytes.is_empty() {
            return Err(BoxError::from_static_str(
                "no PAC source was supplied; pass a file, inline source, or pipe source to stdin",
            ));
        }
        Ok(Self {
            source: decode_utf8_or_latin1_owned(bytes),
            origin: SourceOrigin::Stdin,
        })
    }

    pub(super) fn reload(&mut self) -> Result<(), BoxError> {
        if let SourceOrigin::File(path) = &self.origin {
            *self = Self::from_file(path.clone())?;
        }
        Ok(())
    }

    pub(super) fn replace_with_file(&mut self, path: PathBuf) -> Result<(), BoxError> {
        *self = Self::from_file(path)?;
        Ok(())
    }

    pub(super) fn as_str(&self) -> &str {
        &self.source
    }

    pub(super) fn came_from_stdin(&self) -> bool {
        matches!(self.origin, SourceOrigin::Stdin)
    }

    pub(super) fn description(&self) -> String {
        match &self.origin {
            SourceOrigin::File(path) => path.display().to_string(),
            SourceOrigin::Inline => "<inline>".to_owned(),
            SourceOrigin::Stdin => "<stdin>".to_owned(),
        }
    }
}

fn looks_like_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first().copied(), Some(b'/' | b'\\'))
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with(".\\")
        || value.starts_with("..\\")
        || value.starts_with("~/")
        || value.starts_with("~\\")
        || value
            .rsplit(['/', '\\'])
            .next()
            .and_then(|name| name.rsplit_once('.'))
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("pac"))
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positional_existing_file_is_loaded_and_decoded() {
        let directory = rama::utils::fs::tempdir().unwrap();
        let path = directory.path().join("proxy.pac");
        fs::write(
            &path,
            b"// caf\xe9\nfunction FindProxyForURL(){return 'DIRECT'}",
        )
        .unwrap();

        let loaded = LoadedSource::load(
            Some(path.display().to_string()),
            None,
            None,
            false,
            &mut io::empty(),
        )
        .unwrap();

        assert!(loaded.as_str().starts_with("// café"));
        assert_eq!(loaded.description(), path.display().to_string());
        assert!(!loaded.came_from_stdin());

        let explicit = LoadedSource::load(None, Some(path), None, false, &mut io::empty()).unwrap();
        assert_eq!(explicit.as_str(), loaded.as_str());
    }

    #[test]
    fn positional_javascript_is_inline_source() {
        let source = "function FindProxyForURL(){return 'DIRECT'}";
        let loaded =
            LoadedSource::load(Some(source.to_owned()), None, None, false, &mut io::empty())
                .unwrap();

        assert_eq!(loaded.as_str(), source);
        assert_eq!(loaded.description(), "<inline>");
    }

    #[test]
    fn missing_path_like_positional_is_not_executed_as_source() {
        let error = LoadedSource::load(
            Some("missing-policy.pac".to_owned()),
            None,
            None,
            false,
            &mut io::empty(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("inspect PAC source path"));
    }

    #[test]
    fn directory_positional_is_rejected_as_a_non_file() {
        let directory = rama::utils::fs::tempdir().unwrap();
        let error = LoadedSource::load(
            Some(directory.path().display().to_string()),
            None,
            None,
            false,
            &mut io::empty(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn dash_reads_stdin_as_pac_source() {
        let source = b"function FindProxyForURL(){return 'DIRECT'}";
        let loaded = LoadedSource::load(
            Some("-".to_owned()),
            None,
            None,
            false,
            &mut source.as_slice(),
        )
        .unwrap();

        assert_eq!(loaded.as_str().as_bytes(), source);
        assert!(loaded.came_from_stdin());
    }

    #[test]
    fn empty_stdin_has_an_actionable_error() {
        let error = LoadedSource::load(None, None, None, false, &mut io::empty()).unwrap_err();
        assert!(error.to_string().contains("no PAC source was supplied"));
    }

    #[test]
    fn path_detection_covers_unix_windows_and_extension_forms() {
        for value in [
            "/tmp/policy",
            "./policy",
            "../policy",
            ".\\policy",
            "..\\policy",
            "~/policy",
            "~\\policy",
            "\\policy",
            "\\\\server\\share\\policy",
            "\\\\?\\C:\\policy",
            "policy.pac",
            "POLICY.PAC",
            "policy.PaC",
            ".pac",
            "folder/policy.pac",
            "folder\\policy.pac",
            "C:/policy",
            "C:\\policy",
        ] {
            assert!(looks_like_path(value), "{value}");
        }
        for value in [
            "function FindProxyForURL() {}",
            "C:policy",
            "1:\\policy",
            "Cx\\policy",
            "const ratio = 1 / 2;",
        ] {
            assert!(!looks_like_path(value), "{value}");
        }
    }

    #[test]
    fn file_sources_can_be_reloaded_and_replaced() {
        let directory = rama::utils::fs::tempdir().unwrap();
        let first = directory.path().join("first.pac");
        let second = directory.path().join("second.pac");
        fs::write(&first, "first").unwrap();
        fs::write(&second, "second").unwrap();
        let mut loaded = LoadedSource::from_file(first.clone()).unwrap();

        fs::write(&first, "updated").unwrap();
        loaded.reload().unwrap();
        assert_eq!(loaded.as_str(), "updated");

        loaded.replace_with_file(second.clone()).unwrap();
        assert_eq!(loaded.as_str(), "second");
        assert_eq!(loaded.description(), second.display().to_string());
    }
}
