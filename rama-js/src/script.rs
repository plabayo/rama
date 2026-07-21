use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Owned JavaScript source text.
///
/// Cloning is cheap, making this suitable for cached scripts selected by a
/// middleware provider and moved into runtime executions.
#[derive(Clone)]
pub struct JsScript(JsScriptInner);

#[derive(Clone)]
enum JsScriptInner {
    Static(&'static str),
    Shared(Arc<str>),
}

impl JsScript {
    /// Create owned JavaScript source text.
    pub fn new(source: impl Into<Arc<str>>) -> Self {
        Self(JsScriptInner::Shared(source.into()))
    }

    /// Borrow the source text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            JsScriptInner::Static(source) => source,
            JsScriptInner::Shared(source) => source,
        }
    }
}

impl Default for JsScript {
    fn default() -> Self {
        Self(JsScriptInner::Static(""))
    }
}

impl PartialEq for JsScript {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for JsScript {}

impl Hash for JsScript {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl fmt::Debug for JsScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsScript")
            .field("len", &self.as_str().len())
            .finish_non_exhaustive()
    }
}

impl AsRef<str> for JsScript {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&'static str> for JsScript {
    fn from(value: &'static str) -> Self {
        Self(JsScriptInner::Static(value))
    }
}

impl From<String> for JsScript {
    fn from(value: String) -> Self {
        Self(JsScriptInner::Shared(Arc::from(value)))
    }
}

impl From<Box<str>> for JsScript {
    fn from(value: Box<str>) -> Self {
        Self(JsScriptInner::Shared(Arc::from(value)))
    }
}

impl From<Arc<str>> for JsScript {
    fn from(value: Arc<str>) -> Self {
        Self(JsScriptInner::Shared(value))
    }
}
