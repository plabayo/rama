//! Backend compilation before a captured connection is opened.

use rama_core::{error::BoxError, extensions::Extensions};

use crate::profile::{
    capture::joint::CapturedSlotKind, replay::request::ProfilePreservationMode,
    selection::variants::ConnectionSelection,
};

use super::PreparedConnectionComponents;

/// Compile backend-specific connection pieces without connection I/O.
///
/// The default `()` compiler prepares no additional components. A backend owns
/// validation of its native configuration and current request bindings. Errors
/// stop connection establishment, including in best-effort mode.
///
/// The returned value is applied only after every required component and the
/// built-in HTTP settings have passed their preservation checks.
pub trait ConnectionProfileCompiler<Input>: Send + Sync + 'static {
    type Compiled: CompiledConnectionProfile;

    /// Prepare `selection` from its decoded `components`. Current connection
    /// bindings come from `input`; `mode` determines permitted differences.
    fn compile(
        &self,
        input: &Input,
        selection: &ConnectionSelection,
        components: &PreparedConnectionComponents,
        mode: ProfilePreservationMode,
    ) -> Result<Self::Compiled, BoxError>;
}

/// Owned backend output that can be installed after validation succeeds.
///
/// Implementations report only components they actually prepared. Neither
/// profile archives nor caller-supplied capability flags establish that claim.
/// Applying the output must not perform connection I/O or need more validation.
pub trait CompiledConnectionProfile: Send + 'static {
    /// Whether this output implements the selected component's wire properties.
    fn supports(&self, component: CapturedSlotKind) -> bool;

    /// Install owned configuration after all preservation checks have passed.
    fn apply(self, extensions: &Extensions);
}

impl<Input> ConnectionProfileCompiler<Input> for () {
    type Compiled = ();

    fn compile(
        &self,
        _input: &Input,
        _selection: &ConnectionSelection,
        _components: &PreparedConnectionComponents,
        _mode: ProfilePreservationMode,
    ) -> Result<(), BoxError> {
        Ok(())
    }
}

impl CompiledConnectionProfile for () {
    fn supports(&self, _component: CapturedSlotKind) -> bool {
        false
    }

    fn apply(self, _extensions: &Extensions) {}
}
