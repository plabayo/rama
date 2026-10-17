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
    /// Move consumed components into the compiled output instead of cloning them.
    /// Admission still checks every slot in the original selection.
    fn compile(
        &self,
        input: &Input,
        selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
        mode: ProfilePreservationMode,
    ) -> Result<Self::Compiled, BoxError>;
}

/// Owned backend output admitted before a connection can open.
///
/// Implementations report only components they actually prepared. Neither
/// profile archives nor caller-supplied capability flags establish that claim.
/// Native connectors retain and consume this output locally.
pub trait CompiledConnectionProfile: Send + 'static {
    /// Whether this output implements the selected component's wire properties.
    fn supports(&self, component: CapturedSlotKind) -> bool;
}

/// Installation hook for a compiler used by an outer emulation layer.
/// Native connectors consume their compiled output locally instead.
pub trait InstalledConnectionProfile: CompiledConnectionProfile {
    /// Install configuration after all preservation checks have passed.
    fn apply(self, extensions: &Extensions);
}

impl<Input> ConnectionProfileCompiler<Input> for () {
    type Compiled = ();

    fn compile(
        &self,
        _input: &Input,
        _selection: &ConnectionSelection,
        _components: &mut PreparedConnectionComponents,
        _mode: ProfilePreservationMode,
    ) -> Result<(), BoxError> {
        Ok(())
    }
}

impl CompiledConnectionProfile for () {
    fn supports(&self, _component: CapturedSlotKind) -> bool {
        false
    }
}

impl InstalledConnectionProfile for () {
    fn apply(self, _extensions: &Extensions) {}
}
