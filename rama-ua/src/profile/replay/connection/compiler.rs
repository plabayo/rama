//! Backend compilation before a captured connection is opened.

use rama_core::{error::BoxError, extensions::Extensions};

use crate::profile::{capture::joint::CapturedSlotKind, selection::variants::ConnectionSelection};

use super::PreparedConnectionComponents;

/// Compile backend-specific connection pieces without connection I/O.
///
/// The default `()` compiler prepares no additional components. A backend owns
/// validation of its native configuration and current request bindings. Errors
/// stop connection establishment and are reserved for malformed captures; a
/// capture the backend cannot replay safely is left uncompiled, falling back to
/// native behaviour, and the lowering is recorded in the components' report.
///
/// The returned value is applied only after every required component and the
/// built-in HTTP settings have passed their preservation checks.
pub trait ConnectionProfileCompiler<Input>: Send + Sync + 'static {
    type Compiled: CompiledConnectionProfile;

    /// Prepare `selection` from its decoded `components`. Current connection
    /// bindings come from `input`; record lowered items in the components' report.
    /// Move consumed components into the compiled output instead of cloning them.
    /// Admission still checks every slot in the original selection.
    fn compile(
        &self,
        input: &Input,
        selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
    ) -> Result<Self::Compiled, BoxError>;
}

/// Owned backend output admitted before a connection can open.
///
/// Implementations report only components they actually prepared. Neither
/// profile archives nor caller-supplied capability flags establish that claim.
/// The UA modifier consumes this output before invoking its native connector.
pub trait CompiledConnectionProfile: Send + 'static {
    /// Whether this output implements the selected component's wire properties.
    fn supports(&self, component: CapturedSlotKind) -> bool;
}

/// Install a compiler's ordinary native configuration before connecting.
///
/// Move configuration into the input store. Only the returned input bindings
/// remain in the outer UA modifier's future; do not retain native sessions or
/// duplicate the installed configuration there. Protocol connectors receive
/// ordinary settings, never this compiler output or its binding checks.
pub trait InstalledConnectionProfile<Input>: CompiledConnectionProfile {
    type Bindings: ConnectionProfileBindings<Input>;

    /// Install admitted settings and retain only the input requirements that
    /// must remain consistent while the inner connector runs.
    fn apply(self, extensions: &Extensions) -> Self::Bindings;
}

/// Adapter-owned input requirements, checked before profile facts are published.
///
/// Return `()` when the compiler needs no additional binding. These checks concern
/// admission inputs, not serialized ClientHello or packet comparisons. Place the
/// UA modifier around transport when its checks must precede TLS output.
pub trait ConnectionProfileBindings<Input>: Send + 'static {
    fn check(&self, input: &Input) -> Result<(), BoxError>;
}

impl<Input> ConnectionProfileBindings<Input> for () {
    fn check(&self, _input: &Input) -> Result<(), BoxError> {
        Ok(())
    }
}

impl<Input> ConnectionProfileCompiler<Input> for () {
    type Compiled = ();

    fn compile(
        &self,
        _input: &Input,
        _selection: &ConnectionSelection,
        _components: &mut PreparedConnectionComponents,
    ) -> Result<(), BoxError> {
        Ok(())
    }
}

impl CompiledConnectionProfile for () {
    fn supports(&self, _component: CapturedSlotKind) -> bool {
        false
    }
}

impl<Input> InstalledConnectionProfile<Input> for () {
    type Bindings = ();

    fn apply(self, _extensions: &Extensions) {}
}
