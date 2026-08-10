//! The private engine boundary.
//!
//! Everything above this module is engine-agnostic; only the engine
//! submodule (currently boa) touches actual engine types. Keep it that
//! way: no engine type may appear outside `engine/`.

mod boa;

pub(crate) use boa::Engine;
#[cfg(fuzzing)]
pub(crate) use boa::force_collect_for_fuzzing;

use crate::func::RawHostFn;
use crate::snapshot::JsSnapshotLimits;
use crate::value::{JsStr, JsValue};

/// Engine-agnostic configuration lowered from the runtime builder.
///
/// Cloneable so a builder can serve as a reusable blueprint:
/// values share their backing storage and host functions are shared.
#[derive(Clone)]
pub(crate) struct EngineConfig {
    pub(crate) strict: bool,
    pub(crate) recursion_limit: Option<usize>,
    pub(crate) loop_iteration_limit: Option<u64>,
    pub(crate) stack_size_limit: Option<usize>,
    pub(crate) execution_time_limit: Option<std::time::Duration>,
    pub(crate) snapshot_limits: JsSnapshotLimits,
    pub(crate) globals: Vec<(JsStr, GlobalEntry)>,
}

/// A global registration lowered from the runtime builder.
#[derive(Clone)]
pub(crate) enum GlobalEntry {
    Value(JsValue),
    Fn(RawHostFn),
    Namespace(Vec<(JsStr, NamespaceEntry)>),
}

/// A property of a global namespace object.
#[derive(Clone)]
pub(crate) enum NamespaceEntry {
    Value(JsValue),
    Fn(RawHostFn),
}
