use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

#[cfg(not(target_os = "ios"))]
use wasmtime::Strategy;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine as WasmEngine, Store, StoreLimits, StoreLimitsBuilder, Trap};

use super::{EngineConfig, GlobalEntry, NamespaceEntry};
use crate::error::{JsError, JsErrorKind};
use crate::func::RawHostFn;
use crate::host::{
    ErasedHostObject, HostCallback, HostClass, HostMemberKind as RustHostMemberKind,
    HostResourceCell,
};
use crate::snapshot::JsSnapshotLimits;
use crate::value::{JsArray, JsObject, JsStr, JsValue};

pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        path: "engine/starling/engine.wit",
        world: "engine",
    });
}

use bindings::rama::js_engine::host::Host;
use bindings::rama::js_engine::types::{
    ErrorKind, HostFunction, HostMember, HostMemberKind, NamedValue, Outcome, RuntimeOptions,
    SnapshotLimits,
};

const COMPONENT: &[u8] = include_bytes!("../../engine/starling/rama-js-engine.wasm");
const EPOCH_INTERVAL: Duration = Duration::from_millis(10);
const SETUP_DEADLINE_TICKS: u64 = u64::MAX / 2;
const FUEL_BASE: u64 = 2_000_000;
const FUEL_PER_LOOP_ITERATION: u64 = 1_024;
const WASM_STACK_SIZE: usize = rama_utils::octets::mib(2);

struct SharedEngine {
    engine: WasmEngine,
    component: Component,
}

static SHARED_ENGINE: OnceLock<Result<SharedEngine, Box<str>>> = OnceLock::new();

fn shared_engine() -> Result<&'static SharedEngine, JsError> {
    SHARED_ENGINE
        .get_or_init(|| {
            let mut config = Config::new();
            #[cfg(not(target_os = "ios"))]
            config.strategy(Strategy::Winch);
            #[cfg(target_os = "ios")]
            config
                .target(if cfg!(target_endian = "little") {
                    "pulley64"
                } else {
                    "pulley64be"
                })
                .map_err(|err| err.to_string().into_boxed_str())?;
            config
                .consume_fuel(true)
                .epoch_interruption(true)
                .max_wasm_stack(WASM_STACK_SIZE);
            let engine =
                WasmEngine::new(&config).map_err(|err| err.to_string().into_boxed_str())?;
            let component = Component::from_binary(&engine, COMPONENT)
                .map_err(|err| err.to_string().into_boxed_str())?;
            let ticker = engine.clone();
            std::thread::Builder::new()
                .name("rama-js-epoch".to_owned())
                .spawn(move || {
                    loop {
                        std::thread::sleep(EPOCH_INTERVAL);
                        ticker.increment_epoch();
                    }
                })
                .map_err(|err| err.to_string().into_boxed_str())?;
            Ok(SharedEngine { engine, component })
        })
        .as_ref()
        .map_err(|message| {
            JsError::new(
                JsErrorKind::Setup,
                format!("failed to initialize the javascript engine: {message}"),
            )
        })
}

#[derive(Clone)]
enum CallbackEntry {
    Global {
        name: JsStr,
        function: RawHostFn,
    },
    HostObject {
        name: JsStr,
        class_id: u32,
        callback: HostCallback,
    },
}

struct HostObjectEntry {
    class_id: u32,
    resource: Arc<HostResourceCell>,
}

struct HostState {
    callbacks: Vec<CallbackEntry>,
    objects: Vec<HostObjectEntry>,
    classes: Vec<Arc<HostClass>>,
    limits: StoreLimits,
    snapshot_limits: JsSnapshotLimits,
}

impl bindings::rama::js_engine::types::Host for HostState {}

impl Host for HostState {
    fn invoke(&mut self, callback_id: u32, object_id: Option<u32>, arguments: Vec<u8>) -> Outcome {
        let result = decode_arguments(&arguments, self.snapshot_limits).and_then(|arguments| {
            let callback = self
                .callbacks
                .get(callback_id as usize)
                .cloned()
                .ok_or_else(|| JsError::new(JsErrorKind::Setup, "unknown host callback"))?;
            match callback {
                CallbackEntry::Global { name, function } => {
                    if object_id.is_some() {
                        return Err(JsError::new(
                            JsErrorKind::Setup,
                            "global host function received an object receiver",
                        ));
                    }
                    function
                        .call(arguments)
                        .map_err(|err| prefixed_host_error(&name, &err))
                }
                CallbackEntry::HostObject {
                    name,
                    class_id,
                    callback,
                } => {
                    let object_id = object_id.ok_or_else(|| {
                        JsError::throw(format!("{name}: invalid host object receiver"))
                    })?;
                    let object = self.objects.get(object_id as usize).ok_or_else(|| {
                        JsError::throw(format!("{name}: invalid host object receiver"))
                    })?;
                    if object.class_id != class_id {
                        return Err(JsError::throw(format!(
                            "{name}: incompatible host object receiver"
                        )));
                    }
                    object
                        .resource
                        .call(&callback, arguments)
                        .map_err(|err| prefixed_host_error(&name, &err))
                }
            }
        });

        match result.and_then(|value| encode_value(&value, self.snapshot_limits)) {
            Ok(payload) => success_outcome(payload),
            Err(error) => error_outcome(&error),
        }
    }
}

fn prefixed_host_error(name: &JsStr, error: &JsError) -> JsError {
    JsError::new(error.kind(), format!("{name}: {}", error.message()))
}

pub(crate) struct Engine {
    store: Store<HostState>,
    bindings: bindings::Engine,
    snapshot_limits: JsSnapshotLimits,
    loop_iteration_limit: Option<u64>,
    execution_time_limit: Option<Duration>,
    poisoned: bool,
    not_send: PhantomData<Rc<()>>,
}

impl Engine {
    pub(crate) fn warm_up() -> Result<(), JsError> {
        shared_engine().map(|_engine| ())
    }

    pub(crate) fn new(config: EngineConfig) -> Result<Self, JsError> {
        let shared = shared_engine()?;
        let options = runtime_options(config.strict, config.snapshot_limits)?;
        let state = HostState {
            callbacks: Vec::new(),
            objects: Vec::new(),
            classes: Vec::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(config.memory_limit)
                .trap_on_grow_failure(true)
                .build(),
            snapshot_limits: config.snapshot_limits,
        };
        let mut store = Store::new(&shared.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(u64::MAX)
            .map_err(|err| setup_engine_error("failed to configure fuel", &err))?;
        store.set_epoch_deadline(SETUP_DEADLINE_TICKS);

        let mut linker = Linker::new(&shared.engine);
        bindings::Engine::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|err| setup_engine_error("failed to link javascript host functions", &err))?;
        let bindings = bindings::Engine::instantiate(&mut store, &shared.component, &linker)
            .map_err(|err| setup_engine_error("failed to instantiate javascript engine", &err))?;
        let configured = bindings
            .rama_js_engine_runtime()
            .call_configure(&mut store, options)
            .map_err(|err| setup_engine_error("failed to configure javascript engine", &err))?;
        outcome_unit(configured, config.snapshot_limits)
            .map_err(|err| setup_engine_error("failed to configure javascript engine", &err))?;

        let mut engine = Self {
            store,
            bindings,
            snapshot_limits: config.snapshot_limits,
            loop_iteration_limit: config.loop_iteration_limit,
            execution_time_limit: config.execution_time_limit,
            poisoned: false,
            not_send: PhantomData,
        };
        for (name, entry) in config.globals {
            engine.register_global(&name, entry)?;
        }
        Ok(engine)
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn ensure_not_poisoned(&self) -> Result<(), JsError> {
        if self.poisoned {
            return Err(JsError::new(
                JsErrorKind::Setup,
                "js runtime is poisoned: a previous operation trapped inside the wasm engine",
            ));
        }
        Ok(())
    }

    pub(crate) fn eval(&mut self, source: &str) -> Result<JsValue, JsError> {
        self.prepare_operation()?;
        let result = self
            .bindings
            .rama_js_engine_runtime()
            .call_evaluate(&mut self.store, source);
        self.finish_value(result)
    }

    pub(crate) fn exec(&mut self, source: &str) -> Result<(), JsError> {
        self.prepare_operation()?;
        let result = self
            .bindings
            .rama_js_engine_runtime()
            .call_exec(&mut self.store, source);
        self.finish_unit(result)
    }

    pub(crate) fn call(&mut self, name: &str, args: &[JsValue]) -> Result<JsValue, JsError> {
        let arguments = encode_arguments_for_guest(args, self.snapshot_limits)?;
        self.prepare_operation()?;
        let result =
            self.bindings
                .rama_js_engine_runtime()
                .call_call(&mut self.store, name, &arguments);
        self.finish_value(result)
    }

    pub(crate) fn has_global_fn(&mut self, name: &str) -> bool {
        if self.prepare_operation().is_err() {
            return false;
        }
        match self
            .bindings
            .rama_js_engine_runtime()
            .call_has_global_function(&mut self.store, name)
        {
            Ok(found) => found,
            Err(_error) => {
                self.poisoned = true;
                false
            }
        }
    }

    pub(crate) fn set_host_global(
        &mut self,
        name: &JsStr,
        object: ErasedHostObject,
    ) -> Result<(), JsError> {
        self.ensure_not_poisoned()?;
        validate_host_class(name, &object.class)?;
        let callback_count = self.store.data().callbacks.len();
        let object_count = self.store.data().objects.len();
        let class_count = self.store.data().classes.len();
        let class_id = if let Some(index) = self
            .store
            .data()
            .classes
            .iter()
            .position(|class| Arc::ptr_eq(class, &object.class))
        {
            u32::try_from(index).map_err(|_error| too_many_host_entries())?
        } else {
            let id = u32::try_from(self.store.data().classes.len())
                .map_err(|_error| too_many_host_entries())?;
            self.store
                .data_mut()
                .classes
                .push(Arc::clone(&object.class));
            id
        };
        let object_id = u32::try_from(self.store.data().objects.len())
            .map_err(|_error| too_many_host_entries())?;
        self.store.data_mut().objects.push(HostObjectEntry {
            class_id,
            resource: object.resource,
        });

        let mut members = Vec::with_capacity(object.class.members.len());
        for member in &object.class.members {
            let callback_id = self.push_callback(CallbackEntry::HostObject {
                name: member.name.clone(),
                class_id,
                callback: member.callback.clone(),
            })?;
            members.push(HostMember {
                name: member.name.to_string(),
                callback_id,
                kind: match member.kind {
                    RustHostMemberKind::Method => HostMemberKind::Method,
                    RustHostMemberKind::Getter => HostMemberKind::Getter,
                    RustHostMemberKind::Setter => HostMemberKind::Setter,
                },
                arity: optional_u32(member.callback.arity())?,
            });
        }

        self.prepare_setup()?;
        let outcome = self
            .bindings
            .rama_js_engine_runtime()
            .call_define_host_object(&mut self.store, name, object_id, class_id, &members);
        let result = match outcome {
            Ok(outcome) => outcome_unit(outcome, self.snapshot_limits)
                .map_err(|err| setup_global_error(name, err.message())),
            Err(error) => Err(self.trap_error(&error)),
        };
        if result.is_err() {
            self.store.data_mut().callbacks.truncate(callback_count);
            self.store.data_mut().objects.truncate(object_count);
            self.store.data_mut().classes.truncate(class_count);
        }
        result
    }

    fn register_global(&mut self, name: &JsStr, entry: GlobalEntry) -> Result<(), JsError> {
        self.prepare_setup()?;
        let result = match entry {
            GlobalEntry::Value(value) => {
                let value = encode_value(&value, self.snapshot_limits)
                    .map_err(|err| setup_global_error(name, err.message()))?;
                self.bindings.rama_js_engine_runtime().call_define_global(
                    &mut self.store,
                    name,
                    &value,
                )
            }
            GlobalEntry::Fn(function) => {
                let specification = self.host_function(name, &function)?;
                self.bindings
                    .rama_js_engine_runtime()
                    .call_define_host_function(&mut self.store, &specification)
            }
            GlobalEntry::Namespace(entries) => {
                let mut values = Vec::new();
                let mut functions = Vec::new();
                for (property, entry) in entries {
                    match entry {
                        NamespaceEntry::Value(value) => values.push(NamedValue {
                            name: property.to_string(),
                            value: encode_value(&value, self.snapshot_limits)
                                .map_err(|err| setup_global_error(name, err.message()))?,
                        }),
                        NamespaceEntry::Fn(function) => {
                            functions.push(self.host_function(&property, &function)?);
                        }
                    }
                }
                self.bindings
                    .rama_js_engine_runtime()
                    .call_define_namespace(&mut self.store, name, &values, &functions)
            }
        }
        .map_err(|err| setup_engine_error("failed to register javascript global", &err))?;
        outcome_unit(result, self.snapshot_limits)
            .map_err(|err| setup_global_error(name, err.message()))
    }

    fn host_function(
        &mut self,
        name: &JsStr,
        function: &RawHostFn,
    ) -> Result<HostFunction, JsError> {
        let callback_id = self.push_callback(CallbackEntry::Global {
            name: name.clone(),
            function: function.clone(),
        })?;
        Ok(HostFunction {
            name: name.to_string(),
            callback_id,
            arity: optional_u32(function.arity())?,
            lenient_args: function.lenient_args(),
        })
    }

    fn push_callback(&mut self, callback: CallbackEntry) -> Result<u32, JsError> {
        let id = u32::try_from(self.store.data().callbacks.len())
            .map_err(|_error| too_many_host_entries())?;
        self.store.data_mut().callbacks.push(callback);
        Ok(id)
    }

    fn prepare_setup(&mut self) -> Result<(), JsError> {
        self.ensure_not_poisoned()?;
        self.store
            .set_fuel(u64::MAX)
            .map_err(|err| setup_engine_error("failed to configure fuel", &err))?;
        self.store.set_epoch_deadline(SETUP_DEADLINE_TICKS);
        Ok(())
    }

    fn prepare_operation(&mut self) -> Result<(), JsError> {
        self.ensure_not_poisoned()?;
        let fuel = self.loop_iteration_limit.map_or(u64::MAX, |limit| {
            FUEL_BASE.saturating_add(limit.saturating_mul(FUEL_PER_LOOP_ITERATION))
        });
        self.store
            .set_fuel(fuel)
            .map_err(|err| setup_engine_error("failed to configure fuel", &err))?;
        let ticks = self
            .execution_time_limit
            .map_or(SETUP_DEADLINE_TICKS, |limit| {
                let interval_nanos = EPOCH_INTERVAL.as_nanos();
                let ticks = limit.as_nanos().div_ceil(interval_nanos);
                u64::try_from(ticks).unwrap_or(u64::MAX / 2).max(1)
            });
        self.store.set_epoch_deadline(ticks);
        Ok(())
    }

    fn finish_value(&mut self, result: wasmtime::Result<Outcome>) -> Result<JsValue, JsError> {
        match result {
            Ok(outcome) => outcome_value(outcome, self.snapshot_limits),
            Err(error) => Err(self.trap_error(&error)),
        }
    }

    fn finish_unit(&mut self, result: wasmtime::Result<Outcome>) -> Result<(), JsError> {
        match result {
            Ok(outcome) => outcome_unit(outcome, self.snapshot_limits),
            Err(error) => Err(self.trap_error(&error)),
        }
    }

    fn trap_error(&mut self, error: &wasmtime::Error) -> JsError {
        self.poisoned = true;
        if let Some(trap) = error.chain().find_map(|cause| cause.downcast_ref::<Trap>()) {
            return match trap {
                Trap::Interrupt => JsError::new(
                    JsErrorKind::LimitExceeded,
                    "javascript execution time limit exceeded",
                ),
                Trap::OutOfFuel => JsError::new(
                    JsErrorKind::LimitExceeded,
                    "javascript execution fuel limit exceeded",
                ),
                Trap::StackOverflow => JsError::new(
                    JsErrorKind::LimitExceeded,
                    "javascript engine wasm stack limit exceeded",
                ),
                Trap::MemoryOutOfBounds => JsError::new(
                    JsErrorKind::LimitExceeded,
                    "javascript engine memory limit exceeded",
                ),
                _ => JsError::new(
                    JsErrorKind::Setup,
                    "javascript engine trapped inside its wasm container",
                ),
            };
        }
        let text = format!("{error:#}");
        if text.contains("memory") || text.contains("grow") || text.contains("allocation") {
            JsError::new(
                JsErrorKind::LimitExceeded,
                "javascript engine memory limit exceeded",
            )
        } else {
            JsError::new(
                JsErrorKind::Setup,
                "javascript engine failed inside its wasm container",
            )
        }
    }
}

fn runtime_options(strict: bool, limits: JsSnapshotLimits) -> Result<RuntimeOptions, JsError> {
    Ok(RuntimeOptions {
        strict,
        snapshot_limits: SnapshotLimits {
            max_depth: limit_u32("snapshot depth", limits.max_depth())?,
            max_nodes: limit_u32("snapshot node count", limits.max_nodes())?,
            max_array_length: limit_u32("snapshot array length", limits.max_array_length())?,
            max_object_properties: limit_u32(
                "snapshot object property count",
                limits.max_object_properties(),
            )?,
            max_string_bytes: limit_u32("snapshot string bytes", limits.max_string_bytes())?,
        },
    })
}

fn limit_u32(name: &str, limit: usize) -> Result<u32, JsError> {
    u32::try_from(limit).map_err(|_error| {
        JsError::new(
            JsErrorKind::Setup,
            format!("{name} limit exceeds the wasm engine boundary maximum"),
        )
    })
}

fn optional_u32(value: Option<usize>) -> Result<Option<u32>, JsError> {
    value
        .map(|value| {
            u32::try_from(value).map_err(|_error| {
                JsError::new(
                    JsErrorKind::Setup,
                    "host function arity exceeds the wasm engine boundary maximum",
                )
            })
        })
        .transpose()
}

fn too_many_host_entries() -> JsError {
    JsError::new(
        JsErrorKind::Setup,
        "too many host entries for the wasm engine boundary",
    )
}

fn setup_engine_error(context: &str, error: &dyn std::fmt::Display) -> JsError {
    JsError::new(
        JsErrorKind::Setup,
        bounded_format(format_args!("{context}: {error}")),
    )
}

fn setup_global_error(name: &str, message: &str) -> JsError {
    JsError::new(
        JsErrorKind::Setup,
        bounded_format(format_args!(
            "failed to register global `{name}`: {message}"
        )),
    )
}

fn success_outcome(payload: Vec<u8>) -> Outcome {
    Outcome {
        ok: true,
        kind: None,
        message: String::new(),
        payload,
        thrown: None,
    }
}

fn error_outcome(error: &JsError) -> Outcome {
    Outcome {
        ok: false,
        kind: Some(error_kind_to_wit(error.kind())),
        message: bounded_format(format_args!("{}", error.message())),
        payload: Vec::new(),
        thrown: None,
    }
}

fn error_kind_to_wit(kind: JsErrorKind) -> ErrorKind {
    match kind {
        JsErrorKind::Parse => ErrorKind::Parse,
        JsErrorKind::Throw | JsErrorKind::Timeout => ErrorKind::Throw,
        JsErrorKind::LimitExceeded => ErrorKind::LimitExceeded,
        JsErrorKind::Conversion => ErrorKind::Conversion,
        JsErrorKind::NotFound => ErrorKind::NotFound,
        JsErrorKind::Setup => ErrorKind::Setup,
    }
}

fn error_kind_from_wit(kind: Option<ErrorKind>) -> JsErrorKind {
    match kind {
        Some(ErrorKind::Parse) => JsErrorKind::Parse,
        Some(ErrorKind::Throw) => JsErrorKind::Throw,
        Some(ErrorKind::LimitExceeded) => JsErrorKind::LimitExceeded,
        Some(ErrorKind::Conversion) => JsErrorKind::Conversion,
        Some(ErrorKind::NotFound) => JsErrorKind::NotFound,
        Some(ErrorKind::Setup) | None => JsErrorKind::Setup,
    }
}

fn outcome_unit(outcome: Outcome, limits: JsSnapshotLimits) -> Result<(), JsError> {
    if outcome.ok {
        Ok(())
    } else {
        Err(error_from_outcome(outcome, limits))
    }
}

fn outcome_value(outcome: Outcome, limits: JsSnapshotLimits) -> Result<JsValue, JsError> {
    if outcome.ok {
        decode_value(&outcome.payload, limits)
    } else {
        Err(error_from_outcome(outcome, limits))
    }
}

fn error_from_outcome(outcome: Outcome, limits: JsSnapshotLimits) -> JsError {
    let kind = error_kind_from_wit(outcome.kind);
    let mut error = JsError::new(kind, bounded_format(format_args!("{}", outcome.message)));
    if kind == JsErrorKind::Throw
        && let Some(thrown) = outcome.thrown
        && let Ok(value) = decode_value(&thrown, limits)
    {
        error = error.with_thrown(value);
    }
    error
}

fn validate_host_class(name: &JsStr, class: &HostClass) -> Result<(), JsError> {
    for (index, member) in class.members.iter().enumerate() {
        let has_conflict = class.members[..index]
            .iter()
            .filter(|previous| previous.name == member.name)
            .any(|previous| {
                !matches!(
                    (previous.kind, member.kind),
                    (RustHostMemberKind::Getter, RustHostMemberKind::Setter)
                        | (RustHostMemberKind::Setter, RustHostMemberKind::Getter)
                )
            });
        if has_conflict {
            return Err(setup_global_error(
                name,
                &format!("duplicate host object member `{}`", member.name),
            ));
        }
    }
    Ok(())
}

const MAX_ERROR_MESSAGE_BYTES: usize = rama_utils::octets::kib(4);

fn bounded_format(args: std::fmt::Arguments<'_>) -> String {
    use std::fmt::Write as _;

    struct BoundedWriter(String);

    impl std::fmt::Write for BoundedWriter {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let remaining = MAX_ERROR_MESSAGE_BYTES.saturating_sub(self.0.len());
            if remaining == 0 {
                return Err(std::fmt::Error);
            }
            if value.len() <= remaining {
                self.0.push_str(value);
                Ok(())
            } else {
                let mut cut = remaining;
                while !value.is_char_boundary(cut) {
                    cut -= 1;
                }
                self.0.push_str(&value[..cut]);
                Err(std::fmt::Error)
            }
        }
    }

    let mut writer = BoundedWriter(String::new());
    if writer.write_fmt(args).is_err() {
        writer.0.push_str("… (truncated)");
    }
    writer.0
}

struct Encoder {
    output: Vec<u8>,
    state: SnapshotState,
}

impl Encoder {
    fn new(limits: JsSnapshotLimits) -> Self {
        Self {
            output: Vec::new(),
            state: SnapshotState::new(limits),
        }
    }

    fn value(&mut self, value: &JsValue, depth: usize, node_reserved: bool) -> Result<(), JsError> {
        if depth > self.state.limits.max_depth() {
            return Err(JsError::new(
                JsErrorKind::LimitExceeded,
                format!(
                    "value exceeds the maximum nesting depth of {}",
                    self.state.limits.max_depth()
                ),
            ));
        }
        if !node_reserved {
            self.state.reserve_nodes(1)?;
        }
        match value {
            JsValue::Undefined => self.output.push(0),
            JsValue::Null => self.output.push(1),
            JsValue::Bool(false) => self.output.push(2),
            JsValue::Bool(true) => self.output.push(3),
            JsValue::Number(value) => {
                self.output.push(4);
                self.output.extend_from_slice(&value.to_le_bytes());
            }
            JsValue::String(value) => {
                self.output.push(5);
                self.string(value)?;
            }
            JsValue::Array(values) => {
                let length = values.len();
                if length > self.state.limits.max_array_length() {
                    return Err(JsError::new(
                        JsErrorKind::LimitExceeded,
                        format!(
                            "js array length {length} exceeds the snapshot maximum of {}",
                            self.state.limits.max_array_length()
                        ),
                    ));
                }
                self.state.reserve_nodes(length)?;
                self.output.push(6);
                self.length(length)?;
                for value in values {
                    self.value(value, depth + 1, true)?;
                }
            }
            JsValue::Object(entries) => {
                let length = entries.len();
                if length > self.state.limits.max_object_properties() {
                    return Err(JsError::new(
                        JsErrorKind::LimitExceeded,
                        format!(
                            "js object property count {length} exceeds the snapshot maximum of {}",
                            self.state.limits.max_object_properties()
                        ),
                    ));
                }
                self.state.reserve_nodes(length)?;
                self.output.push(7);
                self.length(length)?;
                for (key, value) in entries {
                    self.string(key)?;
                    self.value(value, depth + 1, true)?;
                }
            }
        }
        Ok(())
    }

    fn length(&mut self, length: usize) -> Result<(), JsError> {
        let length = u32::try_from(length).map_err(|_error| {
            JsError::new(
                JsErrorKind::LimitExceeded,
                "value is too large for the wasm engine boundary",
            )
        })?;
        self.output.extend_from_slice(&length.to_le_bytes());
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), JsError> {
        self.state.reserve_string_bytes(value.len())?;
        self.length(value.len())?;
        self.output.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

fn encode_value(value: &JsValue, limits: JsSnapshotLimits) -> Result<Vec<u8>, JsError> {
    let mut encoder = Encoder::new(limits);
    encoder.value(value, 0, false)?;
    Ok(encoder.output)
}

fn encode_arguments_for_guest(
    arguments: &[JsValue],
    limits: JsSnapshotLimits,
) -> Result<Vec<u8>, JsError> {
    let mut encoder = Encoder::new(limits);
    let length = arguments.len();
    if length > limits.max_array_length() {
        return Err(JsError::new(
            JsErrorKind::LimitExceeded,
            format!(
                "js argument count {length} exceeds the snapshot maximum of {}",
                limits.max_array_length()
            ),
        ));
    }
    encoder.state.reserve_nodes(1)?;
    encoder.state.reserve_nodes(length)?;
    encoder.output.push(6);
    encoder.length(length)?;
    for argument in arguments {
        encoder.value(argument, 0, true)?;
    }
    Ok(encoder.output)
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    state: SnapshotState,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8], limits: JsSnapshotLimits) -> Self {
        Self {
            input,
            offset: 0,
            state: SnapshotState::new(limits),
        }
    }

    fn value(&mut self, depth: usize, node_reserved: bool) -> Result<JsValue, JsError> {
        if depth > self.state.limits.max_depth() {
            return Err(JsError::new(
                JsErrorKind::LimitExceeded,
                format!(
                    "js value snapshot exceeds the maximum depth of {}",
                    self.state.limits.max_depth()
                ),
            ));
        }
        if !node_reserved {
            self.state.reserve_nodes(1)?;
        }
        Ok(match self.byte()? {
            0 => JsValue::Undefined,
            1 => JsValue::Null,
            2 => JsValue::Bool(false),
            3 => JsValue::Bool(true),
            4 => {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(self.take(8)?);
                JsValue::Number(f64::from_le_bytes(bytes))
            }
            5 => JsValue::String(self.string()?.into()),
            6 => {
                let length = self.u32()? as usize;
                if length > self.state.limits.max_array_length() {
                    return Err(JsError::new(
                        JsErrorKind::LimitExceeded,
                        format!(
                            "js array length {length} exceeds the snapshot maximum of {}",
                            self.state.limits.max_array_length()
                        ),
                    ));
                }
                self.state.reserve_nodes(length)?;
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.value(depth + 1, true)?);
                }
                JsValue::Array(JsArray::from(values))
            }
            7 => {
                let length = self.u32()? as usize;
                if length > self.state.limits.max_object_properties() {
                    return Err(JsError::new(
                        JsErrorKind::LimitExceeded,
                        format!(
                            "js object property count {length} exceeds the snapshot maximum of {}",
                            self.state.limits.max_object_properties()
                        ),
                    ));
                }
                self.state.reserve_nodes(length)?;
                let mut entries = Vec::with_capacity(length);
                for _ in 0..length {
                    let key: JsStr = self.string()?.into();
                    let value = self.value(depth + 1, true)?;
                    entries.push((key, value));
                }
                JsValue::Object(JsObject::from(entries))
            }
            _ => return Err(JsError::conversion("unknown wasm engine value tag")),
        })
    }

    fn byte(&mut self) -> Result<u8, JsError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, JsError> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, JsError> {
        let length = self.u32()? as usize;
        self.state.reserve_string_bytes(length)?;
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_error| JsError::conversion("invalid utf-8 from wasm engine"))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], JsError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.input.len())
            .ok_or_else(|| JsError::conversion("truncated value from wasm engine"))?;
        let bytes = &self.input[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
}

struct SnapshotState {
    limits: JsSnapshotLimits,
    nodes: usize,
    string_bytes: usize,
}

impl SnapshotState {
    fn new(limits: JsSnapshotLimits) -> Self {
        Self {
            limits,
            nodes: 0,
            string_bytes: 0,
        }
    }

    fn reserve_nodes(&mut self, count: usize) -> Result<(), JsError> {
        let nodes = self.nodes.checked_add(count).ok_or_else(|| {
            JsError::new(
                JsErrorKind::LimitExceeded,
                "js value snapshot node count overflowed",
            )
        })?;
        if nodes > self.limits.max_nodes() {
            return Err(JsError::new(
                JsErrorKind::LimitExceeded,
                format!(
                    "js value snapshot exceeds the maximum of {} nodes and edges",
                    self.limits.max_nodes()
                ),
            ));
        }
        self.nodes = nodes;
        Ok(())
    }

    fn reserve_string_bytes(&mut self, count: usize) -> Result<(), JsError> {
        let bytes = self.string_bytes.checked_add(count).ok_or_else(|| {
            JsError::new(
                JsErrorKind::LimitExceeded,
                "js value snapshot string byte count overflowed",
            )
        })?;
        if bytes > self.limits.max_string_bytes() {
            return Err(JsError::new(
                JsErrorKind::LimitExceeded,
                format!(
                    "js value snapshot exceeds the maximum of {} string bytes",
                    self.limits.max_string_bytes()
                ),
            ));
        }
        self.string_bytes = bytes;
        Ok(())
    }
}

fn decode_value(input: &[u8], limits: JsSnapshotLimits) -> Result<JsValue, JsError> {
    let mut decoder = Decoder::new(input, limits);
    let value = decoder.value(0, false)?;
    if decoder.offset != input.len() {
        return Err(JsError::conversion(
            "trailing bytes after value from wasm engine",
        ));
    }
    Ok(value)
}

fn decode_arguments(input: &[u8], limits: JsSnapshotLimits) -> Result<Vec<JsValue>, JsError> {
    let value = decode_value(input, limits)?;
    match value {
        JsValue::Array(arguments) => Ok(arguments.to_vec()),
        _ => Err(JsError::conversion(
            "host function arguments are not an array",
        )),
    }
}
