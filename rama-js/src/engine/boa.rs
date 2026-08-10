//! The boa implementation of the engine boundary.
//!
//! This is the only file in this crate allowed to mention boa.

use boa_engine::object::{FunctionObjectBuilder, JsObject as BoaObject, ObjectInitializer};
use boa_engine::property::{Attribute, PropertyKey};
use boa_engine::string::JsStrVariant;
use boa_engine::{
    Context, Finalize, JsData, JsNativeError, JsNativeErrorKind, JsString, NativeFunction, Script,
    Source, Trace,
};

use super::{EngineConfig, GlobalEntry, NamespaceEntry};
use crate::error::{JsError, JsErrorKind};
use crate::func::RawHostFn;
use crate::host::{ErasedHostObject, HostCallback, HostClass, HostMemberKind, HostResourceCell};
use crate::snapshot::JsSnapshotLimits;
use crate::value::{JsArray, JsStr, JsValue};

/// Collect unreachable engine allocations before a fuzz iteration's
/// mid-process leak check runs.
#[cfg(fuzzing)]
pub(crate) fn force_collect_for_fuzzing() {
    boa_gc::force_collect();
}

/// A host→script call in flight, handed to the deadline call trampoline:
/// the resolved callable plus its already-converted arguments.
///
/// GC-traced, since it holds engine values.
type PendingCall = boa_engine::gc::Gc<boa_engine::gc::GcRefCell<Option<BoaObject>>>;

pub(crate) struct Engine {
    context: Context,
    snapshot_limits: JsSnapshotLimits,
    execution_time_limit: Option<std::time::Duration>,
    // dispatch scripts for deadline-bounded calls, compiled per arity
    call_trampolines: Option<Vec<(usize, Script)>>,
    call_payload: PendingCall,
    // interned once, then reused: every call would otherwise allocate an
    // engine string per payload property and per looked-up global
    call_keys: Vec<PropertyKey>,
    global_keys: Vec<(Box<str>, PropertyKey)>,
    poisoned: bool,
}

/// Instruction-cost units executed between two deadline checks: small
/// enough for sub-millisecond reaction, large enough to keep checks cheap.
const DEADLINE_CHECK_BUDGET: u32 = 4096;

/// The reserved global backing deadline-bounded calls: the engine can only
/// interrupt script evaluation, not function calls, so calls run through a
/// trampoline script which takes its payload from this host function.
///
/// Registered frozen (non-writable, non-configurable, non-enumerable) and
/// cleared before user code runs: scripts cannot tamper with it, and an
/// out-of-band call only yields an error, never host data.
const CALL_SLOT: &str = "__rama_js_call__";

/// The property naming the target on the payload object.
const CALL_TARGET_PROP: &str = "f";

/// Dispatch script for a deadline-bounded call of `arity` arguments.
///
/// Every construct here has to be one a script cannot reach: the payload
/// object is built host-side with a null prototype and own data properties,
/// so plain reads off it consult no prototype, accessor or iterator. Hence
/// no destructuring and no spread, and the target is called through a local
/// binding so `this` is the global object rather than the payload.
fn call_trampoline_src(arity: usize) -> String {
    let mut src = String::from(
        "(() => {\n    const p = __rama_js_call__();\n    const f = p.f;\n    return f(",
    );
    for index in 0..arity {
        if index > 0 {
            src.push_str(", ");
        }
        src.push_str("p.a");
        src.push_str(&index.to_string());
    }
    src.push_str(");\n})()");
    src
}

impl Engine {
    pub(crate) fn new(config: EngineConfig) -> Result<Self, JsError> {
        let mut context = Context::default();
        let snapshot_limits = config.snapshot_limits;

        context.strict(config.strict);
        // `None` means unlimited: overwrite boa's own built-in defaults.
        let limits = context.runtime_limits_mut();
        limits.set_recursion_limit(config.recursion_limit.unwrap_or(usize::MAX));
        limits.set_loop_iteration_limit(config.loop_iteration_limit.unwrap_or(u64::MAX));
        limits.set_stack_size_limit(config.stack_size_limit.unwrap_or(usize::MAX));

        if config.execution_time_limit.is_some()
            && config.globals.iter().any(|(name, _)| name == CALL_SLOT)
        {
            return Err(setup_err(
                CALL_SLOT,
                "this global name is reserved for execution time limited calls",
            ));
        }

        for (name, entry) in config.globals {
            match entry {
                GlobalEntry::Value(value) => {
                    let value = value_to_boa(&value, &mut context, snapshot_limits)
                        .map_err(|err| setup_err(&name, err.message()))?;
                    context
                        .register_global_property(js_str_to_boa(&name), value, Attribute::all())
                        .map_err(|err| setup_err(&name, &err.to_string()))?;
                }
                GlobalEntry::Fn(func) => {
                    let arity = func.arity().unwrap_or_default();
                    let native = native_fn(name.clone(), func, snapshot_limits);
                    context
                        .register_global_callable(js_str_to_boa(&name), arity, native)
                        .map_err(|err| setup_err(&name, &err.to_string()))?;
                }
                GlobalEntry::Namespace(entries) => {
                    let object = BoaObject::with_object_proto(context.intrinsics());
                    for (prop, entry) in entries {
                        let value = match entry {
                            NamespaceEntry::Value(value) => {
                                value_to_boa(&value, &mut context, snapshot_limits)
                                    .map_err(|err| setup_err(&name, err.message()))?
                            }
                            NamespaceEntry::Fn(func) => {
                                let arity = func.arity().unwrap_or_default();
                                let native = native_fn(prop.clone(), func, snapshot_limits);
                                FunctionObjectBuilder::new(context.realm(), native)
                                    .name(js_str_to_boa(&prop))
                                    .length(arity)
                                    .build()
                                    .into()
                            }
                        };
                        object
                            .create_data_property_or_throw(
                                js_str_to_boa(&prop),
                                value,
                                &mut context,
                            )
                            .map_err(|err| setup_err(&name, &err.to_string()))?;
                    }
                    context
                        .register_global_property(js_str_to_boa(&name), object, Attribute::all())
                        .map_err(|err| setup_err(&name, &err.to_string()))?;
                }
            }
        }

        let call_payload: PendingCall =
            boa_engine::gc::Gc::new(boa_engine::gc::GcRefCell::new(None));
        let call_trampolines = if config.execution_time_limit.is_some() {
            let take_call = NativeFunction::from_copy_closure_with_captures(
                |_this, _args, payload: &PendingCall, _context| {
                    let Some(payload) = payload.borrow_mut().take() else {
                        return Err(JsNativeError::error()
                            .with_message("no pending host call")
                            .into());
                    };
                    Ok(payload.into())
                },
                call_payload.clone(),
            );
            let func = FunctionObjectBuilder::new(context.realm(), take_call)
                .name(JsString::from(CALL_SLOT))
                .length(0)
                .build();
            // frozen: scripts can neither replace nor delete the slot
            context
                .register_global_property(JsString::from(CALL_SLOT), func, Attribute::empty())
                .map_err(|err| setup_err(CALL_SLOT, &err.to_string()))?;
            Some(Vec::new())
        } else {
            None
        };

        Ok(Self {
            context,
            snapshot_limits,
            execution_time_limit: config.execution_time_limit,
            call_trampolines,
            call_payload,
            call_keys: vec![PropertyKey::from(JsString::from(CALL_TARGET_PROP))],
            global_keys: Vec::new(),
            poisoned: false,
        })
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn ensure_not_poisoned(&self) -> Result<(), JsError> {
        if self.poisoned {
            return Err(JsError::new(
                JsErrorKind::Setup,
                "js runtime is poisoned: a previous evaluation exceeded the execution time limit",
            ));
        }
        Ok(())
    }

    pub(crate) fn eval(&mut self, src: &str) -> Result<JsValue, JsError> {
        let value = self.evaluate(src)?;
        value_from_boa(&value, &mut self.context, self.snapshot_limits)
    }

    pub(crate) fn exec(&mut self, src: &str) -> Result<(), JsError> {
        self.evaluate(src).map(drop)
    }

    fn evaluate(&mut self, src: &str) -> Result<boa_engine::JsValue, JsError> {
        self.ensure_not_poisoned()?;
        let script = match Script::parse(Source::from_bytes(src), None, &mut self.context) {
            Ok(script) => script,
            Err(err) => {
                return Err(parse_error_from_boa(
                    &err,
                    &mut self.context,
                    self.snapshot_limits,
                ));
            }
        };
        match self.execution_time_limit {
            Some(limit) => self.run_script_with_deadline(&script, limit),
            None => match script.evaluate(&mut self.context) {
                Ok(value) => Ok(value),
                Err(err) => Err(error_from_boa(
                    &err,
                    &mut self.context,
                    self.snapshot_limits,
                )),
            },
        }
    }

    /// Run a script, aborting once the wall-clock limit passes.
    ///
    /// An abort drops the evaluation mid-execution, leaving the engine
    /// in an unknown state: the engine is poisoned and unusable after.
    fn run_script_with_deadline(
        &mut self,
        script: &Script,
        limit: std::time::Duration,
    ) -> Result<boa_engine::JsValue, JsError> {
        let deadline = std::time::Instant::now() + limit;
        let result = drive_with_deadline(
            script.evaluate_async_with_budget(&mut self.context, DEADLINE_CHECK_BUDGET),
            deadline,
        );
        match result {
            Some(Ok(value)) => Ok(value),
            Some(Err(err)) => Err(error_from_boa(
                &err,
                &mut self.context,
                self.snapshot_limits,
            )),
            None => {
                self.poisoned = true;
                Err(JsError::new(
                    JsErrorKind::LimitExceeded,
                    format!("execution time limit of {limit:?} exceeded; the runtime is poisoned"),
                ))
            }
        }
    }

    /// The global callable `name` refers to, resolved without invoking
    /// anything.
    ///
    /// A `[[Get]]` would run a script-installed accessor, which no deadline
    /// can interrupt: only own data properties are honoured, so an accessor
    /// reads as absent rather than as an invitation to run script code.
    fn resolve_global_callable(&mut self, name: &str) -> Result<BoaObject, JsError> {
        let key = self.global_key(name);
        let global = self.context.global_object();
        let descriptor = global.borrow().properties().get(&key);

        descriptor
            .filter(boa_engine::property::PropertyDescriptor::is_data_descriptor)
            .and_then(|descriptor| descriptor.value().cloned())
            .as_ref()
            .and_then(boa_engine::JsValue::as_object)
            .filter(BoaObject::is_callable)
            .ok_or_else(|| {
                JsError::new(
                    JsErrorKind::NotFound,
                    format!("global function `{name}` not found"),
                )
            })
    }

    /// Call through a pre-compiled trampoline so the invocation runs under
    /// the execution deadline.
    fn call_with_deadline(
        &mut self,
        name: &str,
        args: &[JsValue],
        limit: std::time::Duration,
    ) -> Result<JsValue, JsError> {
        if self.call_trampolines.is_none() {
            return Err(JsError::new(
                JsErrorKind::Setup,
                "js call trampoline missing",
            ));
        }

        let target = self.resolve_global_callable(name)?;
        let args = args
            .iter()
            .map(|arg| value_to_boa(arg, &mut self.context, self.snapshot_limits))
            .collect::<Result<Vec<_>, _>>()?;
        let trampoline = self.trampoline_for(args.len())?;
        let payload = self.build_call_payload(target, args)?;

        *self.call_payload.borrow_mut() = Some(payload);
        let result = self.run_script_with_deadline(&trampoline, limit);
        // drop a payload the trampoline never got to take
        *self.call_payload.borrow_mut() = None;

        let value = result?;
        value_from_boa(&value, &mut self.context, self.snapshot_limits)
    }

    /// The interned key for a global name, cached across lookups.
    fn global_key(&mut self, name: &str) -> PropertyKey {
        if let Some((_, key)) = self
            .global_keys
            .iter()
            .find(|(cached, _)| cached.as_ref() == name)
        {
            return key.clone();
        }

        let key = PropertyKey::from(JsString::from(name));
        self.global_keys.push((name.into(), key.clone()));
        key
    }

    /// The interned `a{index}` payload keys, up to the given arity.
    fn arg_key(&mut self, index: usize) -> PropertyKey {
        while self.call_keys.len() <= index + 1 {
            let next = self.call_keys.len() - 1;
            self.call_keys.push(PropertyKey::from(JsString::from(
                format!("a{next}").as_str(),
            )));
        }
        self.call_keys[index + 1].clone()
    }

    /// The trampoline for this arity, compiled on first use.
    fn trampoline_for(&mut self, arity: usize) -> Result<Script, JsError> {
        let trampolines = self
            .call_trampolines
            .as_ref()
            .ok_or_else(|| JsError::new(JsErrorKind::Setup, "js call trampoline missing"))?;
        if let Some((_, script)) = trampolines.iter().find(|(cached, _)| *cached == arity) {
            return Ok(script.clone());
        }

        let script = Script::parse(
            Source::from_bytes(&call_trampoline_src(arity)),
            None,
            &mut self.context,
        )
        .map_err(|err| setup_err(CALL_SLOT, &err.to_string()))?;
        if let Some(trampolines) = self.call_trampolines.as_mut() {
            trampolines.push((arity, script.clone()));
        }
        Ok(script)
    }

    /// The payload the trampoline reads: a null-prototype object carrying
    /// the target and its arguments as own data properties, so no script
    /// can interpose on the reads.
    fn build_call_payload(
        &mut self,
        target: BoaObject,
        args: Vec<boa_engine::JsValue>,
    ) -> Result<BoaObject, JsError> {
        let payload = BoaObject::with_null_proto();
        let target_key = self.call_keys[0].clone();
        payload
            .create_data_property_or_throw(target_key, target, &mut self.context)
            .map_err(|err| setup_err(CALL_SLOT, &err.to_string()))?;
        for (index, arg) in args.into_iter().enumerate() {
            let key = self.arg_key(index);
            payload
                .create_data_property_or_throw(key, arg, &mut self.context)
                .map_err(|err| setup_err(CALL_SLOT, &err.to_string()))?;
        }
        Ok(payload)
    }

    pub(crate) fn call(&mut self, name: &str, args: &[JsValue]) -> Result<JsValue, JsError> {
        self.ensure_not_poisoned()?;
        if let Some(limit) = self.execution_time_limit {
            return self.call_with_deadline(name, args, limit);
        }

        let func = self.resolve_global_callable(name)?;
        let args = args
            .iter()
            .map(|arg| value_to_boa(arg, &mut self.context, self.snapshot_limits))
            .collect::<Result<Vec<_>, _>>()?;

        match func.call(&boa_engine::JsValue::undefined(), &args, &mut self.context) {
            Ok(value) => value_from_boa(&value, &mut self.context, self.snapshot_limits),
            Err(err) => Err(error_from_boa(
                &err,
                &mut self.context,
                self.snapshot_limits,
            )),
        }
    }

    pub(crate) fn has_global_fn(&mut self, name: &str) -> bool {
        if self.poisoned {
            return false;
        }
        self.resolve_global_callable(name).is_ok()
    }

    pub(crate) fn set_host_global(
        &mut self,
        name: &JsStr,
        host: ErasedHostObject,
    ) -> Result<(), JsError> {
        self.ensure_not_poisoned()?;
        validate_host_class(name, &host.class)?;

        let mut prototype = ObjectInitializer::new(&mut self.context);
        for member in host
            .class
            .members
            .iter()
            .filter(|member| member.kind == HostMemberKind::Method)
        {
            prototype.function(
                native_host_fn(
                    member.name.clone(),
                    member.callback.clone(),
                    host.class.clone(),
                    self.snapshot_limits,
                ),
                js_str_to_boa(&member.name),
                member.callback.arity().unwrap_or_default(),
            );
        }

        for getter in host
            .class
            .members
            .iter()
            .filter(|member| member.kind == HostMemberKind::Getter)
        {
            let get = FunctionObjectBuilder::new(
                prototype.context().realm(),
                native_host_fn(
                    getter.name.clone(),
                    getter.callback.clone(),
                    host.class.clone(),
                    self.snapshot_limits,
                ),
            )
            .name(js_str_to_boa(&getter.name))
            .length(0)
            .build();
            let set = host
                .class
                .members
                .iter()
                .find(|member| member.kind == HostMemberKind::Setter && member.name == getter.name)
                .map(|setter| {
                    FunctionObjectBuilder::new(
                        prototype.context().realm(),
                        native_host_fn(
                            setter.name.clone(),
                            setter.callback.clone(),
                            host.class.clone(),
                            self.snapshot_limits,
                        ),
                    )
                    .name(js_str_to_boa(&setter.name))
                    .length(1)
                    .build()
                });
            prototype.accessor(
                js_str_to_boa(&getter.name),
                Some(get),
                set,
                Attribute::all(),
            );
        }

        for setter in host.class.members.iter().filter(|member| {
            member.kind == HostMemberKind::Setter
                && !host.class.members.iter().any(|candidate| {
                    candidate.kind == HostMemberKind::Getter && candidate.name == member.name
                })
        }) {
            let set = FunctionObjectBuilder::new(
                prototype.context().realm(),
                native_host_fn(
                    setter.name.clone(),
                    setter.callback.clone(),
                    host.class.clone(),
                    self.snapshot_limits,
                ),
            )
            .name(js_str_to_boa(&setter.name))
            .length(1)
            .build();
            prototype.accessor(
                js_str_to_boa(&setter.name),
                None,
                Some(set),
                Attribute::all(),
            );
        }

        let prototype = prototype.build();
        let object = ObjectInitializer::with_native_data_and_proto(
            BoaHostObject {
                resource: host.resource,
                class: host.class,
            },
            prototype,
            &mut self.context,
        )
        .build();
        self.context
            .register_global_property(js_str_to_boa(name), object, Attribute::all())
            .map_err(|err| setup_err(name, &err.to_string()))
    }
}

/// Drive a budgeted evaluation on the current thread, aborting it
/// (by dropping the future mid-execution) once the deadline passes.
fn drive_with_deadline<F: std::future::Future>(
    future: F,
    deadline: std::time::Instant,
) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(output) => return Some(output),
            std::task::Poll::Pending if std::time::Instant::now() >= deadline => return None,
            std::task::Poll::Pending => {}
        }
    }
}

#[derive(Trace, Finalize, JsData)]
struct BoaHostObject {
    // SAFETY: both fields are engine-agnostic Rust storage. Their types cannot
    // contain Boa GC handles, so there is nothing for the collector to trace.
    #[unsafe_ignore_trace]
    resource: std::sync::Arc<HostResourceCell>,
    #[unsafe_ignore_trace]
    class: std::sync::Arc<HostClass>,
}

fn validate_host_class(name: &JsStr, class: &HostClass) -> Result<(), JsError> {
    for (index, member) in class.members.iter().enumerate() {
        let has_conflict = class.members[..index]
            .iter()
            .filter(|previous| previous.name == member.name)
            .any(|previous| {
                !matches!(
                    (previous.kind, member.kind),
                    (HostMemberKind::Getter, HostMemberKind::Setter)
                        | (HostMemberKind::Setter, HostMemberKind::Getter)
                )
            });
        if has_conflict {
            return Err(setup_err(
                name,
                &format!("duplicate host object member `{}`", member.name),
            ));
        }
    }
    Ok(())
}

fn native_host_fn(
    name: JsStr,
    callback: HostCallback,
    class: std::sync::Arc<HostClass>,
    snapshot_limits: JsSnapshotLimits,
) -> NativeFunction {
    // SAFETY: all captured fields are engine-independent rust data and do not
    // contain values managed by Boa's garbage collector.
    unsafe {
        NativeFunction::from_closure(move |this, args, context| {
            let object = this.as_object().ok_or_else(|| {
                JsNativeError::typ().with_message(format!("{name}: invalid host object receiver"))
            })?;
            let resource = {
                let host = object.downcast_ref::<BoaHostObject>().ok_or_else(|| {
                    JsNativeError::typ()
                        .with_message(format!("{name}: invalid host object receiver"))
                })?;
                if !std::sync::Arc::ptr_eq(&class, &host.class) {
                    return Err(JsNativeError::typ()
                        .with_message(format!("{name}: incompatible host object receiver"))
                        .into());
                }
                host.resource.clone()
            };

            let arg_count = callback.arity().unwrap_or(args.len()).min(args.len());
            let mut host_args = Vec::with_capacity(arg_count);
            let mut snapshot = SnapshotState::new(snapshot_limits);
            for arg in args.iter().take(arg_count) {
                let arg = snapshot_value_from_boa(arg, context, &mut snapshot, 0, false)
                    .map_err(|err| host_error_to_boa(&name, &err))?;
                host_args.push(arg);
            }
            match resource
                .call(&callback, host_args)
                .and_then(|value| value_to_boa(&value, context, snapshot_limits))
            {
                Ok(value) => Ok(value),
                Err(err) => Err(host_error_to_boa(&name, &err)),
            }
        })
    }
}

fn setup_err(name: &str, msg: &str) -> JsError {
    JsError::new(
        JsErrorKind::Setup,
        format!("failed to register global `{name}`: {msg}"),
    )
}

fn js_str_to_boa(s: &JsStr) -> JsString {
    JsString::from(s.as_str())
}

/// Wrap a raw host function into a boa native function which
/// materializes arguments, invokes the host function, and converts
/// its output (or error) back into the engine.
fn native_fn(name: JsStr, func: RawHostFn, snapshot_limits: JsSnapshotLimits) -> NativeFunction {
    // SAFETY: the closure only captures `name` (a plain string) and
    // `func` (a plain shared rust closure); neither contains any engine
    // GC-traced values, which is the only from_closure requirement.
    unsafe {
        NativeFunction::from_closure(move |_this, args, context| {
            let arg_count = func.arity().unwrap_or(args.len()).min(args.len());
            let mut host_args = Vec::with_capacity(arg_count);
            let mut snapshot = SnapshotState::new(snapshot_limits);
            for arg in args.iter().take(arg_count) {
                let arg = match snapshot_value_from_boa(arg, context, &mut snapshot, 0, false) {
                    Ok(arg) => arg,
                    Err(err) if func.lenient_args() => {
                        JsValue::String(format!("<{}>", err.message()).into())
                    }
                    Err(err) => return Err(host_error_to_boa(&name, &err)),
                };
                host_args.push(arg);
            }
            match func
                .call(host_args)
                .and_then(|value| value_to_boa(&value, context, snapshot_limits))
            {
                Ok(value) => Ok(value),
                Err(err) => Err(host_error_to_boa(&name, &err)),
            }
        })
    }
}

/// Throw a host-side error into the running script.
fn host_error_to_boa(name: &JsStr, err: &JsError) -> boa_engine::JsError {
    let message = format!("{name}: {}", err.message());
    match err.kind() {
        JsErrorKind::Conversion => JsNativeError::typ().with_message(message).into(),
        JsErrorKind::LimitExceeded => JsNativeError::runtime_limit().with_message(message).into(),
        _ => JsNativeError::error().with_message(message).into(),
    }
}

/// Classify a failure produced while parsing source text.
fn parse_error_from_boa(
    err: &boa_engine::JsError,
    context: &mut Context,
    snapshot_limits: JsSnapshotLimits,
) -> JsError {
    if let Ok(native) = err.try_native(context)
        && native.kind == JsNativeErrorKind::Syntax
    {
        return JsError::new(JsErrorKind::Parse, native.to_string());
    }
    error_from_boa(err, context, snapshot_limits)
}

/// Classify an engine error into an engine-agnostic [`JsError`].
fn error_from_boa(
    err: &boa_engine::JsError,
    context: &mut Context,
    snapshot_limits: JsSnapshotLimits,
) -> JsError {
    if let Ok(native) = err.try_native(context) {
        let kind = match native.kind {
            JsNativeErrorKind::RuntimeLimit => JsErrorKind::LimitExceeded,
            _ => JsErrorKind::Throw,
        };
        return JsError::new(kind, bounded_format(format_args!("{native}")));
    }

    let thrown = err.to_opaque(context);
    match value_from_boa(&thrown, context, snapshot_limits) {
        Ok(value) => JsError::new(
            JsErrorKind::Throw,
            bounded_format(format_args!("script threw: {value}")),
        )
        .with_thrown(value),
        // never Debug-print an engine value: that writes boa's internal
        // type name and the object's address into operator-visible text
        Err(err) => JsError::new(
            JsErrorKind::Throw,
            bounded_format(format_args!(
                "script threw a value that could not be materialized: {}",
                err.message()
            )),
        ),
    }
}

/// Thrown values can be arbitrarily large; error messages must not bypass
/// the snapshot budget, so formatting stops at a bounded prefix.
const MAX_ERROR_MESSAGE_BYTES: usize = rama_utils::octets::kib(4);

fn bounded_format(args: std::fmt::Arguments<'_>) -> String {
    use std::fmt::Write;

    struct BoundedWriter(String);

    impl Write for BoundedWriter {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            let remaining = MAX_ERROR_MESSAGE_BYTES.saturating_sub(self.0.len());
            if remaining == 0 {
                return Err(std::fmt::Error);
            }
            if s.len() <= remaining {
                self.0.push_str(s);
                Ok(())
            } else {
                let mut cut = remaining;
                while !s.is_char_boundary(cut) {
                    cut -= 1;
                }
                self.0.push_str(&s[..cut]);
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

struct SnapshotState {
    limits: JsSnapshotLimits,
    nodes: usize,
    string_bytes: usize,
    active: Vec<BoaObject>,
}

impl SnapshotState {
    fn new(limits: JsSnapshotLimits) -> Self {
        Self {
            limits,
            nodes: 0,
            string_bytes: 0,
            active: Vec::new(),
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

/// Materialize an engine value into an engine-agnostic [`JsValue`] snapshot.
fn value_from_boa(
    value: &boa_engine::JsValue,
    context: &mut Context,
    limits: JsSnapshotLimits,
) -> Result<JsValue, JsError> {
    snapshot_value_from_boa(value, context, &mut SnapshotState::new(limits), 0, false)
}

fn snapshot_value_from_boa(
    value: &boa_engine::JsValue,
    context: &mut Context,
    state: &mut SnapshotState,
    depth: usize,
    node_reserved: bool,
) -> Result<JsValue, JsError> {
    use boa_engine::value::JsVariant;

    if depth > state.limits.max_depth() {
        return Err(JsError::new(
            JsErrorKind::LimitExceeded,
            format!(
                "js value snapshot exceeds the maximum depth of {}",
                state.limits.max_depth()
            ),
        ));
    }
    if !node_reserved {
        state.reserve_nodes(1)?;
    }

    Ok(match value.variant() {
        JsVariant::Undefined => JsValue::Undefined,
        JsVariant::Null => JsValue::Null,
        JsVariant::Boolean(b) => JsValue::Bool(b),
        JsVariant::Integer32(n) => JsValue::Number(f64::from(n)),
        JsVariant::Float64(n) => JsValue::Number(n),
        JsVariant::String(s) => {
            state.reserve_string_bytes(boa_string_public_len(&s))?;
            JsValue::String(boa_string_to_public(&s))
        }
        JsVariant::BigInt(n) => {
            return Err(JsError::conversion(bounded_format(format_args!(
                "bigint values cannot cross the js boundary (got {n})"
            ))));
        }
        JsVariant::Symbol(s) => {
            return Err(JsError::conversion(bounded_format(format_args!(
                "symbol values cannot cross the js boundary (got {s})"
            ))));
        }
        JsVariant::Object(obj) => {
            if obj.downcast_ref::<BoaHostObject>().is_some() {
                return Err(JsError::conversion(
                    "native host objects cannot cross the js value boundary",
                ));
            }
            if obj.is_callable() {
                return Err(JsError::conversion(
                    "function values cannot cross the js boundary",
                ));
            }

            if state
                .active
                .iter()
                .any(|active| BoaObject::equals(active, &obj))
            {
                return Err(JsError::conversion(
                    "cyclic object graph cannot cross the js boundary",
                ));
            }
            state.active.push(obj.clone());
            let snapshot = (|| {
                if obj.is_array() {
                    let length = obj
                        .get(JsString::from("length"), context)
                        .map_err(|err| snapshot_err(&err, context))?
                        .as_number()
                        .ok_or_else(|| JsError::conversion("array length is not a number"))?;
                    if !length.is_finite()
                        || length < 0.0
                        || length.fract() != 0.0
                        || length > f64::from(u32::MAX)
                    {
                        return Err(JsError::conversion(format!(
                            "invalid array length while snapshotting: {length}"
                        )));
                    }
                    let length = length as usize;
                    if length > state.limits.max_array_length() {
                        return Err(JsError::new(
                            JsErrorKind::LimitExceeded,
                            format!(
                                "js array length {length} exceeds the snapshot maximum of {}",
                                state.limits.max_array_length()
                            ),
                        ));
                    }
                    state.reserve_nodes(length)?;
                    let mut values = Vec::with_capacity(length);
                    for index in 0..length {
                        let element = obj
                            .get(index as u64, context)
                            .map_err(|err| snapshot_err(&err, context))?;
                        values.push(snapshot_value_from_boa(
                            &element,
                            context,
                            state,
                            depth + 1,
                            true,
                        )?);
                    }
                    Ok(JsValue::Array(JsArray::from(values)))
                } else {
                    let keys = obj
                        .own_property_keys(context)
                        .map_err(|err| snapshot_err(&err, context))?;
                    if keys.len() > state.limits.max_object_properties() {
                        return Err(JsError::new(
                            JsErrorKind::LimitExceeded,
                            format!(
                                "js object property count {} exceeds the snapshot maximum of {}",
                                keys.len(),
                                state.limits.max_object_properties()
                            ),
                        ));
                    }
                    state.reserve_nodes(keys.len())?;
                    let mut entries = Vec::with_capacity(keys.len());
                    for key in keys {
                        let name = match &key {
                            PropertyKey::String(s) => {
                                state.reserve_string_bytes(boa_string_public_len(s))?;
                                boa_string_to_public(s)
                            }
                            PropertyKey::Index(index) => {
                                let name = index.get().to_string();
                                state.reserve_string_bytes(name.len())?;
                                JsStr::from(name)
                            }
                            PropertyKey::Symbol(_) => continue,
                        };
                        let prop = obj
                            .get(key, context)
                            .map_err(|err| snapshot_err(&err, context))?;
                        // functions are skipped, mirroring JSON.stringify semantics
                        if prop.is_callable() {
                            continue;
                        }
                        entries.push((
                            name,
                            snapshot_value_from_boa(&prop, context, state, depth + 1, true)?,
                        ));
                    }
                    Ok(JsValue::Object(entries.into_iter().collect()))
                }
            })();
            state.active.pop();
            snapshot?
        }
    })
}

fn snapshot_err(err: &boa_engine::JsError, context: &mut Context) -> JsError {
    if let Ok(native) = err.try_native(context) {
        let kind = if native.kind == JsNativeErrorKind::RuntimeLimit {
            JsErrorKind::LimitExceeded
        } else {
            JsErrorKind::Throw
        };
        return JsError::new(
            kind,
            bounded_format(format_args!("failed to snapshot js value: {native}")),
        );
    }

    JsError::new(
        JsErrorKind::Throw,
        "failed to snapshot js value; script threw a value that could not be materialized",
    )
}

/// Copy an engine string out in a single transcoding pass; unpaired
/// surrogates are replaced (lossy), as a `Send` utf-8 string cannot hold them.
fn boa_string_to_public(s: &JsString) -> JsStr {
    match s.as_str().variant() {
        // non-ascii latin1 bytes are NOT utf-8, even when they happen to parse as it
        JsStrVariant::Latin1(bytes) => match std::str::from_utf8(bytes) {
            Ok(ascii) if ascii.is_ascii() => JsStr::new(ascii),
            _ => bytes
                .iter()
                .map(|&b| char::from(b))
                .collect::<String>()
                .into(),
        },
        JsStrVariant::Utf16(units) => String::from_utf16_lossy(units).into(),
    }
}

fn boa_string_public_len(s: &JsString) -> usize {
    match s.as_str().variant() {
        JsStrVariant::Latin1(bytes) => bytes
            .iter()
            .map(|&byte| if byte.is_ascii() { 1 } else { 2 })
            .sum(),
        JsStrVariant::Utf16(units) => char::decode_utf16(units.iter().copied())
            .map(|result| result.unwrap_or(char::REPLACEMENT_CHARACTER).len_utf8())
            .sum(),
    }
}

/// Convert an engine-agnostic [`JsValue`] into an engine value.
///
/// Depth-capped by the snapshot limits, so a host-constructed value of
/// absurd depth errors instead of overflowing the stack: whatever the
/// engine can copy out, it can also feed back in.
fn value_to_boa(
    value: &JsValue,
    context: &mut Context,
    limits: JsSnapshotLimits,
) -> Result<boa_engine::JsValue, JsError> {
    value_to_boa_at(value, context, limits.max_depth(), 0)
}

fn value_to_boa_at(
    value: &JsValue,
    context: &mut Context,
    max_depth: usize,
    depth: usize,
) -> Result<boa_engine::JsValue, JsError> {
    if depth > max_depth {
        return Err(JsError::new(
            JsErrorKind::LimitExceeded,
            format!("value exceeds the maximum nesting depth of {max_depth}"),
        ));
    }
    Ok(match value {
        JsValue::Undefined => boa_engine::JsValue::undefined(),
        JsValue::Null => boa_engine::JsValue::null(),
        JsValue::Bool(b) => boa_engine::JsValue::from(*b),
        JsValue::Number(n) => boa_engine::JsValue::from(*n),
        JsValue::String(s) => boa_engine::JsValue::from(js_str_to_boa(s)),
        JsValue::Array(arr) => {
            let elements = arr
                .iter()
                .map(|element| value_to_boa_at(element, context, max_depth, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            boa_engine::object::builtins::JsArray::from_iter(elements, context).into()
        }
        JsValue::Object(obj) => {
            let object = BoaObject::with_object_proto(context.intrinsics());
            for (key, value) in obj {
                let value = value_to_boa_at(value, context, max_depth, depth + 1)?;
                // infallible: fresh plain object + JsObject keys are unique
                let result =
                    object.create_data_property_or_throw(js_str_to_boa(key), value, context);
                debug_assert!(result.is_ok());
            }
            object.into()
        }
    })
}
