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

pub(crate) struct Engine {
    context: Context,
    snapshot_limits: JsSnapshotLimits,
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

        Ok(Self {
            context,
            snapshot_limits,
        })
    }

    pub(crate) fn eval(&mut self, src: &str) -> Result<JsValue, JsError> {
        let value = self.evaluate(src)?;
        value_from_boa(&value, &mut self.context, self.snapshot_limits)
    }

    pub(crate) fn exec(&mut self, src: &str) -> Result<(), JsError> {
        self.evaluate(src).map(drop)
    }

    fn evaluate(&mut self, src: &str) -> Result<boa_engine::JsValue, JsError> {
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
        match script.evaluate(&mut self.context) {
            Ok(value) => Ok(value),
            Err(err) => Err(error_from_boa(
                &err,
                &mut self.context,
                self.snapshot_limits,
            )),
        }
    }

    pub(crate) fn call(&mut self, name: &str, args: &[JsValue]) -> Result<JsValue, JsError> {
        let global = self.context.global_object();
        let func = global
            .get(JsString::from(name), &mut self.context)
            .map_err(|err| error_from_boa(&err, &mut self.context, self.snapshot_limits))?;
        let Some(func) = func.as_object().filter(|obj| obj.is_callable()) else {
            return Err(JsError::new(
                JsErrorKind::NotFound,
                format!("global function `{name}` not found"),
            ));
        };

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
        let global = self.context.global_object();
        global
            .get(JsString::from(name), &mut self.context)
            .ok()
            .and_then(|value| value.as_object())
            .is_some_and(|obj| obj.is_callable())
    }

    pub(crate) fn set_host_global(
        &mut self,
        name: &JsStr,
        host: ErasedHostObject,
    ) -> Result<(), JsError> {
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
        Err(_) => JsError::new(
            JsErrorKind::Throw,
            bounded_format(format_args!("script threw: {thrown:?}")),
        ),
    }
}

/// Thrown values can be arbitrarily large; error messages must not bypass
/// the snapshot budget, so formatting stops at a bounded prefix.
const MAX_ERROR_MESSAGE_BYTES: usize = 4 * 1024;

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

    let thrown = err.to_opaque(context);
    JsError::new(
        JsErrorKind::Throw,
        bounded_format(format_args!(
            "failed to snapshot js value; script threw: {thrown:?}"
        )),
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
