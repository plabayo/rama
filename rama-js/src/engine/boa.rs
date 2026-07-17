//! The boa implementation of the engine boundary.
//!
//! This is the only file in this crate allowed to mention boa.

use boa_engine::object::{FunctionObjectBuilder, JsObject as BoaObject};
use boa_engine::property::{Attribute, PropertyKey};
use boa_engine::string::JsStrVariant;
use boa_engine::{Context, JsNativeError, JsNativeErrorKind, JsString, NativeFunction, Source};

use super::{EngineConfig, GlobalEntry, NamespaceEntry};
use crate::error::{JsError, JsErrorKind};
use crate::func::RawHostFn;
use crate::value::{JsArray, JsStr, JsValue};

/// Maximum nesting depth when snapshotting values out of the engine,
/// which also bounds cyclic object graphs.
const MAX_SNAPSHOT_DEPTH: usize = 64;

pub(crate) struct Engine {
    context: Context,
}

impl Engine {
    pub(crate) fn new(config: EngineConfig) -> Result<Self, JsError> {
        let mut context = Context::default();

        context.strict(config.strict);
        if let Some(limit) = config.recursion_limit {
            context.runtime_limits_mut().set_recursion_limit(limit);
        }
        if let Some(limit) = config.loop_iteration_limit {
            context.runtime_limits_mut().set_loop_iteration_limit(limit);
        }
        if let Some(limit) = config.stack_size_limit {
            context.runtime_limits_mut().set_stack_size_limit(limit);
        }

        for (name, entry) in config.globals {
            match entry {
                GlobalEntry::Value(value) => {
                    let value = value_to_boa(&value, &mut context);
                    context
                        .register_global_property(js_str_to_boa(&name), value, Attribute::all())
                        .map_err(|err| setup_err(&name, &err.to_string()))?;
                }
                GlobalEntry::Fn(func) => {
                    let native = native_fn(name.clone(), func);
                    context
                        .register_global_callable(js_str_to_boa(&name), 0, native)
                        .map_err(|err| setup_err(&name, &err.to_string()))?;
                }
                GlobalEntry::Namespace(entries) => {
                    let object = BoaObject::with_object_proto(context.intrinsics());
                    for (prop, entry) in entries {
                        let value = match entry {
                            NamespaceEntry::Value(value) => value_to_boa(&value, &mut context),
                            NamespaceEntry::Fn(func) => {
                                let native = native_fn(prop.clone(), func);
                                FunctionObjectBuilder::new(context.realm(), native)
                                    .name(js_str_to_boa(&prop))
                                    .build()
                                    .into()
                            }
                        };
                        object
                            .set(js_str_to_boa(&prop), value, false, &mut context)
                            .map_err(|err| setup_err(&name, &err.to_string()))?;
                    }
                    context
                        .register_global_property(js_str_to_boa(&name), object, Attribute::all())
                        .map_err(|err| setup_err(&name, &err.to_string()))?;
                }
            }
        }

        Ok(Self { context })
    }

    pub(crate) fn eval(&mut self, src: &str) -> Result<JsValue, JsError> {
        match self.context.eval(Source::from_bytes(src)) {
            Ok(value) => value_from_boa(&value, &mut self.context, 0),
            Err(err) => Err(error_from_boa(&err, &mut self.context)),
        }
    }

    pub(crate) fn call(&mut self, name: &str, args: &[JsValue]) -> Result<JsValue, JsError> {
        let global = self.context.global_object();
        let func = global
            .get(JsString::from(name), &mut self.context)
            .map_err(|err| error_from_boa(&err, &mut self.context))?;
        let Some(func) = func.as_object().filter(|obj| obj.is_callable()) else {
            return Err(JsError::new(
                JsErrorKind::NotFound,
                format!("global function `{name}` not found"),
            ));
        };

        let args: Vec<_> = args
            .iter()
            .map(|arg| value_to_boa(arg, &mut self.context))
            .collect();

        match func.call(&boa_engine::JsValue::undefined(), &args, &mut self.context) {
            Ok(value) => value_from_boa(&value, &mut self.context, 0),
            Err(err) => Err(error_from_boa(&err, &mut self.context)),
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
fn native_fn(name: JsStr, func: RawHostFn) -> NativeFunction {
    // SAFETY: the closure only captures `name` (a plain string) and
    // `func` (a plain shared rust closure); neither contains any engine
    // GC-traced values, which is the only from_closure requirement.
    unsafe {
        NativeFunction::from_closure(move |_this, args, context| {
            let mut host_args = Vec::with_capacity(args.len());
            for arg in args {
                let arg = value_from_boa(arg, context, 0)
                    .map_err(|err| host_error_to_boa(&name, &err))?;
                host_args.push(arg);
            }
            match func(host_args) {
                Ok(value) => Ok(value_to_boa(&value, context)),
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
        _ => JsNativeError::error().with_message(message).into(),
    }
}

/// Classify an engine error into an engine-agnostic [`JsError`].
fn error_from_boa(err: &boa_engine::JsError, context: &mut Context) -> JsError {
    if let Ok(native) = err.try_native(context) {
        let kind = match native.kind {
            JsNativeErrorKind::Syntax => JsErrorKind::Parse,
            JsNativeErrorKind::RuntimeLimit => JsErrorKind::LimitExceeded,
            _ => JsErrorKind::Throw,
        };
        return JsError::new(kind, native.to_string());
    }

    let thrown = err.to_opaque(context);
    let mut public = JsError::new(JsErrorKind::Throw, format!("script threw: {thrown:?}"));
    if let Ok(value) = value_from_boa(&thrown, context, 0) {
        public =
            JsError::new(JsErrorKind::Throw, format!("script threw: {value}")).with_thrown(value);
    }
    public
}

/// Materialize an engine value into an engine-agnostic [`JsValue`] snapshot.
fn value_from_boa(
    value: &boa_engine::JsValue,
    context: &mut Context,
    depth: usize,
) -> Result<JsValue, JsError> {
    use boa_engine::value::JsVariant;

    if depth > MAX_SNAPSHOT_DEPTH {
        return Err(JsError::conversion(format!(
            "value nesting exceeds the maximum supported depth of {MAX_SNAPSHOT_DEPTH}"
        )));
    }

    Ok(match value.variant() {
        JsVariant::Undefined => JsValue::Undefined,
        JsVariant::Null => JsValue::Null,
        JsVariant::Boolean(b) => JsValue::Bool(b),
        JsVariant::Integer32(n) => JsValue::Number(f64::from(n)),
        JsVariant::Float64(n) => JsValue::Number(n),
        JsVariant::String(s) => JsValue::String(boa_string_to_public(&s)),
        JsVariant::BigInt(n) => {
            return Err(JsError::conversion(format!(
                "bigint values cannot cross the js boundary (got {n})"
            )));
        }
        JsVariant::Symbol(s) => {
            return Err(JsError::conversion(format!(
                "symbol values cannot cross the js boundary (got {s})"
            )));
        }
        JsVariant::Object(obj) => {
            if obj.is_callable() {
                return Err(JsError::conversion(
                    "function values cannot cross the js boundary",
                ));
            }
            if obj.is_array() {
                let length = obj
                    .get(JsString::from("length"), context)
                    .ok()
                    .and_then(|len| len.as_number())
                    .unwrap_or_default() as u64;
                // `length` is script-controlled and may be enormous even for
                // a sparse array, so it must not size a speculative allocation.
                let mut values = Vec::new();
                for index in 0..length {
                    let element = obj.get(index, context).map_err(|err| snapshot_err(&err))?;
                    values.push(value_from_boa(&element, context, depth + 1)?);
                }
                JsValue::Array(JsArray::from(values))
            } else {
                let keys = obj
                    .own_property_keys(context)
                    .map_err(|err| snapshot_err(&err))?;
                let mut entries = Vec::with_capacity(keys.len());
                for key in keys {
                    let name = match &key {
                        PropertyKey::String(s) => boa_string_to_public(s),
                        PropertyKey::Index(index) => JsStr::from(index.get().to_string()),
                        PropertyKey::Symbol(_) => continue,
                    };
                    let prop = obj.get(key, context).map_err(|err| snapshot_err(&err))?;
                    // functions are skipped, mirroring JSON.stringify semantics
                    if prop.is_callable() {
                        continue;
                    }
                    entries.push((name, value_from_boa(&prop, context, depth + 1)?));
                }
                JsValue::Object(entries.into_iter().collect())
            }
        }
    })
}

fn snapshot_err(err: &boa_engine::JsError) -> JsError {
    JsError::conversion(format!("failed to snapshot js value: {err}"))
}

/// Copy an engine string out in a single pass, straight from the
/// engine's internal representation: ascii (the common case) is a
/// plain byte copy, latin1 and utf-16 transcode exactly once. Unpaired
/// surrogates are replaced (lossy), as a `Send` utf-8 string cannot
/// hold them.
fn boa_string_to_public(s: &JsString) -> JsStr {
    match s.as_str().variant() {
        JsStrVariant::Latin1(bytes) => match std::str::from_utf8(bytes) {
            Ok(ascii) => JsStr::new(ascii),
            Err(_) => bytes
                .iter()
                .map(|&b| char::from(b))
                .collect::<String>()
                .into(),
        },
        JsStrVariant::Utf16(units) => String::from_utf16_lossy(units).into(),
    }
}

/// Convert an engine-agnostic [`JsValue`] into an engine value.
fn value_to_boa(value: &JsValue, context: &mut Context) -> boa_engine::JsValue {
    match value {
        JsValue::Undefined => boa_engine::JsValue::undefined(),
        JsValue::Null => boa_engine::JsValue::null(),
        JsValue::Bool(b) => boa_engine::JsValue::from(*b),
        JsValue::Number(n) => boa_engine::JsValue::from(*n),
        JsValue::String(s) => boa_engine::JsValue::from(js_str_to_boa(s)),
        JsValue::Array(arr) => {
            let elements: Vec<_> = arr
                .iter()
                .map(|element| value_to_boa(element, context))
                .collect();
            boa_engine::object::builtins::JsArray::from_iter(elements, context).into()
        }
        JsValue::Object(obj) => {
            let object = BoaObject::with_object_proto(context.intrinsics());
            for (key, value) in obj {
                let value = value_to_boa(value, context);
                let result =
                    object.create_data_property_or_throw(js_str_to_boa(key), value, context);
                debug_assert!(result.is_ok());
            }
            object.into()
        }
    }
}
