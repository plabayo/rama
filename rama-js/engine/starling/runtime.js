import { invoke } from "rama:js-engine/host@0.1.0";

const realmGlobal = globalThis;
const evaluateScript = realmGlobal.__rama_evaluate_script__;
const takeParseFailure = realmGlobal.__rama_take_parse_failure__;
const IntrinsicError = Error;
const IntrinsicTypeError = TypeError;
const IntrinsicRangeError = RangeError;
const IntrinsicInternalError = realmGlobal.InternalError;
const IntrinsicArray = Array;
const IntrinsicSet = Set;
const IntrinsicWeakMap = WeakMap;
const IntrinsicUint8Array = Uint8Array;
const IntrinsicDataView = DataView;
const stringConvert = String;
const stringSlice = String.prototype.slice;
const numberIsInteger = Number.isInteger;
const numberIsSafeInteger = Number.isSafeInteger;
const mathCeil = Math.ceil;
const mathMax = Math.max;
const mathMin = Math.min;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const functionHasInstance = Function.prototype[Symbol.hasInstance];
const stringCharCodeAt = String.prototype.charCodeAt;
const reflectApply = Reflect.apply;
const reflectDeleteProperty = Reflect.deleteProperty;
const reflectGet = Reflect.get;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const setAdd = Set.prototype.add;
const setDelete = Set.prototype.delete;
const setHas = Set.prototype.has;
const weakMapGet = WeakMap.prototype.get;
const weakMapHas = WeakMap.prototype.has;
const weakMapSet = WeakMap.prototype.set;
const typedArraySet = Uint8Array.prototype.set;
const dataViewGetFloat64 = DataView.prototype.getFloat64;
const dataViewSetFloat64 = DataView.prototype.setFloat64;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const textEncoderEncode = TextEncoder.prototype.encode;
const textDecoderDecode = TextDecoder.prototype.decode;

if (typeof evaluateScript !== "function" || typeof takeParseFailure !== "function") {
  throw new IntrinsicError("Rama's native Script evaluator is unavailable");
}
if (
  !reflectApply(reflectDeleteProperty, Reflect, [realmGlobal, "__rama_evaluate_script__"])
  || !reflectApply(reflectDeleteProperty, Reflect, [realmGlobal, "__rama_take_parse_failure__"])
) {
  throw new IntrinsicError("Rama's native Script evaluator could not be sealed");
}

const hostObjectMetadata = new IntrinsicWeakMap();
const markedErrorKinds = new IntrinsicWeakMap();

let options;

class BoundaryError extends IntrinsicError {
  constructor(kind, message) {
    super(message);
    reflectApply(weakMapSet, markedErrorKinds, [this, kind]);
  }
}

function encodeText(value) {
  return reflectApply(textEncoderEncode, textEncoder, [value]);
}

function decodeText(value) {
  return reflectApply(textDecoderDecode, textDecoder, [value]);
}

function success(value = undefined, encodeValue = true) {
  return {
    ok: true,
    kind: undefined,
    message: "",
    payload: encodeValue ? encode(value) : new IntrinsicUint8Array(),
    thrown: undefined,
  };
}

function boundedText(value, maxBytes = 4096) {
  let text;
  try {
    text = stringConvert(value);
  } catch {
    return "script threw a value that could not be rendered";
  }
  if (encodeText(text).length <= maxBytes) {
    return text;
  }

  let low = 0;
  let high = text.length;
  while (low < high) {
    const middle = mathCeil((low + high) / 2);
    if (encodeText(reflectApply(stringSlice, text, [0, middle])).length <= maxBytes) {
      low = middle;
    } else {
      high = middle - 1;
    }
  }
  if (low > 0) {
    const code = reflectApply(stringCharCodeAt, text, [low - 1]);
    if (code >= 0xd800 && code <= 0xdbff) {
      low -= 1;
    }
  }
  return `${reflectApply(stringSlice, text, [0, low])}… (truncated)`;
}

function isInstance(value, constructor) {
  return reflectApply(functionHasInstance, constructor, [value]);
}

function errorMessage(error) {
  try {
    if (isInstance(error, BoundaryError)) {
      return boundedText(error.message);
    }
    if (isInstance(error, IntrinsicError)) {
      return boundedText(`${error.name}: ${error.message}`);
    }
    return boundedText(`script threw: ${stringConvert(error)}`);
  } catch {
    return "script threw a value that could not be rendered";
  }
}

function failure(error, fallbackKind = "throw") {
  const boundaryKind = isInstance(error, BoundaryError)
    ? reflectApply(weakMapGet, markedErrorKinds, [error])
    : undefined;
  const markedKind =
    typeof error === "object" && error !== null
      ? reflectApply(weakMapGet, markedErrorKinds, [error])
      : undefined;
  const engineLimitKind =
    typeof IntrinsicInternalError === "function" && isInstance(error, IntrinsicInternalError)
      ? "limit-exceeded"
      : undefined;
  const kind = boundaryKind ?? markedKind ?? engineLimitKind ?? fallbackKind;
  let thrown;
  if (kind === "throw") {
    try {
      thrown = encode(error);
    } catch {
      thrown = undefined;
    }
  }
  return {
    ok: false,
    kind,
    message: errorMessage(error),
    payload: new IntrinsicUint8Array(),
    thrown,
  };
}

function run(operation, fallbackKind = "throw", encodeValue = true) {
  try {
    return success(operation(), encodeValue);
  } catch (error) {
    return failure(error, fallbackKind);
  }
}

function defineDataProperty(object, name, value) {
  objectDefineProperty(object, name, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

function throwHostFailure(outcome) {
  let error;
  switch (outcome.kind) {
    case "conversion":
      error = new IntrinsicTypeError(outcome.message);
      break;
    case "limit-exceeded":
      error = new IntrinsicRangeError(outcome.message);
      reflectApply(weakMapSet, markedErrorKinds, [error, outcome.kind]);
      break;
    default:
      error = new IntrinsicError(outcome.message);
      break;
  }
  throw error;
}

function hostFunction(callbackId, arity, lenientArgs, receiver) {
  const fn = function (...args) {
    const objectId = receiver === undefined ? undefined : receiver(this);
    const count = arity === undefined ? args.length : mathMin(arity, args.length);
    const outcome = invoke(
      callbackId,
      objectId,
      encodeArguments(args, count, lenientArgs),
    );
    if (!outcome.ok) {
      throwHostFailure(outcome);
    }
    return decode(outcome.payload);
  };
  if (arity !== undefined) {
    objectDefineProperty(fn, "length", { value: arity, configurable: true });
  }
  return fn;
}

function hostReceiver(classId) {
  return (receiver) => {
    const metadata = reflectApply(weakMapGet, hostObjectMetadata, [receiver]);
    if (metadata === undefined) {
      throw new IntrinsicTypeError("invalid host object receiver");
    }
    if (metadata.classId !== classId) {
      throw new IntrinsicTypeError("incompatible host object receiver");
    }
    return metadata.objectId;
  };
}

function defineHostObject(name, objectId, classId, members) {
  const prototype = {};
  const object = objectCreate(prototype);
  reflectApply(weakMapSet, hostObjectMetadata, [object, { objectId, classId }]);
  const receiver = hostReceiver(classId);

  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    const descriptor = objectGetOwnPropertyDescriptor(prototype, member.name) ?? {
      enumerable: true,
      configurable: true,
    };
    switch (member.kind) {
      case "method":
        descriptor.value = hostFunction(member.callbackId, member.arity, false, receiver);
        descriptor.writable = true;
        break;
      case "getter":
        descriptor.get = hostFunction(member.callbackId, 0, false, receiver);
        break;
      case "setter":
        descriptor.set = hostFunction(member.callbackId, 1, false, receiver);
        break;
      default:
        throw new IntrinsicTypeError(`unknown host member kind: ${member.kind}`);
    }
    objectDefineProperty(prototype, member.name, descriptor);
  }

  defineDataProperty(realmGlobal, name, object);
}

class SnapshotState {
  constructor() {
    this.nodes = 0;
    this.stringBytes = 0;
    this.active = new IntrinsicSet();
  }

  reserveNodes(count) {
    const next = this.nodes + count;
    if (!numberIsSafeInteger(next) || next > options.snapshotLimits.maxNodes) {
      throw new BoundaryError(
        "limit-exceeded",
        `js value snapshot exceeds the maximum of ${options.snapshotLimits.maxNodes} nodes and edges`,
      );
    }
    this.nodes = next;
  }

  reserveString(bytes) {
    const next = this.stringBytes + bytes;
    if (!numberIsSafeInteger(next) || next > options.snapshotLimits.maxStringBytes) {
      throw new BoundaryError(
        "limit-exceeded",
        `js value snapshot exceeds the maximum of ${options.snapshotLimits.maxStringBytes} string bytes`,
      );
    }
    this.stringBytes = next;
  }
}

class Writer {
  constructor() {
    this.bytes = new IntrinsicUint8Array(256);
    this.offset = 0;
  }

  ensure(length) {
    const required = this.offset + length;
    if (!numberIsSafeInteger(required) || required > 0xffff_ffff) {
      throw new BoundaryError("limit-exceeded", "js value is too large to encode");
    }
    if (required <= this.bytes.length) {
      return;
    }
    let capacity = this.bytes.length;
    while (capacity < required) {
      capacity = mathMin(0xffff_ffff, mathMax(required, capacity * 2));
    }
    const grown = new IntrinsicUint8Array(capacity);
    reflectApply(typedArraySet, grown, [this.bytes, 0]);
    this.bytes = grown;
  }

  byte(value) {
    this.ensure(1);
    this.bytes[this.offset] = value;
    this.offset += 1;
  }

  u32(value) {
    if (!numberIsSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
      throw new BoundaryError("limit-exceeded", "js value is too large to encode");
    }
    this.ensure(4);
    this.bytes[this.offset] = value & 0xff;
    this.bytes[this.offset + 1] = (value >>> 8) & 0xff;
    this.bytes[this.offset + 2] = (value >>> 16) & 0xff;
    this.bytes[this.offset + 3] = (value >>> 24) & 0xff;
    this.offset += 4;
  }

  f64(value) {
    this.ensure(8);
    const view = new IntrinsicDataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 8);
    reflectApply(dataViewSetFloat64, view, [0, value, true]);
    this.offset += 8;
  }

  raw(bytes) {
    this.ensure(bytes.length);
    reflectApply(typedArraySet, this.bytes, [bytes, this.offset]);
    this.offset += bytes.length;
  }

  string(value, state) {
    const bytes = encodeText(value);
    state.reserveString(bytes.length);
    this.u32(bytes.length);
    this.raw(bytes);
  }

  finish() {
    return new IntrinsicUint8Array(this.bytes.buffer, this.bytes.byteOffset, this.offset);
  }
}

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  take(length) {
    if (!numberIsSafeInteger(length) || length < 0 || length > this.bytes.length - this.offset) {
      throw new BoundaryError("conversion", "truncated JavaScript value");
    }
    const bytes = new IntrinsicUint8Array(
      this.bytes.buffer,
      this.bytes.byteOffset + this.offset,
      length,
    );
    this.offset += length;
    return bytes;
  }

  byte() {
    return this.take(1)[0];
  }

  u32() {
    const bytes = this.take(4);
    return (
      bytes[0]
      + bytes[1] * 0x100
      + bytes[2] * 0x1_0000
      + bytes[3] * 0x100_0000
    );
  }

  f64() {
    const bytes = this.take(8);
    const view = new IntrinsicDataView(bytes.buffer, bytes.byteOffset, 8);
    return reflectApply(dataViewGetFloat64, view, [0, true]);
  }

  string() {
    return decodeText(this.take(this.u32()));
  }
}

function writeObject(writer, value, state, depth) {
  if (reflectApply(weakMapHas, hostObjectMetadata, [value])) {
    throw new BoundaryError(
      "conversion",
      "native host objects cannot cross the js value boundary",
    );
  }
  if (reflectApply(setHas, state.active, [value])) {
    throw new BoundaryError("conversion", "cyclic object graph cannot cross the js boundary");
  }
  reflectApply(setAdd, state.active, [value]);
  try {
    if (arrayIsArray(value)) {
      const length = reflectGet(value, "length");
      if (
        typeof length === "number"
        && numberIsInteger(length)
        && length >= 0
        && length <= 0xffff_ffff
      ) {
        if (length > options.snapshotLimits.maxArrayLength) {
          throw new BoundaryError(
            "limit-exceeded",
            `js array length ${length} exceeds the snapshot maximum of ${options.snapshotLimits.maxArrayLength}`,
          );
        }
        state.reserveNodes(length);
        writer.byte(6);
        writer.u32(length);
        for (let index = 0; index < length; index += 1) {
          writeValue(writer, reflectGet(value, index), state, depth + 1, true);
        }
        return;
      }
    }

    const keys = reflectOwnKeys(value);
    if (keys.length > options.snapshotLimits.maxObjectProperties) {
      throw new BoundaryError(
        "limit-exceeded",
        `js object property count ${keys.length} exceeds the snapshot maximum of ${options.snapshotLimits.maxObjectProperties}`,
      );
    }
    state.reserveNodes(keys.length);
    const entries = new IntrinsicArray();
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (typeof key !== "string") {
        continue;
      }
      const entry = reflectGet(value, key);
      if (typeof entry !== "function") {
        entries[entries.length] = [key, entry];
      }
    }
    writer.byte(7);
    writer.u32(entries.length);
    for (let index = 0; index < entries.length; index += 1) {
      const key = entries[index][0];
      const entry = entries[index][1];
      writer.string(key, state);
      writeValue(writer, entry, state, depth + 1, true);
    }
  } finally {
    reflectApply(setDelete, state.active, [value]);
  }
}

function writeValue(writer, value, state, depth = 0, nodeReserved = false) {
  if (depth > options.snapshotLimits.maxDepth) {
    throw new BoundaryError(
      "limit-exceeded",
      `js value snapshot exceeds the maximum depth of ${options.snapshotLimits.maxDepth}`,
    );
  }
  if (!nodeReserved) {
    state.reserveNodes(1);
  }

  if (value === undefined) {
    writer.byte(0);
  } else if (value === null) {
    writer.byte(1);
  } else if (value === false) {
    writer.byte(2);
  } else if (value === true) {
    writer.byte(3);
  } else if (typeof value === "number") {
    writer.byte(4);
    writer.f64(value);
  } else if (typeof value === "string") {
    writer.byte(5);
    writer.string(value, state);
  } else if (typeof value === "object") {
    writeObject(writer, value, state, depth);
  } else if (typeof value === "bigint") {
    throw new BoundaryError(
      "conversion",
      `bigint values cannot cross the js boundary (got ${boundedText(value, 512)})`,
    );
  } else if (typeof value === "symbol") {
    throw new BoundaryError(
      "conversion",
      `symbol values cannot cross the js boundary (got ${boundedText(value, 512)})`,
    );
  } else if (typeof value === "function") {
    throw new BoundaryError("conversion", "function values cannot cross the js boundary");
  } else {
    throw new BoundaryError(
      "conversion",
      `${typeof value} values cannot cross the js boundary`,
    );
  }
}

function readValue(reader) {
  switch (reader.byte()) {
    case 0: return undefined;
    case 1: return null;
    case 2: return false;
    case 3: return true;
    case 4: return reader.f64();
    case 5: return reader.string();
    case 6: {
      const length = reader.u32();
      const values = new IntrinsicArray(length);
      for (let index = 0; index < length; index += 1) {
        values[index] = readValue(reader);
      }
      return values;
    }
    case 7: {
      const length = reader.u32();
      const object = {};
      for (let index = 0; index < length; index += 1) {
        defineDataProperty(object, reader.string(), readValue(reader));
      }
      return object;
    }
    default:
      throw new BoundaryError("conversion", "unknown JavaScript value tag");
  }
}

function encode(value) {
  const writer = new Writer();
  writeValue(writer, value, new SnapshotState());
  return writer.finish();
}

function encodeArguments(args, count, lenient) {
  const writer = new Writer();
  const state = new SnapshotState();
  writer.byte(6);
  writer.u32(count);
  for (let index = 0; index < count; index += 1) {
    const offset = writer.offset;
    const nodes = state.nodes;
    const stringBytes = state.stringBytes;
    try {
      writeValue(writer, args[index], state);
    } catch (error) {
      if (!lenient) {
        throw error;
      }
      writer.offset = offset;
      state.nodes = nodes;
      state.stringBytes = stringBytes;
      writeValue(writer, `<${errorMessage(error)}>`, state);
    }
  }
  return writer.finish();
}

function decode(bytes) {
  const reader = new Reader(bytes);
  const value = readValue(reader);
  if (reader.offset !== bytes.length) {
    throw new BoundaryError("conversion", "trailing bytes after JavaScript value");
  }
  return value;
}

function sourceText(source) {
  return options.strict ? `"use strict";\n${source}` : source;
}

function evaluate(source, encodeValue) {
  const text = sourceText(source);
  try {
    const value = evaluateScript(text);
    return success(value, encodeValue);
  } catch (error) {
    return failure(error, takeParseFailure() ? "parse" : "throw");
  }
}

export const runtime = {
  configure(nextOptions) {
    return run(() => {
      if (options !== undefined) {
        throw new IntrinsicError("runtime is already configured");
      }
      options = nextOptions;
      objectDefineProperty(realmGlobal, "__rama_js_call__", {
        value() {
          throw new IntrinsicError("no pending host call");
        },
        writable: false,
        enumerable: false,
        configurable: false,
      });
    }, "setup", false);
  },

  defineGlobal(name, value) {
    return run(() => defineDataProperty(realmGlobal, name, decode(value)), "setup", false);
  },

  defineHostFunction(specification) {
    return run(() => {
      defineDataProperty(
        realmGlobal,
        specification.name,
        hostFunction(
          specification.callbackId,
          specification.arity,
          specification.lenientArgs,
        ),
      );
    }, "setup", false);
  },

  defineNamespace(name, values, functions) {
    return run(() => {
      const namespace = {};
      for (let index = 0; index < values.length; index += 1) {
        const entry = values[index];
        defineDataProperty(namespace, entry.name, decode(entry.value));
      }
      for (let index = 0; index < functions.length; index += 1) {
        const entry = functions[index];
        defineDataProperty(
          namespace,
          entry.name,
          hostFunction(entry.callbackId, entry.arity, entry.lenientArgs),
        );
      }
      defineDataProperty(realmGlobal, name, namespace);
    }, "setup", false);
  },

  defineHostObject(name, objectId, classId, members) {
    return run(() => defineHostObject(name, objectId, classId, members), "setup", false);
  },

  exec(source) {
    return evaluate(source, false);
  },

  evaluate(source) {
    return evaluate(source, true);
  },

  call(name, args) {
    const descriptor = objectGetOwnPropertyDescriptor(realmGlobal, name);
    if (
      descriptor === undefined
      || !reflectApply(objectHasOwnProperty, descriptor, ["value"])
      || typeof descriptor.value !== "function"
    ) {
      return failure(
        new IntrinsicError(`global function \`${name}\` not found`),
        "not-found",
      );
    }
    return run(() => reflectApply(descriptor.value, realmGlobal, decode(args)));
  },

  hasGlobalFunction(name) {
    const descriptor = objectGetOwnPropertyDescriptor(realmGlobal, name);
    return descriptor !== undefined
      && reflectApply(objectHasOwnProperty, descriptor, ["value"])
      && typeof descriptor.value === "function";
  },
};
