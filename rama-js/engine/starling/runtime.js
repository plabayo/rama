import { invoke } from "rama:js-engine/host@0.1.0";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const indirectEval = (0, eval);
const hostObjectMetadata = new WeakMap();

function success(value = undefined) {
  return { ok: true, payload: encode(value) };
}

function failure(error) {
  let message;
  try {
    message = error instanceof Error ? error.message : String(error);
  } catch {
    message = "JavaScript operation failed";
  }
  return { ok: false, payload: textEncoder.encode(message) };
}

function run(operation) {
  try {
    return success(operation());
  } catch (error) {
    return failure(error);
  }
}

function hostFunction(callbackId, arity, receiver) {
  const fn = function (...args) {
    const objectId = receiver === undefined ? undefined : receiver(this);
    const outcome = invoke(callbackId, objectId, encode(args));
    if (!outcome.ok) {
      throw new Error(textDecoder.decode(outcome.payload));
    }
    return decode(outcome.payload);
  };
  if (arity !== undefined) {
    Object.defineProperty(fn, "length", { value: arity, configurable: true });
  }
  return fn;
}

function hostReceiver(classId) {
  return (receiver) => {
    const metadata = hostObjectMetadata.get(receiver);
    if (metadata === undefined) {
      throw new TypeError("invalid host object receiver");
    }
    if (metadata.classId !== classId) {
      throw new TypeError("incompatible host object receiver");
    }
    return metadata.objectId;
  };
}

function defineHostObject(name, objectId, classId, members) {
  const object = {};
  hostObjectMetadata.set(object, { objectId, classId });
  const receiver = hostReceiver(classId);

  for (const member of members) {
    const descriptor = Object.getOwnPropertyDescriptor(object, member.name) ?? {
      enumerable: true,
      configurable: true,
    };
    switch (member.kind) {
      case "method":
        descriptor.value = hostFunction(member.callbackId, member.arity, receiver);
        descriptor.writable = true;
        break;
      case "getter":
        descriptor.get = hostFunction(member.callbackId, 0, receiver);
        break;
      case "setter":
        descriptor.set = hostFunction(member.callbackId, 1, receiver);
        break;
      default:
        throw new TypeError(`unknown host member kind: ${member.kind}`);
    }
    Object.defineProperty(object, member.name, descriptor);
  }

  globalThis[name] = object;
}

function assertScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new TypeError("JavaScript string contains an unpaired surrogate");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("JavaScript string contains an unpaired surrogate");
    }
  }
}

class Writer {
  constructor() {
    this.bytes = [];
  }

  byte(value) {
    this.bytes.push(value);
  }

  u32(value) {
    this.byte(value & 0xff);
    this.byte((value >>> 8) & 0xff);
    this.byte((value >>> 16) & 0xff);
    this.byte((value >>> 24) & 0xff);
  }

  f64(value) {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setFloat64(0, value, true);
    this.raw(bytes);
  }

  raw(bytes) {
    for (const byte of bytes) {
      this.byte(byte);
    }
  }

  string(value) {
    assertScalarString(value);
    const bytes = textEncoder.encode(value);
    this.u32(bytes.length);
    this.raw(bytes);
  }

  finish() {
    return Uint8Array.from(this.bytes);
  }
}

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  take(length) {
    if (length > this.bytes.length - this.offset) {
      throw new TypeError("truncated JavaScript value");
    }
    const bytes = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }

  byte() {
    return this.take(1)[0];
  }

  u32() {
    return new DataView(this.take(4).buffer, this.bytes.byteOffset + this.offset - 4, 4)
      .getUint32(0, true);
  }

  f64() {
    return new DataView(this.take(8).buffer, this.bytes.byteOffset + this.offset - 8, 8)
      .getFloat64(0, true);
  }

  string() {
    return textDecoder.decode(this.take(this.u32()));
  }
}

function writeValue(writer, value, ancestors) {
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
    writer.string(value);
  } else if (Array.isArray(value)) {
    if (ancestors.has(value)) {
      throw new TypeError("cyclic JavaScript values cannot cross the boundary");
    }
    ancestors.add(value);
    writer.byte(6);
    writer.u32(value.length);
    for (const element of value) {
      writeValue(writer, element, ancestors);
    }
    ancestors.delete(value);
  } else if (typeof value === "object") {
    if (hostObjectMetadata.has(value)) {
      throw new TypeError("native host objects cannot cross the JavaScript value boundary");
    }
    if (ancestors.has(value)) {
      throw new TypeError("cyclic JavaScript values cannot cross the boundary");
    }
    ancestors.add(value);
    const entries = Object.keys(value)
      .map((key) => [key, value[key]])
      .filter(([, entry]) => typeof entry !== "function");
    writer.byte(7);
    writer.u32(entries.length);
    for (const [key, entry] of entries) {
      writer.string(key);
      writeValue(writer, entry, ancestors);
    }
    ancestors.delete(value);
  } else {
    throw new TypeError(`${typeof value} values cannot cross the JavaScript value boundary`);
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
      return Array.from({ length }, () => readValue(reader));
    }
    case 7: {
      const length = reader.u32();
      const object = {};
      for (let index = 0; index < length; index += 1) {
        object[reader.string()] = readValue(reader);
      }
      return object;
    }
    default:
      throw new TypeError("unknown JavaScript value tag");
  }
}

function encode(value) {
  const writer = new Writer();
  writeValue(writer, value, new Set());
  return writer.finish();
}

function decode(bytes) {
  const reader = new Reader(bytes);
  const value = readValue(reader);
  if (reader.offset !== bytes.length) {
    throw new TypeError("trailing bytes after JavaScript value");
  }
  return value;
}

export const runtime = {
  defineGlobal(name, value) {
    return run(() => {
      globalThis[name] = decode(value);
    });
  },

  defineHostFunction(specification) {
    return run(() => {
      globalThis[specification.name] = hostFunction(
        specification.callbackId,
        specification.arity,
      );
    });
  },

  defineNamespace(name, values, functions) {
    return run(() => {
      const namespace = {};
      for (const entry of values) {
        namespace[entry.name] = decode(entry.value);
      }
      for (const entry of functions) {
        namespace[entry.name] = hostFunction(entry.callbackId, entry.arity);
      }
      globalThis[name] = namespace;
    });
  },

  defineHostObject(name, objectId, classId, members) {
    return run(() => defineHostObject(name, objectId, classId, members));
  },

  exec(source) {
    return run(() => {
      indirectEval(source);
    });
  },

  evaluate(source) {
    return run(() => indirectEval(source));
  },

  call(name, args) {
    return run(() => {
      const fn = globalThis[name];
      if (typeof fn !== "function") {
        throw new TypeError(`global function not found: ${name}`);
      }
      return Reflect.apply(fn, globalThis, decode(args));
    });
  },

  hasGlobalFunction(name) {
    return typeof globalThis[name] === "function";
  },
};
