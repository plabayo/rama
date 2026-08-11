import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const artifact = fileURLToPath(new URL("rama-js-engine.wasm", import.meta.url));
const checksum = fileURLToPath(new URL("rama-js-engine.wasm.sha256", import.meta.url));

const digest = createHash("sha256");
for await (const chunk of createReadStream(artifact)) {
  digest.update(chunk);
}

const expected = (await readFile(checksum, "utf8")).trim().split(/\s+/, 1)[0];
const actual = digest.digest("hex");
if (actual !== expected) {
  throw new Error(`rama-js-engine.wasm has sha256 ${actual}, expected ${expected}`);
}
