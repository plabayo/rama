import { componentize } from "@bytecodealliance/componentize-js";
import { writeFile } from "node:fs/promises";

const { component } = await componentize({
  sourcePath: new URL("runtime.js", import.meta.url).pathname,
  witPath: new URL("engine.wit", import.meta.url).pathname,
  worldName: "engine",
  enableAot: false,
  disableFeatures: ["stdio", "random", "clocks", "http", "fetch-event"],
});

await writeFile(new URL("rama-js-engine.wasm", import.meta.url), component);
