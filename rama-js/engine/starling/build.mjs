import { componentize } from "@bytecodealliance/componentize-js";
import { mkdir, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const COMPONENTIZE_JS_REVISION = "4b8d6eb465b5cded6b97c67aaf6fdaa8b62001e2";
const STARLINGMONKEY_REVISION = "9dda8ba7fcda2e17c6795d402f0478cf4c1f7f37";
const root = dirname(fileURLToPath(import.meta.url));
const buildRoot = `${root}/.build`;
const componentizeSource = `${buildRoot}/componentize-js`;
const componentizeBuild = `${buildRoot}/componentize-js-build`;
const customEngine = `${componentizeSource}/lib/starlingmonkey_embedding.wasm`;
const emptyWptRoot = `${buildRoot}/empty-wpt`;

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", ...options });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(
          `${command} failed${signal === null ? ` with exit code ${code}` : ` on signal ${signal}`}`,
        ));
      }
    });
  });
}

async function output(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "inherit"] });
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(new Error(
          `${command} failed${signal === null ? ` with exit code ${code}` : ` on signal ${signal}`}`,
        ));
      }
    });
  });
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function prepareCustomEngine() {
  await mkdir(emptyWptRoot, { recursive: true });
  if (!(await exists(`${componentizeSource}/.git`))) {
    await run("git", [
      "-c", "url.https://github.com/.insteadOf=git@github.com:",
      "clone",
      "--depth", "1",
      "--branch", "0.22.0",
      "https://github.com/bytecodealliance/ComponentizeJS.git",
      componentizeSource,
    ]);
  }
  await run("git", [
    "-c", "url.https://github.com/.insteadOf=git@github.com:",
    "submodule", "update", "--init", "--depth", "1",
  ], { cwd: componentizeSource });

  const componentizeRevision = await output("git", ["rev-parse", "HEAD"], {
    cwd: componentizeSource,
  });
  if (componentizeRevision !== COMPONENTIZE_JS_REVISION) {
    throw new Error(
      `cached ComponentizeJS revision is ${componentizeRevision}, expected ${COMPONENTIZE_JS_REVISION}`,
    );
  }
  const starlingRevision = await output("git", ["rev-parse", "HEAD"], {
    cwd: `${componentizeSource}/StarlingMonkey`,
  });
  if (starlingRevision !== STARLINGMONKEY_REVISION) {
    throw new Error(
      `cached StarlingMonkey revision is ${starlingRevision}, expected ${STARLINGMONKEY_REVISION}`,
    );
  }

  await run("cmake", [
    "-S", componentizeSource,
    "-B", componentizeBuild,
    "-DCMAKE_BUILD_TYPE=Release",
    `-DCMAKE_PROJECT_INCLUDE=${root}/rama-engine.cmake`,
    "-DENABLE_JS_DEBUGGER=OFF",
    "-DENABLE_BUILTIN_WPT_SUPPORT=OFF",
  ], { env: { ...process.env, WPT_ROOT: emptyWptRoot } });
  await run("cmake", [
    "--build", componentizeBuild,
    "--target", "starlingmonkey_embedding",
    "--parallel",
  ]);
  return customEngine;
}

const engine = await prepareCustomEngine();

const { component } = await componentize({
  sourcePath: new URL("runtime.js", import.meta.url).pathname,
  witPath: new URL("engine.wit", import.meta.url).pathname,
  worldName: "engine",
  engine,
  enableAot: false,
  disableFeatures: ["stdio", "random", "clocks", "http", "fetch-event"],
});

await writeFile(new URL("rama-js-engine.wasm", import.meta.url), component);
