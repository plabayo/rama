import { componentize } from "@bytecodealliance/componentize-js";
import { createReadStream } from "node:fs";
import { copyFile, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";

const COMPONENTIZE_JS_REVISION = "4b8d6eb465b5cded6b97c67aaf6fdaa8b62001e2";
const STARLINGMONKEY_REVISION = "9dda8ba7fcda2e17c6795d402f0478cf4c1f7f37";
const root = dirname(fileURLToPath(import.meta.url));
const buildRoot = `${root}/.build`;
const componentizeSource = `${buildRoot}/componentize-js`;
const componentizeBuild = `${buildRoot}/componentize-js-build`;
const customEngine = `${componentizeSource}/lib/starlingmonkey_embedding.wasm`;
const emptyWptRoot = `${buildRoot}/empty-wpt`;
const buildConfigurationRevision = "pinned-toolchains-v1";
const spiderMonkeyHash = "c57dc83d93dc04198882b44fea49cd3cb01e0b267bf99fae3b058cb158da684b";
const spiderMonkeyUrl = "https://github.com/bytecodealliance/StarlingMonkey/releases/download/libspidermonkey_FIREFOX_147_0_4_RELEASE_STARLING/spidermonkey-static-release.tar.gz";

const TOOLCHAINS = [
  {
    name: "wasi-sdk",
    release: "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-30",
    expected: "bin/clang",
    assets: {
      "linux-arm64": ["wasi-sdk-30.0-arm64-linux.tar.gz", "6f2977942308d91b0123978da3c6a0d6fce780994b3b020008c617e26764ea40"],
      "linux-x64": ["wasi-sdk-30.0-x86_64-linux.tar.gz", "0507679dff16814b74516cd969a9b16d2ced1347388024bc7966264648c78bfb"],
      "darwin-arm64": ["wasi-sdk-30.0-arm64-macos.tar.gz", "2c2ed99296857e60fd14c3f40fe226231f296409502491094704089c31a16740"],
      "darwin-x64": ["wasi-sdk-30.0-x86_64-macos.tar.gz", "1594a0791309781bf0d0224431c3556ec4a2326b205687b659f6550d08d8b13e"],
      "win32-arm64": ["wasi-sdk-30.0-arm64-windows.tar.gz", "b9552f207ea4287616dbf7c40bc0fbd5a9271ba6f8333fa606b63636f75060c2"],
      "win32-x64": ["wasi-sdk-30.0-x86_64-windows.tar.gz", "e87d6bf9f9ca3482a75f1cbc630f095b4ae8c98d586708bac7adf08c03b327bc"],
    },
  },
  {
    name: "wasm-tools",
    release: "https://github.com/bytecodealliance/wasm-tools/releases/download/v1.235.0",
    expected: process.platform === "win32" ? "wasm-tools.exe" : "wasm-tools",
    assets: {
      "linux-arm64": ["wasm-tools-1.235.0-aarch64-linux.tar.gz", "384ca3691502116fb6f48951ad42bd0f01f9bf799111014913ce15f4f4dde5a2"],
      "linux-x64": ["wasm-tools-1.235.0-x86_64-linux.tar.gz", "4c44bc776aadbbce4eedc90c6a07c966a54b375f8f36a26fd178cea9b419f584"],
      "darwin-arm64": ["wasm-tools-1.235.0-aarch64-macos.tar.gz", "17035deade9d351df6183d87ad9283ce4ae7d3e8e93724ae70126c87188e96b2"],
      "darwin-x64": ["wasm-tools-1.235.0-x86_64-macos.tar.gz", "154e9ea5f5477aa57466cfb10e44bc62ef537e32bf13d1c35ceb4fedd9921510"],
      "win32-x64": ["wasm-tools-1.235.0-x86_64-windows.zip", "ecf9f2064c2096df134c39c2c97af2c025e974cc32e3c76eb2609156c1690a74"],
    },
  },
  {
    name: "binaryen",
    release: "https://github.com/WebAssembly/binaryen/releases/download/version_123",
    root: "binaryen-version_123",
    expected: process.platform === "win32" ? "bin/wasm-opt.exe" : "bin/wasm-opt",
    assets: {
      "linux-arm64": ["binaryen-version_123-aarch64-linux.tar.gz", "4b6bd61ba6cd3b18c993b4657d93426c782f9b91b74be0d38018cd8be1319376"],
      "linux-x64": ["binaryen-version_123-x86_64-linux.tar.gz", "e959f2170af4c20c552e9de3a0253704d6a9d2766e8fdb88e4d6ac4bae9388fe"],
      "darwin-arm64": ["binaryen-version_123-arm64-macos.tar.gz", "74428be348c1a09863e7b642a1fa948cabf8ec9561052233d8288e941951725b"],
      "darwin-x64": ["binaryen-version_123-x86_64-macos.tar.gz", "cc18b14d2b673d9c66bf54f31ff2b0ceb23ba5132455b893965ae2792f9e00dd"],
      "win32-x64": ["binaryen-version_123-x86_64-windows.tar.gz", "7b3568424a0f871a52865d5c78177db646b1832a8c487321e27703103f936880"],
    },
  },
];

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

async function sha256(path) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    digest.update(chunk);
  }
  return digest.digest("hex");
}

async function prepareSpiderMonkey() {
  const downloads = `${buildRoot}/downloads`;
  const archive = `${downloads}/spidermonkey-static-release.tar.gz`;
  const legacyArchive = `${componentizeBuild}/_deps/spidermonkey-release-subbuild/spidermonkey-release-populate-prefix/src/spidermonkey-static-release.tar.gz`;
  const extracted = `${buildRoot}/spidermonkey`;
  const binaries = `${extracted}/spidermonkey-dist-release`;
  await mkdir(downloads, { recursive: true });

  if (!(await exists(archive))) {
    if (await exists(legacyArchive)) {
      await copyFile(legacyArchive, archive);
    } else {
      await run("curl", ["--fail", "--location", "--output", archive, spiderMonkeyUrl]);
    }
  }
  const actual = await sha256(archive);
  if (actual !== spiderMonkeyHash) {
    throw new Error(
      `SpiderMonkey archive has sha256 ${actual}, expected ${spiderMonkeyHash}`,
    );
  }

  if (!(await exists(`${binaries}/libspidermonkey.a`))) {
    await rm(extracted, { recursive: true, force: true });
    await mkdir(extracted, { recursive: true });
    await run("cmake", ["-E", "tar", "xzf", archive], { cwd: extracted });
  }
  return binaries;
}

async function prepareToolchain(toolchain) {
  const platform = `${process.platform}-${process.arch}`;
  const asset = toolchain.assets[platform];
  if (asset === undefined) {
    throw new Error(`${toolchain.name} has no pinned release for ${platform}`);
  }
  const [name, expectedHash] = asset;
  const downloads = `${buildRoot}/downloads`;
  const archive = `${downloads}/${name}`;
  const legacyArchive = `${componentizeBuild}/_deps/${toolchain.name}-subbuild/${toolchain.name}-populate-prefix/src/${name}`;
  await mkdir(downloads, { recursive: true });
  if (!(await exists(archive))) {
    if (await exists(legacyArchive)) {
      await copyFile(legacyArchive, archive);
    } else {
      await run("curl", [
        "--fail",
        "--location",
        "--output",
        archive,
        `${toolchain.release}/${name}`,
      ]);
    }
  }
  const actualHash = await sha256(archive);
  if (actualHash !== expectedHash) {
    throw new Error(
      `${toolchain.name} archive has sha256 ${actualHash}, expected ${expectedHash}`,
    );
  }

  const extracted = `${buildRoot}/toolchains/${toolchain.name}`;
  const archiveRoot = toolchain.root
    ?? name.replace(/\.(?:tar\.gz|zip)$/, "");
  const source = `${extracted}/${archiveRoot}`;
  if (!(await exists(`${source}/${toolchain.expected}`))) {
    await rm(extracted, { recursive: true, force: true });
    await mkdir(extracted, { recursive: true });
    await run("cmake", ["-E", "tar", "xf", archive], { cwd: extracted });
  }
  return source;
}

async function prepareToolchains() {
  const prepared = {};
  for (const toolchain of TOOLCHAINS) {
    prepared[toolchain.name] = await prepareToolchain(toolchain);
  }
  return prepared;
}

async function prepareBuildConfiguration() {
  const marker = `${componentizeBuild}/.rama-build-configuration`;
  const current = (await exists(marker))
    ? await readFile(marker, "utf8")
    : undefined;
  if (current !== buildConfigurationRevision) {
    await rm(`${componentizeBuild}/CMakeCache.txt`, { force: true });
    await rm(`${componentizeBuild}/CMakeFiles`, { recursive: true, force: true });
  }
  return marker;
}

async function prepareCustomEngine() {
  await mkdir(emptyWptRoot, { recursive: true });
  await writeFile(`${emptyWptRoot}/unused`, "unused build dependency override\n");
  const spiderMonkey = await prepareSpiderMonkey();
  const toolchains = await prepareToolchains();
  const buildConfigurationMarker = await prepareBuildConfiguration();
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
    "-DWEVAL=OFF",
    "-DCPM_PACKAGE_wasi-sdk_VERSION=30.0",
    `-DCPM_wasi-sdk_SOURCE=${toolchains["wasi-sdk"]}`,
    `-DCPM_wasm-tools_SOURCE=${toolchains["wasm-tools"]}`,
    `-DCPM_binaryen_SOURCE=${toolchains.binaryen}`,
    `-DCPM_weval_SOURCE=${emptyWptRoot}`,
    `-DCPM_wasmtime_SOURCE=${emptyWptRoot}`,
    `-DWASM_TOOLS_BIN=${toolchains["wasm-tools"]}/${process.platform === "win32" ? "wasm-tools.exe" : "wasm-tools"}`,
    `-DWASM_OPT=${toolchains.binaryen}/bin/${process.platform === "win32" ? "wasm-opt.exe" : "wasm-opt"}`,
  ], {
    env: {
      ...process.env,
      SPIDERMONKEY_BINARIES: spiderMonkey,
      WPT_ROOT: emptyWptRoot,
    },
  });
  await writeFile(buildConfigurationMarker, buildConfigurationRevision);
  await run("cmake", [
    "--build", componentizeBuild,
    "--target", "starlingmonkey_embedding",
    "--parallel",
  ]);
  return customEngine;
}

const engine = await prepareCustomEngine();

const { component } = await componentize({
  sourcePath: fileURLToPath(new URL("runtime.js", import.meta.url)),
  witPath: fileURLToPath(new URL("engine.wit", import.meta.url)),
  worldName: "engine",
  engine,
  enableAot: false,
  disableFeatures: ["stdio", "random", "clocks", "http", "fetch-event"],
});

await writeFile(new URL("rama-js-engine.wasm", import.meta.url), component);
