# rama on-device Android tests

Test suites that need a real Android runtime, such as code calling the Android
framework through JNI. They run inside an Android runtime started with
`app_process`, without an app or APK. This exercises JNI and Conscrypt, but
does **not** install the application's Network Security Config provider. On
API 24+ the runner also installs a temporary APK and runs instrumentation for
NSC domain anchors, matching/mismatching pins, and duplicated extra anchors.
The APK is uninstalled after the run; an existing package is never replaced.
User-installed CA opt-in is not covered (the tests do not change device trust).

```sh
just test-android                      # every suite
just test-android platform_verifier    # tests whose `suite::test` name contains this
just test-android tls                  # Boring, rustls and relay platform handshakes
just test-android revocation           # intermediate anchors and signed staples
just test-android nsc                  # APK-only Network Security Config tests
```

The runner (`run.sh`) builds this crate for the attached device, compiles the
Java entry point to a `.dex`, pushes both and runs them. Without an attached
device it boots (and on first use creates) the `rama-android-tests` emulator.
Set `ANDROID_SERIAL` to select a device when more than one is attached. Only an
emulator started by this invocation is stopped on exit, including failed boots;
readiness has a 180-second deadline. `RAMA_ANDROID_PORT` selects its console port
(default 5580). Filters accept letters, digits, underscores and colons.

`CARGO_TARGET_DIR` is honored explicitly for both building and selecting the
library to push, avoiding stale artifacts in the project's default target dir.

Requirements: an Android SDK with `platform-tools`, `emulator`, `build-tools`,
an NDK and a system image, plus a JDK. On macOS:

```sh
brew install openjdk@21 android-commandlinetools
sdkmanager --licenses
sdkmanager "platform-tools" "emulator" "platforms;android-34" "build-tools;35.0.0" "ndk;27.2.12479018" \
    "system-images;android-34;google_apis;arm64-v8a"
```

`ANDROID_HOME`, `ANDROID_NDK_HOME` and `JAVA_HOME` are found automatically in
the usual locations, or can be set. CI runs the suites daily on API 23 and 34
(`CI-platforms-daily.yml`).

## Adding a suite

1. Add a module under `src/` exposing `pub(crate) static TESTS: &[Test]`,
   each test a `fn() -> Result<(), String>`.
2. Register it in `SUITES` in `src/lib.rs`.

Tests run on a plain native thread, as rama's own code does on Android;
anything that needs the JVM attaches through `ndk-context`, which the library
initializes when loaded.

The native suites check both TLS backends and the Boring relay against Android
trust, including a server that omits a denied root. On API 24+ they check GOOD,
REVOKED and malformed staples with an explicitly trusted intermediate, both
alone and alongside its root. API 23 retains its documented absence of the
supplementary revocation check. The NSC certificate fixtures expire in 2056;
they contain public certificates only, with the root key pin recorded in XML.
On-device tests do not currently cover network revocation fetches, APEX root
classification, user-CA installation, or delegated OCSP responder certificates.
