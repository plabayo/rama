# rama on-device Android tests

Test suites that need a real Android runtime, such as code calling the Android
framework through JNI. They run inside an Android runtime started with
`app_process`, without an app or APK.

```sh
just test-android                      # every suite
just test-android platform_verifier    # tests whose `suite::test` name contains this
```

The runner (`run.sh`) builds this crate for the attached device, compiles the
Java entry point to a `.dex`, pushes both and runs them. Without an attached
device it boots (and on first use creates) the `rama-android-tests` emulator.

Requirements: an Android SDK with `platform-tools`, `emulator`, `build-tools`,
an NDK and a system image, plus a JDK. On macOS:

```sh
brew install openjdk@21 android-commandlinetools
sdkmanager --licenses
sdkmanager "platform-tools" "emulator" "build-tools;35.0.0" "ndk;27.2.12479018" \
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
