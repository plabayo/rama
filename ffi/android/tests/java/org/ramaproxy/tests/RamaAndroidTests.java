package org.ramaproxy.tests;

/**
 * Entry point for rama's on-device test suites, started with {@code app_process}.
 *
 * <p>Arguments: the path of the native test library, then an optional test filter.
 */
public final class RamaAndroidTests {
    private static native int run(String filter);

    public static void main(String[] args) {
        System.load(args[0]);
        int failed = run(args.length > 1 ? args[1] : "");
        // adb does not report exit codes on every Android release: print a verdict too.
        System.out.println(failed == 0 ? "RAMA_ANDROID_TESTS=PASS" : "RAMA_ANDROID_TESTS=FAIL");
        System.exit(failed == 0 ? 0 : 1);
    }
}
