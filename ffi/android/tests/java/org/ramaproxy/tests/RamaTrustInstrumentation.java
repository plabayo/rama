package org.ramaproxy.tests;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;

/** Runs inside an application process with its real Network Security Config. */
public final class RamaTrustInstrumentation extends Instrumentation {
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        int failed;
        try {
            System.loadLibrary("rama_android_tests");
            failed = RamaAndroidTests.runNetworkSecurityConfig();
            result.putString("rama_result", failed == 0 ? "PASS" : "FAIL: " + failed);
        } catch (Throwable error) {
            failed = 1;
            result.putString("rama_result", "FAIL: " + error);
        }
        finish(failed == 0 ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
    }
}
