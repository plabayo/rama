#!/usr/bin/env bash
# Internal runner invoked by run.sh once its device and native build are ready.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADB="$1"
SERIAL="$2"
BUILD_TOOLS="$3"
ANDROID_JAR="$4"
LIBRARY="$5"
ABI="$6"
CXX_SHARED="$8"
OUT="$7/apk"
PACKAGE=org.ramaproxy.tests.trust
adb_device() { "${ADB}" -s "${SERIAL}" "$@"; }
[[ -f "${ANDROID_JAR}" ]] || { echo "NSC tests require platforms;android-34 in the SDK" >&2; exit 1; }
if adb_device shell pm path "${PACKAGE}" | grep -q '^package:'; then
    echo "Refusing to replace existing ${PACKAGE}; uninstall that test package before running" >&2
    exit 1
fi
mkdir -p "${OUT}/classes" "${OUT}/payload/lib/${ABI}"
"${BUILD_TOOLS}/aapt2" compile --dir "${HERE}/apk/res" -o "${OUT}/resources.zip"
"${BUILD_TOOLS}/aapt2" link -I "${ANDROID_JAR}" --manifest "${HERE}/apk/AndroidManifest.xml" \
    --min-sdk-version 23 --target-sdk-version 34 -o "${OUT}/unsigned.apk" "${OUT}/resources.zip"
javac --release 8 -Xlint:-options -classpath "${ANDROID_JAR}" -d "${OUT}/classes" \
    "${HERE}/java/org/ramaproxy/tests/RamaAndroidTests.java" \
    "${HERE}/java/org/ramaproxy/tests/RamaTrustInstrumentation.java"
"${BUILD_TOOLS}/d8" --min-api 23 --lib "${ANDROID_JAR}" --output "${OUT}/payload" \
    "${OUT}/classes/org/ramaproxy/tests/RamaAndroidTests.class" \
    "${OUT}/classes/org/ramaproxy/tests/RamaTrustInstrumentation.class"
cp "${LIBRARY}" "${OUT}/payload/lib/${ABI}/librama_android_tests.so"
cp "${CXX_SHARED}" "${OUT}/payload/lib/${ABI}/libc++_shared.so"
(cd "${OUT}/payload" && zip -q -r "${OUT}/unsigned.apk" classes.dex lib)
"${BUILD_TOOLS}/zipalign" -f 4 "${OUT}/unsigned.apk" "${OUT}/aligned.apk"
if [[ ! -f "${OUT}/test.keystore" ]]; then
    keytool -genkeypair -keystore "${OUT}/test.keystore" -storepass android -keypass android \
        -alias test -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=Rama Android tests" >/dev/null 2>&1
fi
"${BUILD_TOOLS}/apksigner" sign --ks "${OUT}/test.keystore" --ks-pass pass:android \
    --out "${OUT}/tests.apk" "${OUT}/aligned.apk"
INSTALLED=false
cleanup() { if [[ "${INSTALLED}" == true ]]; then adb_device uninstall "${PACKAGE}" >/dev/null || true; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
adb_device install "${OUT}/tests.apk" >/dev/null
INSTALLED=true
RESULT="$(adb_device shell am instrument -w "${PACKAGE}/org.ramaproxy.tests.RamaTrustInstrumentation" | tr -d '\r')"
echo "${RESULT}"
grep -qx 'INSTRUMENTATION_RESULT: rama_result=PASS' <<<"${RESULT}"
