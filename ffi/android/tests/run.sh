#!/usr/bin/env bash
# Build rama's on-device Android test suites and run them on an attached
# device or emulator, booting a local emulator when none is attached.
#
# Usage: run.sh [filter]
#
# Environment:
#   ANDROID_HOME       Android SDK (default: Homebrew or Android Studio location)
#   ANDROID_NDK_HOME   NDK (default: newest under $ANDROID_HOME/ndk)
#   RAMA_ANDROID_AVD   emulator to boot when no device is attached
#                      (default: rama-android-tests, created on first use)
#   RAMA_ANDROID_API   API level of that emulator's system image (default: 34)
set -euo pipefail

FILTER="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/target/android-tests"
REMOTE=/data/local/tmp/rama-android-tests
# The oldest release the suites target; also the NDK clang API level.
MIN_API=23

fail() {
    echo "android tests: $*" >&2
    exit 1
}

first_dir() {
    for dir in "$@"; do
        [[ -n "${dir}" && -d "${dir}" ]] && {
            echo "${dir}"
            return 0
        }
    done
    return 1
}

ANDROID_HOME="$(first_dir "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" \
    /opt/homebrew/share/android-commandlinetools "${HOME}/Library/Android/sdk" "${HOME}/Android/Sdk")" ||
    fail "no Android SDK found: set ANDROID_HOME"
export ANDROID_HOME

if ! java -version >/dev/null 2>&1; then
    JAVA_HOME="$(first_dir "${JAVA_HOME:-}" /opt/homebrew/opt/openjdk@21 /opt/homebrew/opt/openjdk)" ||
        fail "no Java runtime found: set JAVA_HOME"
    export JAVA_HOME
    export PATH="${JAVA_HOME}/bin:${PATH}"
fi

NDK="$(first_dir "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_LATEST_HOME:-}" \
    "$(ls -d "${ANDROID_HOME}"/ndk/* 2>/dev/null | sort -V | tail -1)")" ||
    fail "no Android NDK found: set ANDROID_NDK_HOME"
BUILD_TOOLS="$(ls -d "${ANDROID_HOME}"/build-tools/* 2>/dev/null | sort -V | tail -1)"
[[ -x "${BUILD_TOOLS}/d8" ]] || fail "no Android build-tools with d8 under ${ANDROID_HOME}"
ADB="${ANDROID_HOME}/platform-tools/adb"
[[ -x "${ADB}" ]] || fail "no adb: install the platform-tools package"

BOOTED_EMULATOR=""
cleanup() {
    if [[ -n "${BOOTED_EMULATOR}" ]]; then
        "${ADB}" -s "${BOOTED_EMULATOR}" emu kill >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if ! "${ADB}" get-state >/dev/null 2>&1; then
    AVD="${RAMA_ANDROID_AVD:-rama-android-tests}"
    EMULATOR="${ANDROID_HOME}/emulator/emulator"
    [[ -x "${EMULATOR}" ]] || fail "no device attached and no emulator installed"
    if ! "${EMULATOR}" -list-avds | grep -qx "${AVD}"; then
        case "$(uname -m)" in
            arm64 | aarch64) HOST_ABI=arm64-v8a ;;
            *) HOST_ABI=x86_64 ;;
        esac
        IMAGE="system-images;android-${RAMA_ANDROID_API:-34};google_apis;${HOST_ABI}"
        AVDMANAGER="$(command -v avdmanager || echo "${ANDROID_HOME}/cmdline-tools/latest/bin/avdmanager")"
        echo "android tests: creating emulator ${AVD} from ${IMAGE}"
        echo no | "${AVDMANAGER}" create avd --name "${AVD}" --package "${IMAGE}" >/dev/null
    fi
    echo "android tests: booting emulator ${AVD}"
    "${EMULATOR}" -avd "${AVD}" -no-window -no-audio -no-boot-anim -no-snapshot-save \
        >"${TMPDIR:-/tmp}/rama-android-emulator.log" 2>&1 &
    "${ADB}" wait-for-device
    BOOTED_EMULATOR="$("${ADB}" get-serialno)"
    for _ in $(seq 1 180); do
        [[ "$("${ADB}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]] && break
        sleep 1
    done
    [[ "$("${ADB}" shell getprop sys.boot_completed | tr -d '\r')" == 1 ]] ||
        fail "emulator did not finish booting"
fi

ABI="$("${ADB}" shell getprop ro.product.cpu.abi | tr -d '\r')"
case "${ABI}" in
    arm64-v8a) TARGET=aarch64-linux-android ;;
    x86_64) TARGET=x86_64-linux-android ;;
    *) fail "unsupported device ABI ${ABI}" ;;
esac
DEVICE_API="$("${ADB}" shell getprop ro.build.version.sdk | tr -d '\r')"
echo "android tests: ${TARGET} on API ${DEVICE_API}"

case "$(uname -s)" in
    Darwin) HOST_TAG=darwin-x86_64 ;;
    *) HOST_TAG=linux-x86_64 ;;
esac
TOOLCHAIN="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}/bin"
TARGET_UPPER="$(echo "${TARGET}" | tr '[:lower:]-' '[:upper:]_')"
TARGET_LOWER="$(echo "${TARGET}" | tr '-' '_')"
export "CARGO_TARGET_${TARGET_UPPER}_LINKER=${TOOLCHAIN}/${TARGET}${MIN_API}-clang"
export "CC_${TARGET_LOWER}=${TOOLCHAIN}/${TARGET}${MIN_API}-clang"
export "AR_${TARGET_LOWER}=${TOOLCHAIN}/llvm-ar"

rustup target add "${TARGET}" >/dev/null 2>&1 || true
cargo build --release --locked --manifest-path "${HERE}/Cargo.toml" --target "${TARGET}"
LIBRARY="${HERE}/target/${TARGET}/release/librama_android_tests.so"

rm -rf "${OUT}" && mkdir -p "${OUT}/classes"
javac --release 8 -Xlint:-options -d "${OUT}/classes" \
    "${HERE}/java/org/ramaproxy/tests/RamaAndroidTests.java"
"${BUILD_TOOLS}/d8" --min-api "${MIN_API}" --output "${OUT}" \
    "${OUT}/classes/org/ramaproxy/tests/RamaAndroidTests.class"

"${ADB}" shell rm -rf "${REMOTE}" >/dev/null
"${ADB}" shell mkdir -p "${REMOTE}" >/dev/null
"${ADB}" push "${LIBRARY}" "${REMOTE}/librama_android_tests.so" >/dev/null
"${ADB}" push "${OUT}/classes.dex" "${REMOTE}/classes.dex" >/dev/null

OUTPUT="$("${ADB}" shell "CLASSPATH=${REMOTE}/classes.dex app_process ${REMOTE} \
    org.ramaproxy.tests.RamaAndroidTests ${REMOTE}/librama_android_tests.so '${FILTER}'" 2>&1 | tr -d '\r')" || true
echo "${OUTPUT}"
grep -qx "RAMA_ANDROID_TESTS=PASS" <<<"${OUTPUT}" || fail "on-device tests failed"
