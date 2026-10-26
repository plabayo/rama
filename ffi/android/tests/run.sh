#!/usr/bin/env bash
# Build rama's on-device Android test suites and run them on an attached
# device or emulator, booting a local emulator when none is attached.
#
# Usage: run.sh [filter]
#
# Environment:
#   ANDROID_HOME       Android SDK (default: Homebrew or Android Studio location)
#   ANDROID_SERIAL     device to use (required when more than one is attached)
#   RAMA_ANDROID_PORT  console port for an emulator started here (default: 5580)
#   CARGO_TARGET_DIR   build artifacts (default: this project's target directory)
#   ANDROID_NDK_HOME   NDK (default: newest under $ANDROID_HOME/ndk)
#   RAMA_ANDROID_AVD   emulator to boot when no device is attached
#                      (default: rama-android-tests, created on first use)
#   RAMA_ANDROID_API   API level of that emulator's system image (default: 34)
set -euo pipefail

FILTER="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_TARGET="${CARGO_TARGET_DIR:-${HERE}/target}"
mkdir -p "${BUILD_TARGET}"
BUILD_TARGET="$(cd "${BUILD_TARGET}" && pwd)"
OUT="${BUILD_TARGET}/android-tests"
REMOTE=/data/local/tmp/rama-android-tests
# The oldest release the suites target; also the NDK clang API level.
MIN_API=23

fail() {
    echo "android tests: $*" >&2
    exit 1
}

# The filter is embedded in an Android shell command below.
[[ "${FILTER}" =~ ^[a-zA-Z0-9_:]*$ ]] || fail "filter may contain only letters, digits, underscores and colons"

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
export ANDROID_NDK_HOME="${NDK}"
BUILD_TOOLS="$(ls -d "${ANDROID_HOME}"/build-tools/* 2>/dev/null | sort -V | tail -1)"
[[ -x "${BUILD_TOOLS}/d8" ]] || fail "no Android build-tools with d8 under ${ANDROID_HOME}"
ADB="${ANDROID_HOME}/platform-tools/adb"
[[ -x "${ADB}" ]] || fail "no adb: install the platform-tools package"

EMULATOR_PID=""
cleanup() {
    # Only terminate the process started by this invocation, including a boot
    # that failed before adb connected. Never stop an existing device.
    if [[ -n "${EMULATOR_PID}" ]]; then
        kill "${EMULATOR_PID}" >/dev/null 2>&1 || true
        wait "${EMULATOR_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

SERIAL="${ANDROID_SERIAL:-}"
DEVICES=()
while read -r serial state rest; do
    [[ -z "${serial}" || "${serial}" == List || "${serial}" == \* ]] && continue
    DEVICES+=("${serial}")
done < <("${ADB}" devices)
if [[ -z "${SERIAL}" ]]; then
    case "${#DEVICES[@]}" in
        0) ;;
        1) SERIAL="${DEVICES[0]}" ;;
        *) fail "several devices attached: select one with ANDROID_SERIAL" ;;
    esac
fi

if [[ -z "${SERIAL}" ]]; then
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
    PORT="${RAMA_ANDROID_PORT:-5580}"
    [[ "${PORT}" =~ ^[0-9]+$ ]] && ((PORT >= 5554 && PORT <= 5682 && PORT % 2 == 0)) ||
        fail "RAMA_ANDROID_PORT must be an even port between 5554 and 5682"
    SERIAL="emulator-${PORT}"
    mkdir -p "${OUT}"
    echo "android tests: booting emulator ${AVD} as ${SERIAL}"
    "${EMULATOR}" -avd "${AVD}" -port "${PORT}" -no-window -no-audio -no-boot-anim -no-snapshot-save \
        >"${OUT}/emulator.log" 2>&1 &
    EMULATOR_PID=$!
fi

adb_device() { "${ADB}" -s "${SERIAL}" "$@"; }
DEADLINE=$((SECONDS + 180))
while ((SECONDS < DEADLINE)); do
    if [[ -n "${EMULATOR_PID}" ]] && ! kill -0 "${EMULATOR_PID}" 2>/dev/null; then
        fail "emulator exited before boot; see ${OUT}/emulator.log"
    fi
    if [[ "$(adb_device get-state 2>/dev/null || true)" == device ]] &&
        [[ "$(adb_device shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]]; then
        break
    fi
    sleep 1
done
((SECONDS < DEADLINE)) || fail "${SERIAL} did not finish booting within 180 seconds"

ABI="$(adb_device shell getprop ro.product.cpu.abi | tr -d '\r')"
case "${ABI}" in
    arm64-v8a) TARGET=aarch64-linux-android ;;
    x86_64) TARGET=x86_64-linux-android ;;
    *) fail "unsupported device ABI ${ABI}" ;;
esac
DEVICE_API="$(adb_device shell getprop ro.build.version.sdk | tr -d '\r')"
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
cargo build --release --locked --manifest-path "${HERE}/Cargo.toml" --target "${TARGET}" --target-dir "${BUILD_TARGET}"
LIBRARY="${BUILD_TARGET}/${TARGET}/release/librama_android_tests.so"
CXX_SHARED="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}/sysroot/usr/lib/${TARGET}/libc++_shared.so"

if [[ -z "${FILTER}" || "${FILTER}" != nsc* ]]; then
    rm -rf "${OUT}/classes" && mkdir -p "${OUT}/classes"
    javac --release 8 -Xlint:-options -d "${OUT}/classes" \
        "${HERE}/java/org/ramaproxy/tests/RamaAndroidTests.java"
    "${BUILD_TOOLS}/d8" --min-api "${MIN_API}" --output "${OUT}" \
        "${OUT}/classes/org/ramaproxy/tests/RamaAndroidTests.class"

    adb_device shell rm -rf "${REMOTE}" >/dev/null
    adb_device shell mkdir -p "${REMOTE}" >/dev/null
    adb_device push "${CXX_SHARED}" "${REMOTE}/libc++_shared.so" >/dev/null
    adb_device push "${LIBRARY}" "${REMOTE}/librama_android_tests.so" >/dev/null
    adb_device push "${OUT}/classes.dex" "${REMOTE}/classes.dex" >/dev/null

    OUTPUT="$(adb_device shell "CLASSPATH=${REMOTE}/classes.dex app_process ${REMOTE} \
        org.ramaproxy.tests.RamaAndroidTests ${REMOTE}/librama_android_tests.so '${FILTER}'" 2>&1 | tr -d '\r')" || true
    echo "${OUTPUT}"
    if ! grep -qx "RAMA_ANDROID_TESTS=PASS" <<<"${OUTPUT}"; then
        if [[ -n "${EMULATOR_PID}" ]]; then
            adb_device logcat -d -t 300 > "${OUT}/failure-logcat.txt" || true
            echo "android tests: emulator diagnostics at ${OUT}/failure-logcat.txt" >&2
        fi
        fail "on-device tests failed"
    fi
fi

if [[ -z "${FILTER}" || "${FILTER}" == nsc* ]]; then
    if ((DEVICE_API >= 24)); then
        bash "${HERE}/run-apk.sh" "${ADB}" "${SERIAL}" "${BUILD_TOOLS}" \
            "${ANDROID_HOME}/platforms/android-34/android.jar" "${LIBRARY}" "${ABI}" "${OUT}" "${CXX_SHARED}"
    else
        echo "NSC tests require API 24+; app_process suites cover API ${DEVICE_API}"
        [[ "${FILTER}" != nsc* ]] || exit 1
    fi
fi
