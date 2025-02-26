#!/bin/bash

: ${root=$(pwd)}
: ${tag=latest}
: ${os=linux}
: ${name=rama}

# Function to print colored text based on log level
log() {
  local level=$1
  local message=$2
  local NC='\033[0m' # Reset to default color

  case "$level" in
  "info")
    echo -e "\033[0;32m[INFO] $message${NC}" # Green for INFO
    ;;
  "warning")
    echo -e "\033[0;33m[WARNING] $message${NC}" # Yellow for WARNING
    ;;
  "error")
    echo -e "\033[0;31m[ERROR] $message${NC}" # Red for ERROR
    ;;
  *)
    echo "$message" # Default to printing message without color for other levels
    ;;
  esac
}

[ ! -d target ] && mkdir target

# Build support paltform target
# 1. Linux
linux_target=(
  "x86_64-unknown-linux-gnu:mimalloc"
  "aarch64-unknown-linux-gnu:mimalloc"
  "armv7-unknown-linux-gnueabihf:jemalloc"
  "arm-unknown-linux-gnueabi:jemalloc"
  "i686-unknown-linux-gnu:jemalloc"
)

# 2. MacOS
macos_target=(
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

# 3. Windows
windows_target=(
  "x86_64-pc-windows-gnu"
  "i686-pc-windows-gnu"
)

# Check linux rustup target installed
check_linux_rustup_target_installed() {
  for target in ${linux_target[@]}; do
    target=$(echo $target | cut -d':' -f1)
    installed=$(rustup target list | grep "${target} (installed)")
    if [ -z "$installed" ]; then
      log "info" "Installing ${target}..."
      rustup target add ${target}
    fi
  done
}

# Check macos rustup target installed
check_macos_rustup_target_installed() {
  for target in ${macos_target[@]}; do
    installed=$(rustup target list | grep "${target} (installed)")
    if [ -z "$installed" ]; then
      log "info" "Installing ${target}..."
      rustup target add ${target}
    fi
  done
}

# Check windows rustup target installed
check_windows_rustup_target_installed() {
  for target in ${windows_target[@]}; do
    installed=$(rustup target list | grep "${target} (installed)")
    if [ -z "$installed" ]; then
      log "info" "Installing ${target}..."
      rustup target add ${target}
    fi
  done
}

# Build linux target
build_linux_target() {
  for target in "${linux_target[@]}"; do
    build_target=$(echo $target | cut -d':' -f1)
    feature=$(echo $target | cut -d':' -f2)
    log "info" "Building ${target}..."
    if cargo zigbuild --release -p rama-cli --target "${build_target}" --features "${feature}"; then
      compress_and_move $build_target
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# Build macos target
build_macos_target() {
  for target in "${macos_target[@]}"; do
    log "info" "Building ${target}..."
    if CARGO_PROFILE_RELEASE_STRIP=none cargo zigbuild --release -p rama-cli --target "${target}"; then
      compress_and_move $target
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# Build windows target
build_windows_target() {
  for target in "${windows_target[@]}"; do
    log "info" "Building ${target}..."
    if cargo build --release -p rama-cli --target "${target}"; then
      compress_and_move $target
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# upx and move target
compress_and_move() {
  build_target=$1
  target_dir="target/${build_target}/release"
  bin_name=$name
  if [[ $build_target == *windows* ]]; then
    bin_name="${name}.exe"
  fi
  upx "${target_dir}/${bin_name}"
  chmod +x "${target_dir}/${bin_name}"
  cd "${target_dir}"
  tar czvf $name-$tag-${build_target}.tar.gz $bin_name
  shasum -a 256 $name-$tag-${build_target}.tar.gz >$name-$tag-${build_target}.tar.gz.sha256
  mv $name-$tag-${build_target}.tar.gz $root/target/
  mv $name-$tag-${build_target}.tar.gz.sha256 $root/target/
  cd -
}

# Execute
if [ "$os" == "linux" ]; then
  log "info" "Building linux target..."
  check_linux_rustup_target_installed
  build_linux_target
elif [ "$os" == "macos" ]; then
  log "info" "Building macos target..."
  check_macos_rustup_target_installed
  build_macos_target
elif [ "$os" == "windows" ]; then
  log "info" "Building windows target..."
  check_windows_rustup_target_installed
  build_windows_target
else
  log "error" "Unsupported os: ${os}"
  exit 1
fi
