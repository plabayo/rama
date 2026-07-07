#!/bin/bash

# Install the rama binary from a GitHub release.
#
# Usage:
#   install.sh                    latest stable release (default)
#   install.sh --pre              latest release, pre-releases included
#   install.sh --version 0.3.0    a specific version (bare version or full tag)
#
# When piping (curl ... | bash), pass flags as: bash -s -- --pre

usage() {
    echo "Usage: install.sh [--pre] [--version <version>]"
    echo "  --pre                latest release, pre-releases included"
    echo "  --version <version>  specific version, e.g. 0.3.0 or rama-0.3.0"
}

include_prereleases=false
requested_version=""

while [ $# -gt 0 ]; do
    case "$1" in
        --pre|--prerelease) include_prereleases=true ;;
        --version|-v)
            shift
            requested_version="${1:-}"
            if [ -z "$requested_version" ]; then
                echo "--version requires an argument"
                usage
                exit 1
            fi
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

# Resolve the release tag
if [ -n "$requested_version" ]; then
    case "$requested_version" in
        rama-*) tag="$requested_version" ;;
        *) tag="rama-$requested_version" ;;
    esac
    if ! curl --silent --fail "https://api.github.com/repos/plabayo/rama/releases/tags/$tag" > /dev/null; then
        echo "No release found for version: $requested_version (tag: $tag)"
        exit 1
    fi
elif [ "$include_prereleases" = true ]; then
    tag=$(jq -r 'first | .tag_name' <<< $(curl --silent https://api.github.com/repos/plabayo/rama/releases))
else
    tag=$(jq -r 'map(select(.prerelease|not)) | first | .tag_name' <<< $(curl --silent https://api.github.com/repos/plabayo/rama/releases))
fi

if [ -z "$tag" ] || [ "$tag" = "null" ]; then
    echo "Could not resolve a release tag."
    exit 1
fi

echo "Installing rama release: $tag"

# Get system architecture and OS
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Select the appropriate filename based on the system architecture and OS
case "$ARCH-$OS" in
    "aarch64-darwin") FILENAME="rama.aarch64-apple-darwin.tar.xz" ;;
    "arm64-darwin") FILENAME="rama.aarch64-apple-darwin.tar.xz" ;;
    "aarch64-linux") FILENAME="rama.aarch64-unknown-linux-gnu.tar.xz" ;;
    "arm-linux") echo "ARMv6 Linux binaries are not published."; exit 1 ;;
    "armv7l-linux") FILENAME="rama.armv7-unknown-linux-gnueabihf.tar.xz" ;;
    "i686-linux") echo "i686 Linux binaries are not published."; exit 1 ;;
    "x86_64-darwin") FILENAME="rama.x86_64-apple-darwin.tar.xz" ;;
    "x86_64-linux") FILENAME="rama.x86_64-unknown-linux-musl.tar.xz" ;;
    *) echo "Unknown system architecture: $ARCH-$OS"; exit 1 ;;
esac

SHA256_FILENAME="$FILENAME.sha256"

# Construct the download URLs
download_url="https://github.com/plabayo/rama/releases/download/$tag/$FILENAME"
sha256_url="https://github.com/plabayo/rama/releases/download/$tag/$SHA256_FILENAME"

echo "Download URL: $download_url"
echo "SHA256 URL: $sha256_url"
if [ -z "$download_url" ]; then
    echo "Could not find a suitable package for your system architecture."
    exit 1
fi

# Download the binary package and its SHA256 checksum
curl -L -o $FILENAME $download_url
curl -L -o $SHA256_FILENAME $sha256_url

echo "Download complete: $FILENAME"

if [[ "$OS" == "darwin" ]]; then
    computed_sha256=$(shasum -a 256 $FILENAME | cut -d' ' -f1)
else
    computed_sha256=$(sha256sum $FILENAME | cut -d' ' -f1)
fi

expected_sha256=$(cat $SHA256_FILENAME | cut -d' ' -f1)

if [ "$computed_sha256" != "$expected_sha256" ]; then
    echo "SHA256 checksum verification failed!"
    echo "Expected: $expected_sha256"
    echo "Got: $computed_sha256"
    rm -f $FILENAME $SHA256_FILENAME
    exit 1
fi

echo "SHA256 checksum verified successfully as $computed_sha256"

# Extract the binary package
tar -xJf $FILENAME
rm -f $FILENAME $SHA256_FILENAME

echo "Extraction complete: $FILENAME"

# Move the extracted files to the installation path
# Assuming the binary file is named `rama`
sudo mv rama /usr/local/bin/rama
echo "Installation complete: /usr/local/bin/rama"
