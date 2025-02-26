#!/bin/bash

# Fetch the latest release information
tag=$(jq -r 'map(select(.prerelease)) | first | .tag_name' <<< $(curl --silent https://api.github.com/repos/plabayo/rama/releases))
version=${tag#v}

# Get system architecture and OS
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Select the appropriate filename based on the system architecture and OS
case "$ARCH-$OS" in
    "aarch64-darwin") FILENAME="rama-aarch64-apple-darwin.tar.gz" ;;
    "arm64-darwin") FILENAME="rama-aarch64-apple-darwin.tar.gz" ;;
    # "aarch64-linux") FILENAME="rama-aarch64-unknown-linux-musl.tar.gz" ;;
    # "arm-linux") FILENAME="rama-arm-unknown-linux-musleabihf.tar.gz" ;;
    # "armv7l-linux") FILENAME="rama-armv7-unknown-linux-musleabihf.tar.gz" ;;
    # "i686-windows") FILENAME="rama-i686-pc-windows-gnu.tar.gz" ;;
    # "i686-linux") FILENAME="rama-i686-unknown-linux-musl.tar.gz" ;;
    "x86_64-darwin") FILENAME="rama-x86_64-apple-darwin.tar.gz" ;;
    # "x86_64-windows") FILENAME="rama-x86_64-pc-windows-gnu.tar.gz" ;;
    # "x86_64-linux") FILENAME="rama-x86_64-unknown-linux-musl.tar.gz" ;;
    *) echo "Unknown system architecture: $ARCH-$OS"; exit 1 ;;
esac

# Construct the download URL
download_url="https://github.com/plabayo/rama/releases/download/$tag/$FILENAME"

echo "Download URL: $download_url"

if [ -z "$download_url" ]; then
    echo "Could not find a suitable package for your system architecture."
    exit 1
fi

# Download the binary package
curl -L -o $FILENAME $download_url

echo "Download complete: $FILENAME"

# Extract the binary package
tar -xzf $FILENAME
rm -rf $FILENAME

echo "Extraction complete: $FILENAME"

# Move the extracted files to the installation path
# Assuming the binary file is named `rama`
sudo mv rama /usr/local/bin/rama
echo "Installation complete: /usr/local/bin/rama"
