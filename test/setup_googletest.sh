#!/bin/bash

set -e  # Exit on any error

# Default values
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="https://github.com/google/googletest/archive/refs/heads/main.zip"
INCLUDE_DIR="$SCRIPT_ROOT/../include"
LIB_DIR="$SCRIPT_ROOT/../lib"
ZIP_PATH="$INCLUDE_DIR/googletest-main.zip"
GTEST_SRC_DIR="$INCLUDE_DIR/googletest-main"
BUILD_DIR="$GTEST_SRC_DIR/build_gcc"

echo "Using script root: $SCRIPT_ROOT"
echo "Include directory: $INCLUDE_DIR"

# Ensure include and lib directories exist
mkdir -p "$INCLUDE_DIR"
mkdir -p "$LIB_DIR"

# Check if gtest libs already exist
if [[ -f "$LIB_DIR/libgtest.a" && -f "$LIB_DIR/libgtest_main.a" ]]; then
    echo "gtest libraries already exist. Skipping download and build."
    exit 0
fi

# Download GoogleTest if needed
if [[ ! -f "$ZIP_PATH" ]]; then
    echo "Downloading GoogleTest to $ZIP_PATH ..."
    curl -L "$URL" -o "$ZIP_PATH"
else
    echo "GoogleTest zip already exists. Skipping download."
fi

# Extract if needed
if [[ ! -d "$GTEST_SRC_DIR" ]]; then
    echo "Extracting GoogleTest..."
    unzip -q "$ZIP_PATH" -d "$INCLUDE_DIR"
else
    echo "GoogleTest source already exists. Skipping extraction."
fi

# Build GoogleTest with GCC
echo "Building GoogleTest with GCC..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake .. -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles"
make

echo "Copying built libraries to $LIB_DIR..."
find . -name "libgtest*.a" -exec cp {} "$LIB_DIR" \;

# Copy headers
GTEST_INCLUDE_SRC="$GTEST_SRC_DIR/googletest/include"
if [[ -d "$GTEST_INCLUDE_SRC" ]]; then
    echo "Copying headers from $GTEST_INCLUDE_SRC to $INCLUDE_DIR..."
    cp -r "$GTEST_INCLUDE_SRC/"* "$INCLUDE_DIR/"
else
    echo "Warning: Include directory not found."
fi

# Cleanup
echo "Cleaning up..."
rm -f "$ZIP_PATH"
rm -rf "$GTEST_SRC_DIR"

echo "GoogleTest setup complete."
