#!/bin/sh
# Run Xcode build tools with the full Xcode toolchain (the machine's
# xcode-select points at CommandLineTools, which lacks xcodebuild).
# Usage: scripts/dev/xcodebuild.sh <xcodebuild args...>
export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
exec xcodebuild "$@"
