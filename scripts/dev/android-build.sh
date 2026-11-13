#!/bin/sh
# Build or test the Android collector (android/) with the toolchain this
# machine has: Homebrew OpenJDK 17 — Gradle 8.9 cannot run on Android
# Studio's bundled JBR (25) — and the Android SDK under
# ~/Library/Android/sdk. Usage: scripts/dev/android-build.sh <gradle task>...
set -e
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home}"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
cd "$(dirname "$0")/../../android"
exec ./gradlew "$@"
