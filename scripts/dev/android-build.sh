#!/bin/sh
# Build or test the Android collector (android/) with the toolchain this
# machine has: Homebrew OpenJDK 21 — Gradle 8.9 supports Java ≤ 22 and
# rejects Android Studio's bundled JBR (25) — and the Android SDK under
# ~/Library/Android/sdk. Usage: scripts/dev/android-build.sh <gradle task>...
set -e
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
if [ ! -x "$JAVA_HOME/bin/java" ]; then
  echo "android-build.sh: no JDK at $JAVA_HOME (brew install openjdk@21)" >&2
  exit 1
fi
cd "$(dirname "$0")/../../android"
exec ./gradlew "$@"
