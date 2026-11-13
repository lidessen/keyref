#!/bin/sh
# Build or test the Android collector (android/). Prefers Android Studio's
# bundled JDK 25 for JAVA_HOME — Gradle 9.9.1 runs on Java 17–27 — and falls
# back to a Homebrew LTS JDK when Studio is not installed. The Android SDK
# defaults to ~/Library/Android/sdk. Usage: scripts/dev/android-build.sh <gradle task>...
set -e
if [ -z "${JAVA_HOME:-}" ]; then
  if [ -x "/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/java" ]; then
    JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
  else
    JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
  fi
fi
export JAVA_HOME
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
if [ ! -x "$JAVA_HOME/bin/java" ]; then
  echo "android-build.sh: no JDK at $JAVA_HOME (set JAVA_HOME, or install Android Studio / 'brew install openjdk@21')" >&2
  exit 1
fi
cd "$(dirname "$0")/../../android"
exec ./gradlew "$@"
