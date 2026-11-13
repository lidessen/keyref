# keyref source (the Android verification-code collector)

The `kind = source` device of design.md v0.8 §14: it reads the phone's own SMS, picks out verification codes with the phone's own filter rules, **encrypts them at the moment they arrive** (the envelope is addressed to the active owners — the owner backfills a decider's wrap later, §6.30 — and tops up the upload to the keyref server through a WorkManager queue). It only uploads and never reads — it does not even hold item keys (§14.2).

## Build

On the macOS dev box:

```sh
scripts/dev/android-build.sh assembleDebug       # debug APK (app/build/outputs/apk/debug/)
scripts/dev/android-build.sh testDebugUnitTest   # golden-vector gate (design §9.2)
scripts/dev/android-build.sh lintDebug           # must report 0 errors
```

The script prefers `JAVA_HOME` = Android Studio's bundled JDK 25 (Gradle 9.9.1 runs on Java 17–27) and falls back to a Homebrew LTS JDK; `ANDROID_HOME` defaults to `~/Library/Android/sdk`. It then runs the committed wrapper (Gradle 9.9.1, AGP 9.5.1 with built-in Kotlin 2.4.21, compileSdk 37) — AGP 9 compiles Kotlin itself, so there is no `kotlin-android` plugin. The host JDK only runs Gradle — the bytecode target stays `jvmTarget = 17` in `app/build.gradle.kts`. Opening this directory in Android Studio (`File → Open`, for device runs and `Build → Build APK(s)`) works alongside the CLI path.

## Use

1. **Open the app once after installing** (the system does not deliver broadcasts to an app that has never been launched).
2. Grant the SMS permission and add the app to the battery-optimisation allowlist.
3. Enter the server address → 「生成配对二维码」 → scan it with the paired iOS keyref app (the QR code carries `t=source`, §9.1 v1.2). The confirmation page states that it can only upload SMS.
4. Add a sender-number allowlist → switch collection on.

The collection rule (design §14.2): the sender number must hit the allowlist **and** the body must contain a 4–8 digit code pattern. An empty allowlist collects nothing. The rules stay on the phone — a source device cannot decrypt any ciphertext, so there is nowhere for the rules to be encrypted and synced to.

## Implementation notes

- **The HPKE interop surface**: `crypto/Envelope.kt` isolates BouncyCastle's RFC 9180 Base mode (DHKEM + HKDF-SHA256 + AES-256-GCM; the KEM follows the recipient's §1.4 key length — X25519 or P-256). It has to interoperate byte for byte with `proto/crypto` (circl), and `CryptoVectorsTest` asserts exactly that against the cross-language golden vectors of design §9.2 (`ios/Tests/KeyrefCoreTests/Fixtures/vectors.json`).
- **Transcripts**: `crypto/Transcripts.kt` implements §3.4 / §3.5 / §3.6 / §3.9 / §3.10 / §3.13 / §3.3 byte for byte — including the §3.13 pairing confirmation MAC the completion is checked against before the owner key is pinned; directory parsing uses the same strategy as the CLI's `audit.parseDirectory` (fixed length + rebuild comparison, fail-closed).
- **Private key at rest**: AndroidKeyStore does not support X25519 / Ed25519 (already stated in design §14.2), so the private key is encrypted with an AES-GCM key inside the Keystore and stored in a private file. Losing the device means revoking and pairing again — it never reads anything anyway.
- **Queue**: the envelope is sealed and written to disk the moment the SMS arrives (the ciphertext lands locally first). WorkManager tops the upload up with exponential backoff: network failures and 5xx retry with the entry still queued, a single 401 renews the session once, every other 4xx (quota, invalid request, revoked device) is dropped and logged.

## Known boundaries

- The iOS inbox, approval screen and decider management (design §14.4, and the iOS side of §14.8) are implemented on the iOS side now, so a message uploaded by this app has a consumer — but the pairing → seal → upload loop has not been watched end to end on a real phone yet (that needs a device and an iOS scan; the byte formats themselves are pinned by the vectors).
