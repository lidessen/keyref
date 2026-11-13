# keyref source (the Android verification-code collector)

The `kind = source` device of design.md v0.8 §14: it reads the phone's own SMS, picks out verification codes with the phone's own filter rules, **encrypts them at the moment they arrive** (the envelope is addressed directly to the active owner plus any decider with a valid delegation, §14.3), and tops up the upload to the keyref server through a WorkManager queue. It only uploads and never reads — it does not even hold item keys (§14.2).

## Build

1. Open this directory with Android Studio (it bundles its own JDK/SDK) via `File → Open`, and wait for the Gradle sync.
2. Run it on a test device, or `Build → Build APK(s)` to produce a sideloadable APK.

This machine (the macOS dev box) has no Android build environment, so this code has never been compiled here — send sync or compile errors straight to the maintainer.

## Use

1. **Open the app once after installing** (the system does not deliver broadcasts to an app that has never been launched).
2. Grant the SMS permission and add the app to the battery-optimisation allowlist.
3. Enter the server address → 「生成配对二维码」 → scan it with the paired iOS keyref app (the QR code carries `t=source`, §9.1 v1.2). The confirmation page states that it can only upload SMS.
4. Add a sender-number allowlist → switch collection on.

The collection rule (design §14.2): the sender number must hit the allowlist **and** the body must contain a 4–8 digit code pattern. An empty allowlist collects nothing. The rules stay on the phone — a source device cannot decrypt any ciphertext, so there is nowhere for the rules to be encrypted and synced to.

## Implementation notes

- **The HPKE interop surface**: `crypto/Envelope.kt` isolates BouncyCastle's RFC 9180 implementation (DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM). It has to interoperate byte for byte with `proto/crypto` (circl) — the cross-language golden vectors of design §9.2 are the admission gate, so run the vectors before wiring this up to iOS.
- **Transcripts**: `crypto/Transcripts.kt` implements §3.5 / §3.6 / §3.9 / §3.3 byte for byte; directory parsing uses the same strategy as the CLI's `audit.parseDirectory` (fixed length + rebuild comparison, fail-closed).
- **Private key at rest**: AndroidKeyStore does not support X25519 / Ed25519 (already stated in design §14.2), so the private key is encrypted with an AES-GCM key inside the Keystore and stored in a private file. Losing the device means revoking and pairing again — it never reads anything anyway.
- **Queue**: the envelope is sealed and written to disk the moment the SMS arrives (the ciphertext lands locally first), and WorkManager tops the upload up with exponential backoff; a 401 retries once after renewing the session; quota-type 4xx responses are dropped and logged.

## Known boundaries

- The iOS inbox, approval screen and decider management (design §14.4, and the iOS side of §14.8) are implemented on the iOS side now, so a message uploaded by this app has a consumer — but this app itself has never been run against a real server, because it has never been compiled.
- The BC ↔ circl interop vectors have not been generated or checked yet (the outstanding task from design §9.2).
