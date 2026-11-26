# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org); the file format has
its own version (`cipherlog-v1`, see [SPEC.md](SPEC.md)). Tags have no `v` prefix (`0.1.0-alpha.1`), as Swift Package
Manager and CocoaPods expect.

## [0.1.0-alpha.1] - 2026-11-26

First alpha. The `cipherlog-v1` file format is fixed; the APIs may still change before `0.1.0`.

### Added

- `cipherlog-v1` file format ([SPEC.md](SPEC.md)): a 118-byte HPKE header (X25519, HKDF-SHA256, ChaCha20-Poly1305)
  carrying a random per-file key, ChaCha20-Poly1305 records bound to file, position and flags, one raw deflate stream
  per file, `CPB1` bundles and armored bundles (`*.cipherlogs.txt`) for mail.
- Key strings `cipherlog-pub-v1:…` and `cipherlog-priv-v1:…`, checked at start with errors that name the problem and
  never repeat a private key.
- Swift package and pod `CipherLog` (iOS 17+, macOS 14+, no dependencies):
  - `CipherLog.start(key:appGroup:)` once per process, with process detection for app extensions;
  - `CipherLogger`, a drop-in for `os.Logger` (levels, `privacy:`, `format:`, `align:`), forwarding to `os.Logger`;
  - `CipherLogExport` for `ShareLink`, armored by default, and `exportBundle(armored:)`;
  - default collectors: app version and install source, OS and model, locale, rounded free space.
- Android library `com.rebels11:cipherlog` (AAR, API 23+, Java, Tink only) and the plain JVM jar
  `com.rebels11:cipherlog-core`:
  - `CipherLog.start(context, key)` in `Application.onCreate`, a static facade that mirrors `android.util.Log` (Logcat
    and the file);
  - `CipherLog.shareIntent(context, email, subject)` through the library's own read-only content provider;
  - default collectors as on iOS.
- Writer behaviour on both platforms: a background worker, flush after 100 ms or at once for warnings, rotation at
  256 KiB, 2 MiB per process, wipe, a support export of up to 4 MiB, crash bundles (`recentBundle`,
  `previousRunBundle`), `scrub`, and turning itself off with one diagnostics line on disk full or a write or crypto
  error.
- Six optional device collectors on both platforms, not in the defaults: `versionHistory` (versions first seen on the
  device), `installDates`, `memory`, `screen`, `network` (connection type only) and `storageUsage` (sizes of the app's
  own folders, capped walk). iOS: `CipherLogCollector.optional()`; Android: `OptionalCollectors.all(context)` (or
  `all(context, logDirectory)` with a custom log directory).
- A warning in the system log and in diagnostics when a release build starts with the published test key.
- CLI `cipherlog` in Rust: `keygen` (to a 0600 file, or into 1Password through `op` on stdin), `keyid`, `open` (files,
  bundles and armored bundles, several keys, `op://` references, capped output, escaped names), `write`. Prebuilt
  binaries for macOS and Linux (arm64 and x86_64) and a Homebrew tap in this repository.
- Shared vectors: test key, byte-exact records with rejection reasons, key strings, armor cases and real files from
  every implementation, which every other implementation must open.

- A privacy manifest (`PrivacyInfo.xcprivacy`, in the Swift package and the pod) for the file-timestamp, disk-space
  and user-defaults APIs the library calls, and R8 rules inside the Android artifacts, so a minified release needs nothing extra.

### Notes

- Releases are started by hand on `main` (`release.yml`); the tag is created only after every test passed.
- The first Kotlin library and TypeScript CLI were replaced by the Java library and the Rust CLI before this release.
  Their sample files stay in `vectors/samples/` as fixtures.
- CocoaPods trunk becomes read-only on 2 December 2026. Versions after that are published for Swift Package Manager
  only.

[0.1.0-alpha.1]: https://github.com/rebels-eleven/cipherlog/releases/tag/0.1.0-alpha.1
