# Examples

Both sample apps use the **test key** from `vectors/test-key.json`. Its private half is in this repository, so
anyone who can read the repository can read logs written by them. They show this on screen. A real app ships its own
public key (see "Keys and the CLI" in the main README).

## iOS: `ios/Example`

A SwiftUI app that depends on the package in this repository by path. Buttons log at info, warning and error level
through `CipherLogger`, export the armored support bundle (shared with `ShareLink` and `CipherLogExport`) and wipe.

The Xcode project is generated with [XcodeGen](https://github.com/yonaskolb/XcodeGen) and is not checked in:

```sh
cd ios/Example
xcodegen generate
xcodebuild -project CipherLogExample.xcodeproj -scheme CipherLogExample \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
```

Or open `CipherLogExample.xcodeproj` in Xcode and run it on a simulator.

## Android: `android/sample`

A plain-Views Java app in the Gradle build under `android/`. `SampleApp` calls `CipherLog.start` with the test key;
buttons log at info, warning and error level through the `CipherLog` facade and send the armored bundle with
`CipherLog.shareIntent` (through the library's own read-only content provider).

```sh
cd android
./gradlew :sample:assembleDebug     # android/sample/build/outputs/apk/debug/sample-debug.apk
```

## Reading what they wrote

Export a bundle from either app, copy it to your computer and open it with the test key:

```sh
cd cli && cargo run --release -- open ../cipherlog-20261126-1007.cipherlogs.txt --key ../vectors/test-key.json
```

## Sample files: `vectors/samples/<impl>/`

Each implementation writes real files from its tests, encrypted to the test key with a deterministic clock:

| File | What |
|---|---|
| `sample.cipherlog` | a closed file (ends with a `final` record): device block with one collector, all six levels, unicode, escaped newlines and replaced control characters |
| `expected.txt` | the exact text a reader must produce for `sample.cipherlog` |
| `unclosed.cipherlog`, `unclosed.expected.txt` | a file without `final` (as after a crash) and its text |
| `sample.cipherlogs` | a bundle of the two files |
| `sample.cipherlogs.txt` | the same bundle armored (SPEC.md 4.1); written by the current implementations only |

`cli` (TypeScript) and `kotlin` come from the retired first implementations. They never change and stay as fixtures:
every current implementation must keep opening them.

Every implementation's tests open every `vectors/samples/*/` directory and compare text and closed status. To rewrite
one implementation's samples:

```sh
CIPHERLOG_WRITE_SAMPLES=1 swift test                                                          # swift
cd cli && cargo run --example make_samples                                                    # rust
cd android && CIPHERLOG_WRITE_SAMPLES=1 ./gradlew :cipherlog-core:test --tests '*SamplesTest*'  # java
```

The files differ on every run (random file keys), so rewrite them only when the format or the sample text changes.
