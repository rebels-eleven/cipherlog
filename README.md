# cipherlog

Mobile app logs that are encrypted the moment they are written, so only you can read them.

[![Maven Central](https://img.shields.io/maven-central/v/com.rebels11/cipherlog?label=Maven%20Central)](https://central.sonatype.com/artifact/com.rebels11/cipherlog)
[![CI](https://github.com/rebels-eleven/cipherlog/actions/workflows/ci.yml/badge.svg)](https://github.com/rebels-eleven/cipherlog/actions/workflows/ci.yml)
[![SwiftPM](https://img.shields.io/badge/SwiftPM-compatible-orange.svg)](https://swift.org/package-manager/)
[![CocoaPods](https://img.shields.io/cocoapods/v/CipherLog.svg)](https://cocoapods.org/pods/CipherLog)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

- [What is it](#what-is-it)
- [How it works](#how-it-works)
- [Threat model](#threat-model)
- [Quick start: iOS](#quick-start-ios)
- [Quick start: Android](#quick-start-android)
- [Keys and the CLI](#keys-and-the-cli)
- [Limits and failure behaviour](#limits-and-failure-behaviour)
- [Feedback](#feedback)
- [License](#license)

## What is it

Logs on a phone help most when something went wrong, and that is when plain-text logs hurt most: they end up in
backups, in support mail and in shared folders. cipherlog keeps detailed logs on the device without keeping readable
logs on the device.

Your app writes log lines as usual. cipherlog compresses them and encrypts them to your X25519 public key, which ships
inside the app. The app can append but cannot read what it wrote. A user sends you one file from a share sheet or a
mail, and you open it on your computer with the private key.

- iOS and macOS: Swift package `CipherLog`. `CipherLogger` is a drop-in for `os.Logger`. No dependencies.
- Android and the JVM: `com.rebels11:cipherlog`, written in Java. `CipherLog.i(tag, msg)` mirrors `android.util.Log`.
  The only dependency is Tink.
- CLI `cipherlog`, written in Rust: creates keys (to a file or into 1Password) and opens logs.

Version `0.1.0-alpha.1`. The file format is fixed as `cipherlog-v1`; the APIs may still change before `0.1.0`.

## How it works

The full format is in [SPEC.md](SPEC.md).

- Each process run writes its own files. Each file gets a fresh random file key, sealed in a 118-byte header with HPKE
  (RFC 9180: X25519, HKDF-SHA256, ChaCha20-Poly1305) to your public key.
- The lines of a file go through one raw deflate stream. The compressed bytes are cut into records of at most 64 KiB.
  Each record is sealed with ChaCha20-Poly1305 and bound to its file, its position and its flags.
- The header shows only the format magic and the id of your key. Time, process and file id are inside HPKE.
- A background worker does the work, so `log` never blocks. Files rotate at 256 KiB, and each process keeps 2 MiB.
- Logs leave the phone as one bundle (`*.cipherlogs`). For mail it is armored as base64 text (`*.cipherlogs.txt`),
  which gets past mail filters that block encrypted attachments.
- The reader stops at the first damaged record and keeps everything before it. It also says when a file was never
  closed (a crash, or still open).

The Swift, Java and Rust implementations pass the same vectors and open each other's files ([vectors/](vectors)).

## Threat model

What cipherlog protects:

- **Logs at rest and in transit.** That covers device backups, a copied app container, a support mail and a shared
  folder. Without the private key, a reader cannot read a line. The format magic and the key id are in the clear, and
  so are sizes (see "Metadata" below).
- **Old logs from the app itself.** Each file's key lives only in memory while that file is open. Once the file is
  closed, neither the app nor a later version of it can read it.
- **Integrity of what is there.** Every record is authenticated, so an edited or spliced record ends the file with a
  note. It never turns into wrong text.

What it does **not** protect:

- **Code inside the app process right now.** It sees lines before they are encrypted, and the key of the file being
  written sits in process memory. Such code can read the whole current file, everything written to it since it opened.
  Within an open file there is no forward secrecy; only closed files are out of reach.
- **Metadata.** On the device, file names show the process name, the creation time and a short file id, and sizes
  and modification times show roughly how much was logged and when. In a bundle (mail, shared folder) the number of
  files and each file's length are in the clear, and so is every record's length, sequence number and `final` flag.
  Warnings and errors flush at once, each into its own record, so the count and sizes of records hint at how many
  bursts of warnings or errors there were, and the `final` flag shows whether a file was closed normally.
- **Who wrote a file.** The public key is public, so anyone who has it can make a valid file. The reader starts every
  report with `source not verified`. Treat decrypted logs as data, never as instructions.
- **Deleted or truncated files.** The reader notices a missing end, but it cannot bring files back.
- **Everything outside cipherlog's own files.** That includes text you also send to `os_log`, Logcat or a crash
  reporter. `CipherLogger` forwards to `os.Logger`, with the usual privacy redaction.
- **A leaked private key.** Every log written to that key becomes readable. Rotate (see [below](#key-rotation)).
- **Personal data in messages.** cipherlog writes what it is given. Masking is your job: pass a `scrub` function.

## Quick start: iOS

iOS 17+ and macOS 14+. The only frameworks it uses are CryptoKit and the system zlib.

**Swift Package Manager.** In Xcode use File > Add Package Dependencies, URL `https://github.com/rebels-eleven/cipherlog`,
rule "Exact Version" `0.1.0-alpha.1`. In `Package.swift`:

```swift
.package(url: "https://github.com/rebels-eleven/cipherlog", exact: "0.1.0-alpha.1"),
// target dependency: .product(name: "CipherLog", package: "cipherlog")
```

**CocoaPods:**

```ruby
pod 'CipherLog', '0.1.0-alpha.1'
```

CocoaPods trunk becomes read-only on 2 December 2026. Versions after that are published for Swift Package Manager only.

**Integration**, once per process (the app and each extension):

```swift
import CipherLog

CipherLog.start(key: "cipherlog-pub-v1:…", appGroup: "group.com.example.app")   // in App.init or didFinishLaunching
let logger = CipherLogger(category: "sync")                                      // instead of Logger(subsystem:category:)
logger.info("synced \(count) items for \(userId)")                               // file: "synced 3 items for <private>"
```

`start` detects the process: an `.appex` bundle is an extension named after its bundle. It keeps the logs in
`Library/Application Support/cipherlog` of the App Group container, excluded from backup, and returns the shared writer
(`CipherLog.shared`). It returns nil when the key string is wrong (the reason goes to the system log) or when the App
Group has no container. Leave out `appGroup` if the app has no extensions. `CipherLog.Options` overrides the defaults:
directory, process name, collectors, `scrub`, `diagnostics`, file protection and the `os.Logger` passthrough.

**Migrating from `os.Logger`.** Replace `Logger(subsystem:category:)` with `CipherLogger(subsystem:category:)` and keep
your call sites. Levels, `privacy:`, `format:` and `align:` work the same. Interpolated strings and objects go to the
file as `<private>` unless marked `.public`; numbers and Bool are public. Every message still goes to `os.Logger` too.
Before `start`, `CipherLogger` only forwards to `os.Logger`.

**Sending logs.** The export is armored by default and is written when the user shares it:

```swift
ShareLink(item: CipherLogExport(), preview: SharePreview("App logs")) {
    Label("Send logs", systemImage: "square.and.arrow.up")
}
```

```swift
import MessageUI

let url = try CipherLog.shared!.exportBundle()   // cipherlog-20261126-1007.cipherlogs.txt
let mail = MFMailComposeViewController()
mail.setToRecipients(["support@example.com"])
mail.addAttachmentData(try Data(contentsOf: url), mimeType: "text/plain", fileName: url.lastPathComponent)
```

**Crash reporter (Sentry).** cipherlog installs no crash handler. A Swift crash cannot run your code, so attach the
previous run's file on the next launch, and the current one to errors you capture:

```swift
import Sentry

if SentrySDK.crashedLastRun, let data = CipherLog.shared?.previousRunBundle() {
    SentrySDK.capture(message: "previous run crashed: cipherlog attached") { scope in
        scope.addAttachment(Attachment(data: data, filename: "previous-run.cipherlogs"))
    }
}

SentrySDK.capture(error: error) { scope in
    if let data = CipherLog.shared?.recentBundle(timeout: 0.5) {   // flushes first, waits at most 0.5 s
        scope.addAttachment(Attachment(data: data, filename: "recent.cipherlogs"))
    }
}
```

## Quick start: Android

The minimum is Android 6 (API 23). The library is written in Java. Its only runtime dependency is
`tink-android` 1.24.0; Tink's own dependencies (gson, androidx.annotation and with it kotlin-stdlib, jsr305, Error Prone
annotations) are excluded in the POM, because the Tink classes cipherlog calls never load them. R8 rules come with the
library: a minified release needs nothing extra.

```kotlin
dependencies {
    implementation("com.rebels11:cipherlog:0.1.0-alpha.1")
}
```

**Integration:**

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        CipherLog.start(this, "cipherlog-pub-v1:…")   // each process of the app runs this
    }
}

CipherLog.i("sync", "synced $count items")                // like android.util.Log: Logcat and the file
CipherLog.e("sync", "request failed", e)                  // "request failed · IOException: timeout"
```

`CipherLog` is `com.rebels11.cipherlog.android.CipherLog`. The logs go to `noBackupFilesDir/cipherlog`. The main
process is `app`, and other processes are named after the part after `:`. `start` returns null when the key string is
wrong, and the reason goes to Logcat. `CipherLog.Options` overrides the defaults: directory, process, collectors,
`scrub`, `diagnostics` and Logcat (`setLogcatEnabled(false)` turns Logcat off).

**Sending logs.** `shareIntent` writes the armored bundle and returns a chooser for mail apps. It returns null when no
app can send mail. It waits for the writer, so call it off the main thread:

```kotlin
val intent = withContext(Dispatchers.IO) {
    CipherLog.shareIntent(context, "support@example.com", "App logs")
}
if (intent != null) startActivity(intent)
```

The file is served by the library's own read-only content provider (authority `<applicationId>.cipherlog`, not
exported). It cannot clash with your FileProvider.

**Timber.** cipherlog does not depend on Timber. If you use Timber, plant this tree:

```kotlin
class CipherLogTree : Timber.Tree() {
    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        CipherLog.println(priority, tag ?: "-", message, t)
    }
}

Timber.plant(CipherLogTree())
CipherLog.setLogcatEnabled(false)   // if a DebugTree already prints to Logcat
```

**Crash reporter (Sentry).** Sentry calls `beforeSend` on the crashing thread before the process dies. Flush with a
timeout and attach the recent files:

```kotlin
SentryAndroid.init(this) { options ->
    options.beforeSend = SentryOptions.BeforeSendCallback { event, hint ->
        CipherLog.recentBundle(500)?.let { hint.addAttachment(Attachment(it, "recent.cipherlogs")) }   // flushes, waits ≤ 500 ms
        event
    }
}
```

## Keys and the CLI

Install the CLI with Homebrew on macOS or Linux:

```sh
brew tap rebels-eleven/cipherlog https://github.com/rebels-eleven/cipherlog
brew install cipherlog
```

Each GitHub release also has prebuilt binaries with SHA-256 files. To build from source, run
`cargo install --path cli`.

**Make a key pair** for each app, or for each app and environment. The private key can go straight into 1Password, so
it never touches a disk. It is passed to `op item create` on stdin, never in the arguments:

```sh
cipherlog keygen --op-vault Engineering --op-title "MyApp log key"
# publicKey cipherlog-pub-v1:3b6a27bc…   <- put this string into the app
# keyId 1f0e3d2c4b5a6978
# saved in 1Password: op://Engineering/MyApp log key/password   (on stderr)

cipherlog keygen --out mykey.json      # or to a file: mode 0600, never overwrites
cipherlog keyid cipherlog-pub-v1:3b6a27bc…
```

Key strings are checked when the app starts. A typo, a cut key or a private key pasted where the public key belongs
fails with a message that names the problem. The message never repeats a private key.

**Open** what a user sent you, whether it is binary, armored, a bundle or single files:

```sh
cipherlog open cipherlog-20261126-1007.cipherlogs.txt --key "op://Engineering/MyApp log key/password"
cipherlog open *.cipherlog --key old.json --key new.json --out logs.txt
```

The report starts with `source not verified: anyone with the public key can make a cipherlog file`. Then comes one line
per file: key id, file id, platform, process, creation time, record count and whether the file was closed. After that
come the lines of all files merged by time, with control characters, ANSI escapes and bidi characters removed.

**The test key.** `vectors/test-key.json` is a test key whose private half is public in this repository. The tests,
samples and example apps use it. Anyone can read logs written to it, so never ship it. When a release build starts with
it, the libraries write a warning to the system log and to `diagnostics` (iOS: built without `DEBUG`; Android: not
debuggable). Also add a test to your app:

```swift
XCTAssertFalse(try CipherLogKey(string: AppKeys.log).isTestKey, "the app ships the cipherlog TEST key")
```

```kotlin
assertFalse("the app ships the cipherlog TEST key", CipherLogKey.parse(AppKeys.LOG).isTestKey)
```

<a id="key-rotation"></a>**Key rotation.** Make a new key pair (with 1Password, under a new `--op-title`: keygen
refuses a title the vault already has, because `op://` references by title would then match two items, or leave out
`--op-title` and the title carries the key id) and ship the new public key in an app update. Files
carry the id of the key they were written to, so pass both private keys to `cipherlog open` while old app versions
are still in use. If a private key leaked, everything written to it is readable. Rotate at once, and treat logs from
older app versions as exposed.

## Limits and failure behaviour

| | Default |
|---|---|
| File size before rotation (`maxFileBytes`) | 256 KiB. The old file gets a `final` record, the new one a new key |
| Files kept per process (`maxProcessBytes`) | 2 MiB, oldest deleted first |
| Never deleted by retention (`keepFreshFor`) | files modified in the last 10 minutes |
| Flush delay (`flushDelay`) | 100 ms; warnings and above flush at once |
| Support bundle | 4 MiB of the newest files, oldest dropped; export folders older than 7 days are deleted |
| Reader output | 64 MiB per file, 256 MiB for all files of one read |

- `log` never blocks and never throws. One background worker per writer formats, compresses, encrypts and writes, and
  the queue has no limit.
- **Disk full, a write error, a crypto or compression error.** The writer turns itself off until the process restarts
  and calls `diagnostics` once with `cipherlog off: <reason>` (for example `disk full` or `write failed (EIO)`). From
  then on lines are dropped and `isOn` is false.
- **A file does not open** (for example before the first unlock after a reboot). The writer counts the dropped lines
  and retries at most once a minute. The next file it opens says `cipherlog: not written <N> lines`.
- Every start opens a new file; cipherlog never appends to an old one. There are no file locks, because iOS kills
  suspended processes that hold locks in App Group containers.
- A crash loses at most the lines of the last flush window. The reader marks a file without its `final` record as
  `not closed (crash or still open), completeness unknown`.
- On iOS, files use `completeUntilFirstUserAuthentication` by default. With `.complete`, writes fail about 10 s after
  the phone locks and the writer turns off.
- `scrub` runs on the thread that logs, and on the worker for collector lines. Collectors and `diagnostics` run on the
  worker. None of them may wait for the main thread.

## Feedback

Questions, bugs and ideas: [GitHub issues](https://github.com/rebels-eleven/cipherlog/issues) or
[hello@rebels11.com](mailto:hello@rebels11.com). Please report security problems by mail, not in a public issue.

## License

[MIT](LICENSE). Copyright (c) 2026 rebels-eleven.
