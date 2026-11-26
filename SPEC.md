# cipherlog file format, version 1 (`cipherlog-v1`)

cipherlog writes app logs to files on the phone and encrypts them at write time to the developer's public key.
The app can append but cannot read what it wrote; only the holder of the private key can. This document is the
single source of truth for the iOS (Swift), Android/JVM (Java) and CLI (Rust) implementations. (The first Kotlin and
TypeScript implementations are retired; their samples stay in `vectors/samples/` as fixtures.)

All integers are big-endian. `‖` is concatenation. Strings in labels are ASCII without a terminator.

## 1. Keys

- A log key is an X25519 key pair. The public key (32 bytes, raw) ships inside the app.
- `keyId` = first 8 bytes of SHA-256(`"cipherlog-key-v1"` ‖ publicKey). It tells the reader which private key to use.
- Key rotation: the app ships a new public key; old files still open with the old private key by their `keyId`.
- The test key in `vectors/test-key.json` is for tests only. Apps must never ship it; an app should have a test
  that fails if its current key equals the test key.

### 1.1 Key strings

Keys travel as one line of text so a typo or a wrong key is caught at start:

- public: `cipherlog-pub-v1:` followed by the 32-byte key in lowercase hex (64 characters);
- private (only in the developer's vault, never in an app): `cipherlog-priv-v1:` followed by 64 hex characters.

Parsers accept upper- or lowercase hex, reject anything else (wrong prefix, length, characters, surrounding text other
than whitespace) with an error that names the problem, and never echo a private key in that error. `cipherlog keygen`
prints the public string and its `keyId`.

- Whitespace is space, tab, CR and LF, and only at the ends. Other invisible characters (a no-break space, a byte order
  mark) are errors like any other character.
- Checks in this order, each with its message (after `cipherlog key: `): empty (`the key string is empty`); the other
  kind's prefix (a private key given as public: `this is a PRIVATE key (cipherlog-priv-v1:…); an app ships only the
  public key (cipherlog-pub-v1:…)`, and the reverse); any other prefix (`the key string must start with <prefix>`);
  the first character after the prefix that is not a hex digit (`character <n> after the prefix is not a hex digit`,
  `n` counting code points from 1, followed by ` ("c")` for printable ASCII or ` (U+XXXX)` otherwise, for public keys
  only); then the length (`expected 64 hex characters after the prefix, got <n>`).
- `vectors/keys.json` holds the shared cases with their exact messages.
- The CLI also reads key files: the JSON of `vectors/test-key.json` and of `cipherlog keygen --out` (hex or key-string
  fields), a key string, or 64 hex characters.

## 2. File (`*.cipherlog`)

A file is a header followed by zero or more records. One file belongs to one process run.

### 2.1 Header: 118 bytes

| Field | Bytes | Content |
|---|---|---|
| `magic` | 4 | ASCII `CPL1` |
| `keyId` | 8 | see 1 |
| `enc` | 32 | HPKE encapsulated key |
| `sealed` | 74 | HPKE ciphertext of `pt` (58) and tag (16) |

- HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, ChaCha20-Poly1305 `0x0003`
  (CryptoKit `Curve25519_SHA256_ChachaPoly`), single-shot seal, empty aad.
- `info` = `"cipherlog-v1"` ‖ `magic` ‖ `keyId`.
- `pt` (58 bytes) = `fileKey` (32, random) ‖ `fileId` (16, random) ‖ `createdAt` (u64, ms since Unix epoch, UTC) ‖
  `platform` (u8) ‖ `process` (u8).
  - `createdAt` is at most 2^53 − 1 (an exact number in every language). Readers treat a header with a larger value as
    one that does not open (5.2).
  - `platform`: 0 unknown, 1 Apple (iOS, macOS), 2 Android, 3 JVM. Readers print other values as numbers.
  - `process`: chosen by the app (for example 1 main app, 2 widget extension). Readers print it as a number.
- `fileKey` lives only in the writing process's memory and only for this file.

### 2.2 Records

`len` (u32) ‖ `seq` (u32) ‖ `flags` (u8) ‖ `ct` (`len` bytes: ciphertext followed by the 16-byte tag).

- ChaCha20-Poly1305 (RFC 8439) with key `fileKey`, nonce = 8 zero bytes ‖ `seq` (u32), aad =
  `"cipherlog-rec-v1"` ‖ `fileId` ‖ `len` ‖ `seq` ‖ `flags`.
- `seq` starts at 0 and increases by 1 with every record of the file. Readers reject a gap, repeat or step back.
  `seq` is a u32 in the nonce: a writer never writes a record past `seq` 0xFFFFFFFF (it would repeat a nonce under the
  same `fileKey`); reaching that point is a crypto error (3.6).
- `flags` bit 0 = `final`: the last record of a normally closed file (rotation, wipe, explicit close). The other
  bits are zero; readers reject a record where they are not. Nothing may follow a `final` record.
- 16 ≤ `len` ≤ 65 552 (plaintext at most 64 KiB). A writer with more compressed bytes writes several records.
- The plaintext of a record is a piece of the file's compressed stream (2.3); an empty plaintext is allowed (for
  example a `final` record after a flush that produced nothing new). A writer may also turn every full 64 KiB of
  compressed output into a record before the flush.

### 2.3 Compression: one stream per file

- Raw deflate (RFC 1951, no zlib or gzip wrapper): level 6, window bits 15 (zlib `windowBits = -15`), default
  memLevel 8. One stream for the whole file.
- A flush ends with `Z_SYNC_FLUSH` (Java `Deflater.SYNC_FLUSH`); the bytes produced since the previous record become
  the next record(s). The `final` record carries the output of `Z_FINISH`.
- Readers inflate the concatenation of all record plaintexts in order, as one raw stream, accepting an unfinished
  stream (inflate with `Z_SYNC_FLUSH`, not `Z_FINISH`) and capping the output at 64 MiB.
- Different zlib builds may produce different bytes for the same text. Only records are compared byte for byte in
  vectors (8).

### 2.4 Text

UTF-8, one line per event, `\n` after every line:

```
2026-11-26T10:00:00.123Z I app spotify: connect
```

Fields separated by one space: time (UTC, ISO 8601 with milliseconds and `Z`), level, process name, category
followed by `:`, message. Category `-` when there is none.

- Levels: `D` debug, `I` info, `N` notice, `W` warning, `E` error, `F` fault.
- The writer replaces `\r\n`, `\r` and `\n` inside fields with the two characters `\n`. It replaces with U+FFFD every
  other C0 control except tab (U+0000–U+0008, U+000B–U+001F), DEL (U+007F), every C1 control (U+0080–U+009F) and
  every unpaired surrogate (it has no UTF-8 form). Everything else is kept, U+2028 and U+2029 included. A line
  therefore never breaks.
- Process name and category: the first 32 Unicode code points are kept, then every code point outside
  `[A-Za-z0-9._-]` becomes `_` (one `_` per code point). An empty or missing name becomes `-`.
- An error value is written as `<type name>: <scrubbed message>`, or `<type name>` when it has no message. When a
  line carries both a message and an error, they are joined by ` · `: `<message> · <type name>: <scrubbed message>`.

### 2.5 Device block

The first lines of every new file describe the device, so any file stands on its own:

```
2026-11-26T10:00:00.123Z I app device: cipherlog 0.1.0-alpha.1 · file 3f2a… · platform 1 · process 1
2026-11-26T10:00:00.123Z I app device: phone · iPhone12,1 · iOS 26.1
2026-11-26T10:00:00.123Z I app device: app · failed DecodingError
```

The first line is written by cipherlog itself (`cipherlog <version> · file <fileId hex, first 8 chars> · platform <n> ·
process <n>`). Then every collector the app registered gives zero or more lines `<collector> · <text>`. A collector
that throws gives `<collector> · failed <error type name>` and the rest go on.

- `<version>` is the full library version (`0.1.0-alpha.1`).
- Every device-block line, and the `not written` line of 3.6, carries the file's `createdAt` as its time.
- Collector text goes through `scrub` (3.8); the first line does not.

## 3. Writer rules

1. **Queue.** `log` only enqueues; one background worker per writer does formatting, compression, encryption and
   file I/O. The queue has no limit (the app owner's choice: simplicity over a cap).
2. **Flush.** 100 ms after a line, one task for the batch; at once for `W` and above; on an explicit `flush()`
   (synchronous, with a time limit, safe to call from any thread except the worker). No `fsync`.
3. **New file** at every writer start (never append to a file of a previous run: that would reuse a nonce), and when
   the current file reaches 256 KiB (the old one gets a `final` record, the new one a new `fileKey` and `seq` 0).
   Files are created with "create new, fail if it exists". Rotation happens at the first flush after the file reached
   the limit, so a file may exceed it by one flush plus the `final` record; a file that holds only the device block
   is not rotated.
4. **Retention.** Each process keeps at most 2 MiB of files; the oldest go first, but files modified less than 10
   minutes ago are never deleted (another live process may be writing them). No file locks (iOS kills a suspended
   process that holds one in an App Group container, `0xdead10cc`). Retention runs whenever a new file opens. It
   counts only names of this process that match rule 5, the current file included (which it never deletes), walks
   them in name order and skips fresh files instead of stopping at them.
5. **File names**: `<process name>-<createdAt ms, 13 digits>-<fileId hex, first 8 chars>.cipherlog`. Sorting by name within
   a process sorts by time. Within one writer every new file's `createdAt` is at least the previous file's `createdAt`
   + 1 ms (fast rotation under a coarse clock), so name order is the order of writing. Two runs of the same process
   that start in the same millisecond sort by their random `fileId`; this is accepted.
6. **Write failure.**
   - Disk full, any other write error on an open file, or a crypto or compression error: the writer turns itself
     off until the process restarts, reports one line through the app's diagnostics callback (`cipherlog off:
     <reason>`), drops queued lines and drops new lines without queueing. The reason is `disk full` for ENOSPC,
     EDQUOT or the platform's out-of-space error; otherwise a short text such as `write failed (EIO)` or
     `crypto error`. A write failure names the errno symbolically when the platform gives one (`write failed (EPERM)`
     for a file locked by data protection, `write failed (EIO)`), not a type name. The current file is left without a
     `final` record. This line and the test-key warning of 7.1 are the only things a writer ever sends to diagnostics.
   - The file does not open (for example iOS before the first unlock after a reboot): the writer retries at most once
     a minute (on the next line at least 60 s after the failed attempt) and counts the dropped lines; after a
     successful open the file gets `W … cipherlog: not written <N> lines`. Nothing goes to diagnostics. Disk full or a
     crypto error while opening turns the writer off as above. A file whose header write fails is deleted, so no
     0-byte file stays behind.
   - Apple platforms: files are created with the data protection class `completeUntilFirstUserAuthentication` unless
     the app chooses another, in that class from the start (not created in the directory's class and changed after:
     with an inherited `complete` that fails while the phone is locked), and the log directory gets the same class; with `complete` (for example inherited from the app's entitlement) writes fail about
     10 s after the phone locks and the writer turns off by the rule above.
7. **Wipe** (sign out, account deletion): close the current file, delete all cipherlog files of every process in the
   directory (names matching rule 5) and all exports, open a new file. Exports are the export folders (4) directly
   inside the configured export root (the platform's default root when the app configures none, so exports of earlier
   runs are found too) and inside every root passed to `exportBundle` in this process; nothing else in those roots is
   touched. After `close()` wipe deletes but opens nothing; while off it deletes and stays off.
   Another process's wipe deletes this writer's current file. A writer therefore checks that its current file still
   exists at the start of every batch of lines (the first line after a flush) and before `recentBundle`; when it is
   gone, the file is dropped without `final` and a new file opens (rule 3).
8. **Errors and privacy.** cipherlog writes what it is given. Masking is the app's job (a `scrub` hook runs over every
   message and error message on the calling thread before the line is queued, and over collector text on the worker;
   the default is identity). Error values are written as `<type name>: <scrubbed
   message>`, never with a stack trace.

## 4. Bundle (`*.cipherlogs`)

Files leave the phone as one bundle: `magic` `CPB1` ‖ entries, each `len` (u32) ‖ the bytes of one `.cipherlog` file.

- Support mail: all files of all processes (newest first until 4 MiB, oldest dropped) plus a fresh in-memory file
  holding only the device block (`device now`), closed with `final`. Written to `<export root>/<random id>/cipherlog-<UTC
  yyyyMMdd-HHmm>.cipherlogs`; folders older than 7 days are deleted on the next export.
  - `<random id>` is 16 random bytes in lowercase hex (32 characters); only folders named like this are export folders.
    A folder's age is the modification time of the newest file in it, or its own when it is empty; it is deleted with
    its contents.
  - Selection: `device now` is always included. The files are taken newest first by the `createdAt` in their names
    (ties by name) while the whole bundle, magic and lengths included, stays within 4 MiB; the first file that does not
    fit ends the selection. Files shorter than a header (118 bytes: another process between creating a file and
    writing its header) are skipped, here and in `previousRunBundle`.
  - Order in the bundle: the selected files oldest first, then `device now` last.
- Crash and failure reports: the current file of this process after a flush, plus the previous one when the current
  one is under 4 KiB; or the newest file of the previous run of this process. Returned as bytes, not a path.
  - `recentBundle`: previous file (the one before the current file in name order, possibly of an earlier run) first,
    then the current one. With no open file (off, closed, not opened yet) the newest file of this process instead.
  - `previousRunBundle`: the newest file of this process that this writer did not create, or none.

### 4.1 Armor (`*.cipherlogs.txt`)

Mail filters block attachments they cannot scan (Gmail blocks encrypted archives). For mail the bundle goes as text:

```
-----BEGIN CIPHERLOG BUNDLE-----
<base64 of the bundle bytes, RFC 4648 standard alphabet with padding, lines of 76 characters>
-----END CIPHERLOG BUNDLE-----
```

- Lines end with `\n`; the last base64 line may be shorter. Nothing else is inside the markers.
- Readers accept `\r\n`, surrounding whitespace and text before the BEGIN line or after the END line (a mail client
  may add a signature), but reject anything between the markers that is not base64, and a missing END line. Exactly:
  - Lines end at `\n`; space, tab and `\r` at the ends of a line are ignored (nothing else: a no-break space or a form
    feed is a wrong character).
  - The BEGIN line is the first line that is exactly the marker. A line holding the marker with other text (a quoted
    `> -----BEGIN…`, a version after it) is not; input without a BEGIN line is not armored. Text before the BEGIN line
    may be any bytes.
  - Every following line up to the first END line is either empty (ignored) or only base64 characters (`A–Z a–z 0–9 +
    / =`). Line lengths are not checked. The first other line gives `armor: line <n> after BEGIN is not base64`, `n`
    counting from 1 at the line after BEGIN, empty lines included. Reaching the end without an END line gives
    `armor: no -----END CIPHERLOG BUNDLE----- line`.
  - The base64 of all lines together has a length that is a multiple of 4 and `=` only as its last one or two
    characters, else `armor: base64 is cut or badly padded`. Non-canonical padding bits are accepted (the payload is
    authenticated anyway).
  - The payload is read as a bundle or as a single file; it is never unwrapped as armor a second time.
  - `vectors/armor.json` holds the shared cases with their exact results.
- Mail exports are armored by default (`exportBundle(armored: true)`, file `cipherlog-<UTC yyyyMMdd-HHmm>.cipherlogs.txt`);
  crash and failure attachments stay binary. Readers (`cipherlog open` and the libraries' readers) detect both; an armor
  error ends that input with the error as its note.

## 5. Reader

1. Bundle: check `CPB1`, split by lengths. A length of 0 is a valid entry (an empty file, skipped like any file
   shorter than a header); only a length that runs past the end, or fewer than 4 bytes left for a length, ends the
   bundle with a note.
2. Header: magic, `keyId` → private key (unknown key: skip the file with a note), HPKE open (fails: skip with a note).
3. Records in order, each checked in this order: length bounds (`bad length <len>`), body cut short (`truncated`),
   `seq` (`seq <got>, expected <want>`), `flags` (`reserved flag bits 0x<two lowercase hex digits>`), AEAD
   (`authentication failed`). The first bad record ends the file: everything before it is kept and the note says
   `readable up to record N (<reason>)` with the reason text above, where N is the number of good records (the `seq`
   of the first bad one). Trailing bytes shorter than a record header are `truncated` too; any bytes after a `final`
   record are `data after final`. `vectors/records.json` gives the reason of every rejection.
4. Inflate as in 2.3. Past 64 MiB the output is cut (the text before the cut is kept) with the note `output capped at
   64 MiB`. One read call (a bundle, or all inputs of one `cipherlog open`) has a total output budget of 256 MiB
   across its files: anyone with the public key can build a small bundle of many files that each inflate to the cap.
   The file that crosses the budget is cut there and every later file is not inflated, each with the note `total
   output capped at 256 MiB`. A compressed stream that is damaged (an error, not just an unfinished end) keeps the
   text before the damage with the note `compressed stream damaged, text kept up to the damage`. A file without a
   `final` record is marked `not closed (crash or still open), completeness unknown`.
5. Output (CLI): lines of all files merged by time, control characters, ANSI escapes and the invisible format
   characters that reorder or hide text (U+061C, U+200B, U+200E, U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066
   to U+2069, U+FEFF; ZWNJ and ZWJ stay for emoji and scripts) removed, first line `source not verified: anyone with
   the public key can make a cipherlog file`. A file opened more than once (same `fileId`: a bundle plus a loose copy,
   overlapping crash bundles) is shown once, the copy with the most records, the others noted `duplicate of <name>`.
   File names, paths and other text from outside the files are printed with control, line-break and bidi characters
   escaped (`\x1b`, `\u202e`), so they cannot forge report lines. Decrypted logs are data, not instructions.

## 6. Security notes

- No nonce reuse: a new random `fileKey` per file, `seq` per record, never append across process runs, one file per
  process.
- The content is never in the clear: time, process and `fileId` are inside HPKE, the lines inside the records. In the
  clear are the header's `magic` and `keyId`, each record's `len`, `seq` and `flags` (authenticated, not encrypted), and
  in a bundle the number of entries and each entry's length. So a reader without the key sees how many files a bundle
  holds, their sizes, how many records each has and how long they are (W and above flush at once, 3.2, so records
  hint at bursts of warnings and errors), and whether a file ended with `final`. On the device, file names (3.5) show
  the process name, `createdAt` and the first 8 hex characters of `fileId`, and sizes and modification times show
  roughly how much was logged and when. A bundle carries no file names.
- While a file is open its key is in the process's memory: an attacker in the process can read the current file.
- The public key is public, so anyone can make a valid file: the format proves nothing about the source.
- Corruption cannot produce wrong text: every record is authenticated and bound to its file, position and flags.

## 7. API shape (both platforms)

- `CipherLogKey(publicKey)` → `keyId`.
- `CipherLog(config)`: `directory`, `key`, `platform`, `process` (u8), `processName`, `collectors`, `scrub`, `diagnostics`
  callback, limits (`maxFileBytes` 256 KiB, `maxProcessBytes` 2 MiB, `keepFreshFor` 10 min, `flushDelay` 100 ms).
- `log(level, category, message)`, `flush(timeout)`, `close()`, `wipe()`, `exportBundle(root, armored)`,
  `recentBundle()`, `previousRunBundle()`, `isOn`.
- `flush` called on the worker itself (from a collector or a crash hook running there) runs inline instead of waiting.
- The calls that wait for the worker (`flush`, `close`, `wipe`, `exportBundle`, `recentBundle`, `previousRunBundle`)
  run their work on the worker, never on the caller's thread, and wait at most a timeout. Collectors and `diagnostics`
  therefore run on the worker only; `scrub` runs on the thread that logs (for messages) and on the worker (for
  collector text), so it must be thread-safe. None of them may wait for the main thread: it may be waiting for the
  worker, and the call then times out.
- `log` never throws, not even an error of the runtime (out of memory while starting a thread): a crash handler calls
  it. The worker is started with the writer and lives as long as it.
- The CLI's writer (`cipherlog write`, tests, samples) is a synchronous reference without a queue; rules 1 and 2 are
  about the mobile libraries.
- `CipherLogReader`: open a file or bundle with private keys → lines and per-file status.
- Swift extras: `CipherLogger`, a drop-in for `os.Logger` (`CipherLogMessage` interpolation with `privacy:`; values without
  `.public` go to the file as `<private>`; numbers and Bool are public).

### 7.1 Integration (what an app writes)

The library must be usable with a few lines and without changing existing log call sites.

- `start` runs once per process: later calls return the first writer and ignore their arguments. A key string that does
  not parse makes `start` return nil (no throw) and reports the key error (1.1) to the system log and diagnostics.
- iOS: `CipherLog.start(key: "cipherlog-pub-v1:…", appGroup: "group.…")` once per process (app and each extension;
  the process kind and name are detected: a bundle ending in `.appex` is an extension named after its bundle name).
  Returns the shared writer (`CipherLog.shared`), or nil when the App Group has no container (missing entitlement:
  the library does not fall back to the app's own container, which would split the logs of app and extensions).
  Call sites use `CipherLogger(category:)` (subsystem defaults to the
  main bundle id), a drop-in for `os.Logger` (`Logger(subsystem:category:)` → `CipherLogger(subsystem:category:)` is the
  whole migration). Without a started writer `CipherLogger` only forwards to `os.Logger`.
- Android: `CipherLog.start(context, "cipherlog-pub-v1:…")` in `Application.onCreate`; the static facade
  `CipherLog.v/d/i/w/e(tag, message[, throwable])` mirrors `android.util.Log` (Logcat as well as the file, Logcat can be
  turned off). `CipherLog.shareIntent(context, email, subject)` returns a ready intent: a chooser around an
  `ACTION_SEND` (selector `mailto:`) with the armored bundle, served by the library's own read-only content provider
  (authority `<applicationId>.cipherlog`, not exported, read grant only; no androidx), or null when nothing can send mail
  or the export fails. It writes the bundle and waits for the worker, so apps call it off the main thread.
- Defaults (all overridable): directory (iOS: `Library/Application Support/cipherlog` in the App Group container,
  excluded from backup; Android: `noBackupFilesDir/cipherlog`), process name, built-in device collectors (app version
  and build, install source, OS, device model, locale, rounded free space; never names, accounts, ad ids, location,
  device name), Logcat/os.Logger passthrough (on by default; with no started writer `CipherLogger` always forwards).
- Optional device collectors, never in the defaults; an app opts in with one line (iOS:
  `collectors: CipherLogCollector.defaults + CipherLogCollector.optional()`, on the main thread; Android:
  `options.addCollectors(OptionalCollectors.all(context))`), or picks single ones. Same names and line shapes on both
  platforms where the platform allows:
  - `versionHistory · 1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-12`: every version and build first seen on
    the device with its UTC day, newest first, at most 20, kept in the app's own storage (iOS: `UserDefaults`, default
    `.standard`, key `cipherlog.versionHistory`; Android: private SharedPreferences file `cipherlog`). Recorded when the
    collector is created and when a file opens.
  - `installDates · installed 2026-11-12 · updated 2026-11-20` (UTC days). Android: `firstInstallTime` and
    `lastUpdateTime`. iOS has no such API, both are approximations: installed is the creation date of the data
    container's Library folder; updated is the UTC day the running version and build was first seen (`UserDefaults`
    key `cipherlog.installDates.build`; in the first build with the collector, that first day). iOS reads no
    timestamp outside the app's data container.
  - `memory`: total RAM rounded to 0.5 GB (binary), then Android: memory class and large memory class, low-RAM device,
    low memory now, power save; iOS: what the process may still allocate (`os_proc_available_memory`), Low Power Mode,
    thermal state.
  - `screen`: Android: size in dp, density bucket and dpi, font scale, dark; iOS: size in points and scale, preferred
    content size category, dark. iOS reads UIKit only on the main thread: when the collector is created and on
    becoming active or a text-size change; created off the main thread, the line says so.
  - `network · wifi · expensive no · constrained no`: the connection type only (`wifi`, `cellular`, `ethernet`, `none`,
    `other`), metered and constrained, both for the current network (iOS: `isConstrained`, Low Data Mode; Android:
    metered and Data Saver restricts the app, since Data Saver leaves unmetered networks alone). Android needs `ACCESS_NETWORK_STATE`,
    which the library never adds to its manifest: without it the line is `unknown (no ACCESS_NETWORK_STATE)`. iOS keeps
    one `NWPathMonitor` per collector.
  - `storageUsage`: the size of the app's own folders (Android: files, cache, no_backup, databases and the log
    directory, the one passed to `OptionalCollectors.all(context, logDirectory)` when the app moved it; iOS:
    Documents, Caches, Application Support, tmp and the App Group container when given), as logical sizes (sum of
    file lengths, not allocated blocks) on both, KB under 1 MB, then MB and GB with one decimal. The walk stops after
    50 000 entries or 200 ms in all (Android 26+ reads directories lazily; 23–25 checks the cap before each directory
    read); a folder cut short shows `≥` and what was counted, a folder not reached `not counted`, a missing one `none`.
  - Privacy: none of them collects names, accounts, ids, network names (SSID, BSSID), addresses, carrier names or file
    names. Creating one never throws; a failure while a file opens is `<name> · failed <type>` like any collector.
- Starting with the test key from `vectors/test-key.json` in a release build (iOS: the package compiled without
  `DEBUG`; Android: the app not debuggable) writes a warning to the system log and to diagnostics at every start. The
  libraries recognise the test key by its `keyId` (`dacb47e7a1ba0cf1`) and do not embed the key itself.
- The library installs no crash handler; apps call `flush(timeout)` and `recentBundle()` from their crash reporter.

## 8. Vectors

`vectors/test-key.json` (test key pair), `vectors/records.json` (byte-exact records and rejections),
`vectors/keys.json` (key strings, 1.1), `vectors/armor.json` (armor, 4.1), `vectors/samples/<impl>/` (real files
written by each implementation with the expected text, and an armored `sample.cipherlogs.txt` from the current ones).
Every implementation must pass `records.json`, `keys.json` and `armor.json` and open every other implementation's
samples. `vectors/samples/cli` and `vectors/samples/kotlin` come from the retired TypeScript and Kotlin implementations
and never change; `vectors/cli-open.expected.txt` is the retired TypeScript CLI's `cipherlog open` report on them,
which the Rust CLI must print byte for byte. `records.json` is regenerated by `cargo run --example gen_vectors` in
`cli/` (the HPKE header is randomized, so the generator keeps the existing one when it still opens).
