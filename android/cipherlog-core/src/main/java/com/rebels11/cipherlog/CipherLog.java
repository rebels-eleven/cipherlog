package com.rebels11.cipherlog;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Writes app logs to {@code *.cipherlog} files encrypted at write time to the developer's public key (SPEC.md 3). The
 * app can append but never read what it wrote.
 *
 * <p>{@link #log} only enqueues; one daemon worker thread named {@code cipherlog} formats, compresses, encrypts and
 * writes. Lines are flushed 100 ms after a line, at once for {@link CipherLogLevel#W} and above, and on {@link #flush}.
 * A new file opens at every start (never appended to), and when the current one reaches {@code maxFileBytes}.
 *
 * <p>Crypto comes from Tink ({@code com.google.crypto.tink:tink-android:1.24.0}, a dependency of this library). The
 * writer uses classes from Tink's {@code internal} packages, which carry no compatibility promise. Without Tink at run
 * time (an app that excluded it), or with a Tink whose internal classes changed, the writer turns itself off with
 * {@code cipherlog off: crypto unavailable (...)} instead of crashing the app.
 *
 * <p>Masking is the app's job: {@code scrub} runs over every message before it is queued. Errors are written as
 * {@code <type name>: <scrubbed message>}, never with a stack trace.
 */
public final class CipherLog {
    static final long OPEN_RETRY_MS = 60_000L;
    static final long BUNDLE_LIMIT = 4L * 1024 * 1024;
    static final int RECENT_SMALL = 4 * 1024;
    static final long EXPORT_MAX_AGE_MS = 7L * 24 * 60 * 60 * 1000;
    static final Pattern ANY_FILE = Pattern.compile("^[A-Za-z0-9._-]{1,32}-\\d{13}-[0-9a-f]{8}\\.cipherlog$");
    static final Pattern EXPORT_DIR = Pattern.compile("^[0-9a-f]{32}$");
    private static final Pattern ERRNO = Pattern.compile("\\b(E[A-Z0-9]{2,})\\b");
    /** SPEC.md 7.1: a start with the test key in a release build. */
    public static final String TEST_KEY_WARNING = "cipherlog: started with the TEST key from vectors/test-key.json in a"
            + " release build; anyone can read these logs. Ship your own public key.";

    private final CipherLogConfig config;
    private final SecureRandom random = new SecureRandom();
    private final CipherLogFileSystem fs;
    private final Pattern mine;

    private volatile Thread worker;
    private final ScheduledThreadPoolExecutor executor;

    private volatile boolean off = false;
    private volatile boolean closed = false;
    private final AtomicBoolean offReported = new AtomicBoolean(false);

    // Worker state: touched on the worker thread only.
    private LogFile current;
    private File currentFile;
    private boolean workerClosed = false;
    private final Set<String> createdThisRun = new HashSet<>();
    private long failedOpenAt = -1;
    private boolean hasFailedOpen = false;
    private long lastCreatedAt = Long.MIN_VALUE / 2;
    private long notWritten = 0;
    private boolean flushScheduled = false;
    private boolean inFileOp = false;
    private final Set<File> exportRoots = new LinkedHashSet<>();

    /** Starts the writer: the worker thread starts here and opens the first file. Never throws for I/O or crypto. */
    public CipherLog(CipherLogConfig config) {
        if (config == null) throw new IllegalArgumentException("config is required");
        this.config = config;
        this.fs = config.fileSystem();
        this.mine = Pattern.compile("^" + Pattern.quote(config.processName()) + "-\\d{13}-[0-9a-f]{8}\\.cipherlog$");
        executor = new ScheduledThreadPoolExecutor(1, new ThreadFactory() {
            @Override
            public Thread newThread(Runnable task) {
                Thread thread = new Thread(task, "cipherlog");
                thread.setDaemon(true);
                worker = thread;
                return thread;
            }
        });
        // The one worker lives as long as the writer: starting a thread later (from a crash handler, under memory
        // pressure) can fail with OutOfMemoryError, so it is started here and never times out.
        executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        executor.prestartCoreThread();
        final boolean warn = config.warnIfTestKey() && config.key().isTestKey();
        submit(new Work() {
            @Override
            public void run() throws Exception {
                if (warn) report(TEST_KEY_WARNING);
                openNewFile();
            }
        });
    }

    /** The settings. */
    public CipherLogConfig config() {
        return config;
    }

    /** False once the writer turned itself off (disk full, crypto failure) or was closed. */
    public boolean isOn() {
        return !off && !closed;
    }

    /** Queues one line. Never blocks and never throws. */
    public void log(CipherLogLevel level, String category, String message) {
        log(level, category, message, null);
    }

    /**
     * Queues one line. Never blocks and never throws, not even an {@link Error}. {@code error} is written after the
     * message as {@code <message> · <type name>: <scrubbed error message>}, without a stack trace.
     */
    public void log(final CipherLogLevel level, final String category, String message, Throwable error) {
        if (off || closed) return;
        try {
            final long time = config.clock().nowMs();
            String text = scrub(message == null ? "null" : message);
            if (error != null) text += " · " + errorText(error);
            final String line = text;
            final CipherLogLevel lvl = level == null ? CipherLogLevel.I : level;
            submit(new Work() {
                @Override
                public void run() throws Exception {
                    appendLine(time, lvl, category, line);
                }
            });
        } catch (Throwable ignored) {
            // Never throws, not even an Error (a crash handler calls this): the line is dropped.
        }
    }

    /** {@link #log} at {@link CipherLogLevel#D}. */
    public void d(String category, String message) {
        log(CipherLogLevel.D, category, message, null);
    }

    /** {@link #log} at {@link CipherLogLevel#I}. */
    public void i(String category, String message) {
        log(CipherLogLevel.I, category, message, null);
    }

    /** {@link #log} at {@link CipherLogLevel#N}. */
    public void n(String category, String message) {
        log(CipherLogLevel.N, category, message, null);
    }

    /** {@link #log} at {@link CipherLogLevel#W}. */
    public void w(String category, String message, Throwable error) {
        log(CipherLogLevel.W, category, message, error);
    }

    /** {@link #log} at {@link CipherLogLevel#E}. */
    public void e(String category, String message, Throwable error) {
        log(CipherLogLevel.E, category, message, error);
    }

    /** {@link #log} at {@link CipherLogLevel#F}. */
    public void f(String category, String message, Throwable error) {
        log(CipherLogLevel.F, category, message, error);
    }

    /** {@link #flush(long)} with 1 s. */
    public boolean flush() {
        return flush(1000);
    }

    /**
     * Writes everything queued so far and waits at most {@code timeoutMs}; true when it finished in time. Safe from any
     * thread, a crash handler included: on the worker thread itself it flushes inline (lines queued behind the current
     * task are not waited for) and never deadlocks.
     */
    public boolean flush(long timeoutMs) {
        try {
            if (Thread.currentThread() == worker) {
                if (inFileOp) return false;
                guarded(flushWork);
                return true;
            }
            return onWorker(timeoutMs, new Task<Boolean>() {
                @Override
                public Boolean run() {
                    guarded(flushWork);
                    return Boolean.TRUE;
                }
            }) != null;
        } catch (Throwable e) {
            return false;
        }
    }

    /** {@link #close(long)} with 2 s. */
    public void close() {
        close(2000);
    }

    /** Writes what is queued, closes the current file with a {@code final} record and stops taking lines. */
    public void close(long timeoutMs) {
        if (closed) return;
        closed = true;
        try {
            onWorker(timeoutMs, new Task<Boolean>() {
                @Override
                public Boolean run() {
                    guarded(new Work() {
                        @Override
                        public void run() throws Exception {
                            closeCurrent();
                        }
                    });
                    workerClosed = true;
                    return Boolean.TRUE;
                }
            });
        } catch (Throwable ignored) {
            // close never throws.
        }
    }

    /** {@link #wipe(long)} with 5 s. */
    public boolean wipe() {
        return wipe(5000);
    }

    /**
     * Sign-out or account deletion (SPEC.md 3.7): closes the current file, deletes every cipherlog file of every process
     * in the directory and every export folder in the default export root (also those of earlier runs) and in every
     * root passed to {@link #exportBundle} by this writer, then opens a new file (unless the writer is off or closed).
     * True when it finished within {@code timeoutMs}.
     */
    public boolean wipe(long timeoutMs) {
        try {
            return onWorker(timeoutMs, new Task<Boolean>() {
                @Override
                public Boolean run() throws Exception {
                    doWipe();
                    return Boolean.TRUE;
                }
            }) != null;
        } catch (Throwable e) {
            return false;
        }
    }

    /** The armored support-mail bundle in the default export root, waiting at most 10 s ({@link #exportBundle(File, boolean, long)}). */
    public File exportBundle() throws IOException {
        return exportBundle(defaultExportRoot(), true, 10_000);
    }

    /**
     * The support-mail bundle (SPEC.md 4): the files of all processes newest first until 4 MiB (older ones are
     * dropped), then a fresh in-memory file holding only the device block. Written to
     * {@code <root>/<random id>/cipherlog-<UTC yyyyMMdd-HHmm>.cipherlogs}, or {@code .cipherlogs.txt} when
     * {@code armored} (SPEC.md 4.1, the default for mail); export folders older than 7 days are deleted first.
     *
     * @throws IOException when the bundle cannot be written or the worker does not answer within {@code timeoutMs}
     */
    public File exportBundle(final File root, final boolean armored, long timeoutMs) throws IOException {
        if (root == null) throw new IllegalArgumentException("root is required");
        File result;
        try {
            result = onWorker(timeoutMs, new Task<File>() {
                @Override
                public File run() throws Exception {
                    return doExport(root, armored);
                }
            });
        } catch (IOException e) {
            throw e;
        } catch (Throwable e) {
            throw new IOException("export failed: " + Lines.typeName(e), e);
        }
        if (result == null) throw new IOException("export timed out");
        return result;
    }

    /** {@link #recentBundle(long)} with 2 s. */
    public byte[] recentBundle() {
        return recentBundle(2000);
    }

    /**
     * For crash and failure reports (SPEC.md 4): the current file after a flush, plus the previous file of this process
     * when the current one is under 4 KiB, as bundle bytes. With no open file, the newest file of this process. Null
     * when there is none or on timeout.
     */
    public byte[] recentBundle(long timeoutMs) {
        try {
            return onWorker(timeoutMs, new Task<byte[]>() {
                @Override
                public byte[] run() throws Exception {
                    return doRecent();
                }
            });
        } catch (Throwable e) {
            return null;
        }
    }

    /** {@link #previousRunBundle(long)} with 2 s. */
    public byte[] previousRunBundle() {
        return previousRunBundle(2000);
    }

    /** The newest file of the previous run of this process as bundle bytes, or null when there is none. */
    public byte[] previousRunBundle(long timeoutMs) {
        try {
            return onWorker(timeoutMs, new Task<byte[]>() {
                @Override
                public byte[] run() throws Exception {
                    return doPreviousRun();
                }
            });
        } catch (Throwable e) {
            return null;
        }
    }

    // ---- worker side --------------------------------------------------------------------------------------------

    private final Work flushWork = new Work() {
        @Override
        public void run() throws Exception {
            flushNow();
        }
    };

    private void appendLine(long time, CipherLogLevel level, String category, String text) throws Exception {
        if (workerClosed) return;
        LogFile file = ensureOpen();
        // At the start of a batch, a file deleted by another process's wipe is replaced (one check per batch).
        if (file != null && file.unflushedInput() == 0) file = replaceIfVanished(file);
        if (file == null) {
            notWritten++;
            return;
        }
        inFileOp = true;
        try {
            file.append(Lines.format(time, level, config.processName(), category, text));
            file.appLines++;
        } finally {
            inFileOp = false;
        }
        // Compressed bytes reach the file only at a flush; the uncompressed size since the last one bounds them, so the
        // file is flushed (and rotated once it really reached the limit) before it can grow past maxFileBytes unseen.
        if (level.compareTo(CipherLogLevel.W) >= 0 || file.size() + file.unflushedInput() >= config.maxFileBytes()) {
            flushNow();
        } else {
            scheduleFlush();
        }
    }

    /**
     * Another process may have wiped the directory (SPEC.md 3.7) and deleted the current file: lines written to it
     * would be lost for good, so a vanished file is dropped (no {@code final}) and a new one opens.
     */
    private LogFile replaceIfVanished(LogFile file) throws Exception {
        File path = currentFile;
        if (path == null || fs.exists(path)) return file;
        dropCurrent();
        return openNewFile();
    }

    /** The current file, or a new one when the last failed open is at least a minute old (SPEC.md 3.6). */
    private LogFile ensureOpen() throws Exception {
        if (current != null) return current;
        if (hasFailedOpen && config.clock().nowMs() - failedOpenAt < OPEN_RETRY_MS) return null;
        return openNewFile();
    }

    private void scheduleFlush() {
        if (flushScheduled) return;
        flushScheduled = true;
        try {
            executor.schedule(new Runnable() {
                @Override
                public void run() {
                    flushScheduled = false;
                    guarded(flushWork);
                }
            }, config.flushDelayMs(), TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            flushScheduled = false;
        }
    }

    private void flushNow() throws Exception {
        if (current == null) return;
        LogFile file = replaceIfVanished(current);
        if (file == null) return;
        inFileOp = true;
        try {
            file.flush();
        } finally {
            inFileOp = false;
        }
        if (file.size() >= config.maxFileBytes() && file.appLines > 0) {
            closeCurrent();
            openNewFile();
        }
    }

    private void closeCurrent() throws Exception {
        LogFile file = current;
        if (file == null) return;
        current = null;
        currentFile = null;
        try {
            inFileOp = true;
            file.finish();
        } catch (Throwable e) {
            file.abandon();
            throw e;
        } finally {
            inFileOp = false;
            closeQuietly(file.out);
        }
    }

    /** A new file: fresh random fileKey and fileId, seq 0, device block, then retention. Null when it does not open. */
    private LogFile openNewFile() throws Exception {
        if (off || workerClosed) return null;
        // Names sort by createdAt (SPEC.md 3.5): a file opened in the same millisecond as the previous one of this run
        // (fast rotation) takes the next millisecond, so the order by name stays the order of writing.
        long now = Math.max(config.clock().nowMs(), lastCreatedAt + 1);
        lastCreatedAt = now;
        byte[] fileKey = randomBytes(Format.FILE_KEY_BYTES);
        byte[] fileId = randomBytes(Format.FILE_ID_BYTES);
        LogFile file;
        File path;
        try {
            CipherLogKey key = config.key();
            byte[] header = Format.sealHeader(key.publicKey(), key.keyId(),
                    Format.headerPlain(fileKey, fileId, now, config.platform(), config.process()));
            String name = fileName(now, fileId);
            path = new File(config.directory(), name);
            OutputStream out;
            try {
                out = fs.createNew(path);
            } catch (IOException e) {
                // Disk full while opening turns the writer off; anything else is retried a minute later (SPEC.md 3.6).
                if (isDiskFull(e)) throw e;
                hasFailedOpen = true;
                failedOpenAt = now;
                return null;
            }
            try {
                inFileOp = true;
                file = new LogFile(out, fileKey, fileId, header);
            } catch (Throwable e) {
                // The header did not reach the file (disk full, crypto missing): close it and leave no empty file.
                closeQuietly(out);
                try {
                    fs.delete(path);
                } catch (Exception ignored) {
                    // Best effort.
                }
                throw e;
            } finally {
                inFileOp = false;
            }
            current = file;
            currentFile = path;
            createdThisRun.add(name);
        } finally {
            Arrays.fill(fileKey, (byte) 0);
        }
        hasFailedOpen = false;
        writeDeviceBlock(file, fileId, now);
        if (notWritten > 0) {
            long count = notWritten;
            notWritten = 0;
            appendInFileOp(file, Lines.format(now, CipherLogLevel.W, config.processName(), "cipherlog",
                    "not written " + count + " lines"));
        }
        inFileOp = true;
        try {
            file.flush();
        } finally {
            inFileOp = false;
        }
        try {
            retention();
        } catch (Exception ignored) {
            // Retention is best effort: a file it cannot delete stays until the next try.
        }
        return file;
    }

    private void appendInFileOp(LogFile file, String line) throws Exception {
        inFileOp = true;
        try {
            file.append(line);
        } finally {
            inFileOp = false;
        }
    }

    /** SPEC.md 2.5: the library's own line, then every collector's lines, all stamped with the file's createdAt. */
    private void writeDeviceBlock(LogFile file, byte[] fileId, long createdAt) throws Exception {
        String first = "cipherlog " + LibraryVersion.VERSION + " · file " + Format.hex(fileId).substring(0, 8)
                + " · platform " + config.platform() + " · process " + config.process();
        appendInFileOp(file, deviceLine(createdAt, first));
        for (CipherLogCollector collector : config.collectors()) {
            String name;
            try {
                name = collector.name();
            } catch (Exception e) {
                name = "collector";
            }
            List<String> lines = new ArrayList<>();
            try {
                List<String> raw = collector.lines();
                if (raw != null) for (String line : raw) lines.add(name + " · " + scrub(String.valueOf(line)));
            } catch (VirtualMachineError e) {
                throw e;
            } catch (Throwable e) {
                lines.clear();
                lines.add(name + " · failed " + Lines.typeName(e));
            }
            for (String line : lines) appendInFileOp(file, deviceLine(createdAt, line));
        }
    }

    private String deviceLine(long time, String text) {
        return Lines.format(time, CipherLogLevel.I, config.processName(), "device", text);
    }

    /** SPEC.md 3.4: oldest files of this process go first, but never one modified within keepFreshFor. */
    private void retention() {
        List<File> files = processFiles();
        Map<File, Long> sizes = new HashMap<>();
        long total = 0;
        for (File file : files) {
            long size = fs.length(file);
            sizes.put(file, size);
            total += size;
        }
        if (total <= config.maxProcessBytes()) return;
        long now = config.clock().nowMs();
        for (File file : files) {
            if (total <= config.maxProcessBytes()) break;
            if (file.equals(currentFile)) continue;
            if (now - fs.lastModified(file) < config.keepFreshForMs()) continue;
            if (fs.delete(file)) total -= sizes.get(file);
        }
    }

    private void doWipe() {
        try {
            guarded(new Work() {
                @Override
                public void run() throws Exception {
                    closeCurrent();
                }
            });
        } finally {
            current = null;
            currentFile = null;
        }
        for (File file : fs.list(config.directory())) {
            if (ANY_FILE.matcher(file.getName()).matches()) fs.delete(file);
        }
        // The default root is always included: exports of earlier runs live there too (exportRoots is this run's).
        Set<File> roots = new LinkedHashSet<>(exportRoots);
        roots.add(defaultExportRoot());
        for (File root : roots) deleteExports(root, -1);
        notWritten = 0;
        hasFailedOpen = false;
        guarded(new Work() {
            @Override
            public void run() throws Exception {
                openNewFile();
            }
        });
    }

    private File doExport(File root, boolean armored) throws Exception {
        guarded(flushWork);
        exportRoots.add(root);
        long now = config.clock().nowMs();
        deleteExports(root, now);
        // SPEC.md 4: newest files first until 4 MiB (device now always included), then written oldest first with
        // `device now` last.
        byte[] deviceNow = deviceNow(now);
        List<byte[]> entries = new ArrayList<>();
        long size = Format.BUNDLE_MAGIC.length + 4L + deviceNow.length;
        List<File> files = new ArrayList<>();
        for (File file : fs.list(config.directory())) {
            if (ANY_FILE.matcher(file.getName()).matches()) files.add(file);
        }
        Collections.sort(files, new Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                int byTime = Long.compare(createdAtOf(b.getName()), createdAtOf(a.getName()));
                return byTime != 0 ? byTime : b.getName().compareTo(a.getName());
            }
        });
        for (File file : files) {
            byte[] bytes;
            try {
                bytes = fs.readBytes(file);
            } catch (IOException e) {
                continue;
            }
            // A file shorter than a header (another process between create and header write) carries nothing.
            if (bytes.length < Format.HEADER_BYTES) continue;
            if (size + 4 + bytes.length > BUNDLE_LIMIT) break;
            entries.add(bytes);
            size += 4 + bytes.length;
        }
        Collections.reverse(entries);
        entries.add(deviceNow);
        byte[] bundle = Bundle.encode(entries);
        File dir = new File(root, Format.hex(randomBytes(16)));
        if (!dir.mkdirs()) throw new IOException("cannot create the export folder");
        String base = "cipherlog-" + Lines.compactMinute(now);
        File out;
        if (armored) {
            out = new File(dir, base + "." + CipherLogArmor.FILE_EXTENSION);
            Io.writeNew(out, Format.ascii(CipherLogArmor.armor(bundle)));
        } else {
            out = new File(dir, base + ".cipherlogs");
            Io.writeNew(out, bundle);
        }
        return out;
    }

    /** A closed in-memory file with only the device block ({@code device now}). */
    private byte[] deviceNow(long now) throws Exception {
        byte[] fileKey = randomBytes(Format.FILE_KEY_BYTES);
        byte[] fileId = randomBytes(Format.FILE_ID_BYTES);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        LogFile file;
        try {
            CipherLogKey key = config.key();
            byte[] header = Format.sealHeader(key.publicKey(), key.keyId(),
                    Format.headerPlain(fileKey, fileId, now, config.platform(), config.process()));
            file = new LogFile(out, fileKey, fileId, header);
        } finally {
            Arrays.fill(fileKey, (byte) 0);
        }
        boolean wasInFileOp = inFileOp;
        try {
            writeDeviceBlock(file, fileId, now);
            file.finish();
        } finally {
            file.abandon();
            inFileOp = wasInFileOp;
        }
        return out.toByteArray();
    }

    private byte[] doRecent() throws IOException {
        guarded(flushWork);
        // No open file (off, closed, or not opened yet): the newest file of this process stands in (SPEC.md 4).
        File path = current != null ? currentFile : null;
        List<File> mineFiles = processFiles();
        if (path == null) {
            if (mineFiles.isEmpty()) return null;
            path = mineFiles.get(mineFiles.size() - 1);
        }
        byte[] bytes;
        try {
            bytes = fs.readBytes(path);
        } catch (IOException e) {
            return null;
        }
        List<byte[]> entries = new ArrayList<>();
        if (bytes.length < RECENT_SMALL) {
            File previous = null;
            for (File file : mineFiles) if (file.getName().compareTo(path.getName()) < 0) previous = file;
            if (previous != null) {
                try {
                    entries.add(fs.readBytes(previous));
                } catch (IOException ignored) {
                    // The current file alone.
                }
            }
        }
        entries.add(bytes);
        return Bundle.encode(entries);
    }

    private byte[] doPreviousRun() throws IOException {
        File newest = null;
        for (File file : processFiles()) {
            if (!createdThisRun.contains(file.getName()) && fs.length(file) >= Format.HEADER_BYTES) newest = file;
        }
        if (newest == null) return null;
        return Bundle.encode(Collections.singletonList(fs.readBytes(newest)));
    }

    /**
     * Deletes the export folders directly inside {@code root}: all of them when {@code now} is negative, otherwise
     * those older than 7 days. A folder's age is that of the newest file in it, or its own when it is empty.
     */
    private void deleteExports(File root, long now) {
        File[] dirs = root.listFiles();
        if (dirs == null) return;
        for (File dir : dirs) {
            if (!dir.isDirectory() || !EXPORT_DIR.matcher(dir.getName()).matches()) continue;
            if (now >= 0 && now - folderModified(dir) <= EXPORT_MAX_AGE_MS) continue;
            Io.deleteRecursively(dir);
        }
    }

    private static long folderModified(File dir) {
        File[] files = dir.listFiles();
        if (files == null || files.length == 0) return dir.lastModified();
        long newest = Long.MIN_VALUE;
        for (File file : files) newest = Math.max(newest, file.lastModified());
        return newest;
    }

    private List<File> processFiles() {
        List<File> out = new ArrayList<>();
        for (File file : fs.list(config.directory())) {
            if (mine.matcher(file.getName()).matches()) out.add(file);
        }
        Collections.sort(out, new Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return a.getName().compareTo(b.getName());
            }
        });
        return out;
    }

    private String fileName(long createdAt, byte[] fileId) {
        return config.processName() + "-" + String.format(Locale.ROOT, "%013d", createdAt) + "-"
                + Format.hex(fileId).substring(0, 8) + ".cipherlog";
    }

    private File defaultExportRoot() {
        File root = config.exportRoot();
        return root != null ? root : new File(config.directory(), "exports");
    }

    static long createdAtOf(String name) {
        int dash = name.lastIndexOf('-');
        if (dash < 0) return 0;
        int before = name.lastIndexOf('-', dash - 1);
        try {
            return Long.parseLong(name.substring(before + 1, dash));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    // ---- plumbing -----------------------------------------------------------------------------------------------

    /** Work for the worker that may throw anything; {@link #guarded} turns failures into "off". */
    interface Work {
        void run() throws Exception;
    }

    /** Work with a result, run by {@link #onWorker}. */
    interface Task<T> {
        T run() throws Exception;
    }

    private void submit(final Work task) {
        try {
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    guarded(task);
                }
            });
        } catch (Throwable ignored) {
            // RejectedExecutionException after shutdown, or an Error from the executor: the line is dropped.
        }
    }

    /** Runs {@code task} on the worker (inline when already there) and waits at most {@code timeoutMs}; null on timeout. */
    private <T> T onWorker(long timeoutMs, final Task<T> task) throws Exception {
        if (Thread.currentThread() == worker) return inFileOp ? null : task.run();
        Future<T> future;
        try {
            future = executor.submit(new Callable<T>() {
                @Override
                public T call() throws Exception {
                    return task.run();
                }
            });
        } catch (Throwable e) {
            return null;
        }
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            throw e;
        }
    }

    /** Write, crypto and linkage failures turn the writer off (SPEC.md 3.6); nothing escapes into the executor. */
    private void guarded(Work work) {
        if (off) return;
        try {
            work.run();
        } catch (IOException e) {
            turnOff(isDiskFull(e) ? "disk full" : "write failed" + errno(e));
        } catch (GeneralSecurityException e) {
            turnOff("crypto error");
        } catch (LinkageError e) {
            // Tink missing or changed (an app that excluded it): off, never a crash.
            turnOff("crypto unavailable (" + Lines.typeName(e) + ")");
        } catch (Throwable e) {
            // RuntimeException, or an Error (OutOfMemoryError, StackOverflowError, …) that may have left the stream
            // half-written: the writer turns off instead of going on with a broken file.
            try {
                turnOff("internal error (" + Lines.typeName(e) + ")");
            } catch (Throwable ignored) {
                off = true;
            }
        }
    }

    private void turnOff(String reason) {
        if (off) return;
        off = true;
        dropCurrent();
        if (offReported.compareAndSet(false, true)) report("cipherlog off: " + reason);
    }

    private void report(String line) {
        try {
            config.diagnostics().report(line);
        } catch (Throwable ignored) {
            // A failing callback changes nothing.
        }
    }

    /** Frees the current file's compressor and closes it without a {@code final} record. */
    private void dropCurrent() {
        LogFile file = current;
        if (file != null) {
            file.abandon();
            closeQuietly(file.out);
        }
        current = null;
        currentFile = null;
    }

    private static void closeQuietly(OutputStream out) {
        try {
            out.close();
        } catch (IOException ignored) {
            // Nothing to do.
        }
    }

    private String scrub(String text) {
        try {
            String out = config.scrub().scrub(text);
            return out == null ? "" : out;
        } catch (Throwable e) {
            return "<scrub failed>";
        }
    }

    private String errorText(Throwable error) {
        String message = error.getMessage();
        return message == null ? Lines.typeName(error) : Lines.typeName(error) + ": " + scrub(message);
    }

    /** ENOSPC / EDQUOT: java.io only reports them in the message. */
    static boolean isDiskFull(IOException e) {
        String m = e.getMessage();
        if (m == null) return false;
        String lower = m.toLowerCase(Locale.ROOT);
        return lower.contains("no space left") || m.contains("ENOSPC") || lower.contains("quota exceeded")
                || m.contains("EDQUOT");
    }

    /** {@code " (EIO)"} when the message names an errno (Android: "write failed: EIO (I/O error)"), else "". */
    static String errno(IOException e) {
        String m = e.getMessage();
        if (m == null) return "";
        Matcher matcher = ERRNO.matcher(m);
        if (matcher.find()) return " (" + matcher.group(1) + ")";
        String lower = m.toLowerCase(Locale.ROOT);
        if (lower.contains("permission denied")) return " (EACCES)";
        if (lower.contains("operation not permitted")) return " (EPERM)";
        if (lower.contains("input/output error")) return " (EIO)";
        if (lower.contains("read-only file system")) return " (EROFS)";
        if (lower.contains("stale file handle") || lower.contains("stale nfs")) return " (ESTALE)";
        if (lower.contains("bad file descriptor")) return " (EBADF)";
        return "";
    }

    private byte[] randomBytes(int count) {
        byte[] out = new byte[count];
        random.nextBytes(out);
        return out;
    }

    // ---- test seams -----------------------------------------------------------------------------------------------

    /** Tests: the single worker thread is started at construction and never times out. */
    boolean keepsWorkerAlive() {
        Thread thread = worker;
        return !executor.allowsCoreThreadTimeOut() && executor.getPoolSize() == 1 && thread != null && thread.isAlive();
    }

    /** Tests and the Android facade: the path of the current file, or null. */
    File currentPath() {
        try {
            return onWorker(2000, new Task<File>() {
                @Override
                public File run() {
                    return current != null ? currentFile : null;
                }
            });
        } catch (Exception e) {
            return null;
        }
    }

    /** Tests: stops like a crash would, the current file left without a {@code final} record. */
    void simulateCrash() {
        closed = true;
        try {
            onWorker(2000, new Task<Boolean>() {
                @Override
                public Boolean run() {
                    dropCurrent();
                    workerClosed = true;
                    return Boolean.TRUE;
                }
            });
        } catch (Exception ignored) {
            // Test seam.
        }
    }
}
