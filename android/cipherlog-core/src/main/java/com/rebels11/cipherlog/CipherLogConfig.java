package com.rebels11.cipherlog;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Settings of one {@link CipherLog} writer (SPEC.md 7). Made with {@link #builder(File, CipherLogKey)}; immutable.
 */
public final class CipherLogConfig {
    /** Header platform value (SPEC.md 2.1): unknown. */
    public static final int PLATFORM_UNKNOWN = 0;
    /** Header platform value: Apple (iOS, macOS). */
    public static final int PLATFORM_APPLE = 1;
    /** Header platform value: Android. */
    public static final int PLATFORM_ANDROID = 2;
    /** Header platform value: JVM. */
    public static final int PLATFORM_JVM = 3;

    /** Runs over every message, error message and collector line before it is written; masking is the app's job. */
    public interface Scrub {
        /** The text to write instead of {@code text}. */
        String scrub(String text);
    }

    /** Receives {@code cipherlog off: <reason>} (and the test-key warning). Called on the worker thread. */
    public interface Diagnostics {
        /** One line; must not wait for the main thread. */
        void report(String line);
    }

    /** The time in ms since the epoch (UTC); tests inject their own. */
    public interface Clock {
        /** Now, in ms since the epoch. */
        long nowMs();
    }

    private final File directory;
    private final CipherLogKey key;
    private final int platform;
    private final int process;
    private final String processName;
    private final List<CipherLogCollector> collectors;
    private final Scrub scrub;
    private final Diagnostics diagnostics;
    private final long maxFileBytes;
    private final long maxProcessBytes;
    private final long keepFreshForMs;
    private final long flushDelayMs;
    private final File exportRoot;
    private final Clock clock;
    private final CipherLogFileSystem fileSystem;
    private final boolean warnIfTestKey;

    private CipherLogConfig(Builder b) {
        directory = b.directory;
        key = b.key;
        platform = b.platform;
        process = b.process;
        processName = b.processName.isEmpty() ? "-" : Lines.name(b.processName);
        collectors = Collections.unmodifiableList(new ArrayList<>(b.collectors));
        scrub = b.scrub;
        diagnostics = b.diagnostics;
        maxFileBytes = b.maxFileBytes;
        maxProcessBytes = b.maxProcessBytes;
        keepFreshForMs = b.keepFreshForMs;
        flushDelayMs = b.flushDelayMs;
        exportRoot = b.exportRoot;
        clock = b.clock;
        fileSystem = b.fileSystem;
        warnIfTestKey = b.warnIfTestKey;
    }

    /** A builder with the defaults of SPEC.md 7 for {@code directory} and {@code key}. */
    public static Builder builder(File directory, CipherLogKey key) {
        return new Builder(directory, key);
    }

    /** Where {@code *.cipherlog} files live; may be shared by several processes (each with its own process name). */
    public File directory() {
        return directory;
    }

    /** The developer's public key. */
    public CipherLogKey key() {
        return key;
    }

    /** Written into every header: 0 unknown, 1 Apple, 2 Android, 3 JVM. */
    public int platform() {
        return platform;
    }

    /** An app-chosen number 0..255 (for example 1 main app), written into every header. */
    public int process() {
        return process;
    }

    /** The process name after the charset rule (SPEC.md 2.4); an empty name becomes {@code -}. */
    public String processName() {
        return processName;
    }

    /** Sources of the device block at the start of every file. */
    public List<CipherLogCollector> collectors() {
        return collectors;
    }

    /** The scrub hook (identity by default). */
    public Scrub scrub() {
        return scrub;
    }

    /** The diagnostics callback (none by default). */
    public Diagnostics diagnostics() {
        return diagnostics;
    }

    /** A file that reaches this size is closed and a new one opened (default 256 KiB). */
    public long maxFileBytes() {
        return maxFileBytes;
    }

    /** This process keeps at most this many bytes of files (default 2 MiB). */
    public long maxProcessBytes() {
        return maxProcessBytes;
    }

    /** Files modified less than this long ago are never deleted by retention (default 10 min). */
    public long keepFreshForMs() {
        return keepFreshForMs;
    }

    /** Lines below {@code W} are flushed this long after the first unflushed line (default 100 ms). */
    public long flushDelayMs() {
        return flushDelayMs;
    }

    /** The default export root; {@code null} means {@code <directory>/exports}. */
    public File exportRoot() {
        return exportRoot;
    }

    /** The clock. */
    public Clock clock() {
        return clock;
    }

    /** The file operations. */
    public CipherLogFileSystem fileSystem() {
        return fileSystem;
    }

    /** Whether a start with the test key reports a warning to diagnostics (set for release builds). */
    public boolean warnIfTestKey() {
        return warnIfTestKey;
    }

    /** Builds a {@link CipherLogConfig}. Not thread-safe. */
    public static final class Builder {
        private final File directory;
        private final CipherLogKey key;
        private int platform = detectPlatform();
        private int process = 1;
        private String processName = "app";
        private final List<CipherLogCollector> collectors = new ArrayList<>();
        private Scrub scrub = IDENTITY;
        private Diagnostics diagnostics = NO_DIAGNOSTICS;
        private long maxFileBytes = 256L * 1024;
        private long maxProcessBytes = 2L * 1024 * 1024;
        private long keepFreshForMs = 10L * 60 * 1000;
        private long flushDelayMs = 100L;
        private File exportRoot;
        private Clock clock = SYSTEM_CLOCK;
        private CipherLogFileSystem fileSystem = CipherLogFileSystem.DEFAULT;
        private boolean warnIfTestKey = false;

        private Builder(File directory, CipherLogKey key) {
            if (directory == null || key == null) throw new IllegalArgumentException("directory and key are required");
            this.directory = directory;
            this.key = key;
        }

        /** 0 unknown, 1 Apple, 2 Android, 3 JVM; default: 2 on Android, 3 elsewhere. */
        public Builder platform(int platform) {
            if (platform < 0 || platform > 255) throw new IllegalArgumentException("platform is a u8");
            this.platform = platform;
            return this;
        }

        /** An app-chosen number 0..255 (default 1, the main app). */
        public Builder process(int process) {
            if (process < 0 || process > 255) throw new IllegalArgumentException("process is a u8");
            this.process = process;
            return this;
        }

        /** The process name in every line and file name (default {@code app}); {@code [A-Za-z0-9._-]}, 32 at most. */
        public Builder processName(String processName) {
            this.processName = processName == null ? "" : processName;
            return this;
        }

        /** Replaces the collectors. */
        public Builder collectors(List<? extends CipherLogCollector> collectors) {
            this.collectors.clear();
            if (collectors != null) for (CipherLogCollector c : collectors) addCollector(c);
            return this;
        }

        /** Adds one collector. */
        public Builder addCollector(CipherLogCollector collector) {
            if (collector != null) collectors.add(collector);
            return this;
        }

        /** The scrub hook; null restores identity. */
        public Builder scrub(Scrub scrub) {
            this.scrub = scrub == null ? IDENTITY : scrub;
            return this;
        }

        /** The diagnostics callback; null removes it. */
        public Builder diagnostics(Diagnostics diagnostics) {
            this.diagnostics = diagnostics == null ? NO_DIAGNOSTICS : diagnostics;
            return this;
        }

        /** Rotation size (default 256 KiB). */
        public Builder maxFileBytes(long bytes) {
            if (bytes <= 0) throw new IllegalArgumentException("maxFileBytes must be positive");
            maxFileBytes = bytes;
            return this;
        }

        /** Retention size per process (default 2 MiB). */
        public Builder maxProcessBytes(long bytes) {
            if (bytes <= 0) throw new IllegalArgumentException("maxProcessBytes must be positive");
            maxProcessBytes = bytes;
            return this;
        }

        /** Files younger than this are never deleted by retention (default 10 min). */
        public Builder keepFreshForMs(long ms) {
            if (ms < 0) throw new IllegalArgumentException("keepFreshForMs must not be negative");
            keepFreshForMs = ms;
            return this;
        }

        /** Flush delay for lines below {@code W} (default 100 ms). */
        public Builder flushDelayMs(long ms) {
            if (ms < 0) throw new IllegalArgumentException("flushDelayMs must not be negative");
            flushDelayMs = ms;
            return this;
        }

        /** The default root of {@code exportBundle}; null means {@code <directory>/exports}. */
        public Builder exportRoot(File exportRoot) {
            this.exportRoot = exportRoot;
            return this;
        }

        /** The clock (tests). */
        public Builder clock(Clock clock) {
            this.clock = clock == null ? SYSTEM_CLOCK : clock;
            return this;
        }

        /** The file operations (tests inject failures). */
        public Builder fileSystem(CipherLogFileSystem fileSystem) {
            this.fileSystem = fileSystem == null ? CipherLogFileSystem.DEFAULT : fileSystem;
            return this;
        }

        /**
         * Report a warning to diagnostics at every start when the key is the published test key (SPEC.md 7.1). Set it
         * for release builds; the Android facade sets it when the app is not debuggable.
         */
        public Builder warnIfTestKey(boolean warn) {
            warnIfTestKey = warn;
            return this;
        }

        /** The config. */
        public CipherLogConfig build() {
            return new CipherLogConfig(this);
        }
    }

    private static final Scrub IDENTITY = new Scrub() {
        @Override
        public String scrub(String text) {
            return text;
        }
    };

    private static final Diagnostics NO_DIAGNOSTICS = new Diagnostics() {
        @Override
        public void report(String line) {
        }
    };

    private static final Clock SYSTEM_CLOCK = new Clock() {
        @Override
        public long nowMs() {
            return System.currentTimeMillis();
        }
    };

    private static int detectPlatform() {
        String vm = System.getProperty("java.vm.name", "");
        String vendor = System.getProperty("java.vendor", "");
        return vm.contains("Dalvik") || vendor.contains("Android") ? PLATFORM_ANDROID : PLATFORM_JVM;
    }
}
