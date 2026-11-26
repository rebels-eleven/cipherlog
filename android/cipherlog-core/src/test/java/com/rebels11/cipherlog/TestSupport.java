package com.rebels11.cipherlog;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Shared test helpers. Only the published TEST key from vectors/test-key.json is ever used. */
final class TestSupport {
    private TestSupport() {
    }

    static final File REPO_ROOT = new File(System.getProperty("cipherlog.repoRoot", "../.."));
    static final File VECTORS = new File(REPO_ROOT, "vectors");

    private static Map<String, Object> testKeyJson;
    private static Map<String, Object> recordsJson;

    static synchronized Map<String, Object> testKeyJson() {
        if (testKeyJson == null) testKeyJson = Json.obj(Json.parse(readText(new File(VECTORS, "test-key.json"))));
        return testKeyJson;
    }

    static synchronized Map<String, Object> recordsJson() {
        if (recordsJson == null) recordsJson = Json.obj(Json.parse(readText(new File(VECTORS, "records.json"))));
        return recordsJson;
    }

    static byte[] testPublicKey() {
        return Format.unhex((String) testKeyJson().get("publicKey"));
    }

    static byte[] testPrivateKey() {
        return Format.unhex((String) testKeyJson().get("privateKey"));
    }

    static String testKeyIdHex() {
        return (String) testKeyJson().get("keyId");
    }

    static CipherLogKey key() {
        return new CipherLogKey(testPublicKey());
    }

    static CipherLogReader reader() {
        return new CipherLogReader(Collections.singletonList(testPrivateKey()));
    }

    static File tempDir() {
        try {
            File dir = Files.createTempDirectory("cipherlog-test").toFile();
            dir.deleteOnExit();
            return dir;
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    static String readText(File file) {
        try {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    static byte[] readBytes(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    static void writeBytes(File file, byte[] bytes) {
        try {
            Files.write(file.toPath(), bytes);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    /** A clock that only moves when told to. */
    static final class Clock implements CipherLogConfig.Clock {
        private final AtomicLong now;

        Clock() {
            this(1_795_000_000_000L);
        }

        Clock(long start) {
            now = new AtomicLong(start);
        }

        @Override
        public long nowMs() {
            return now.get();
        }

        void advance(long ms) {
            now.addAndGet(ms);
        }

        void set(long ms) {
            now.set(ms);
        }
    }

    /** The writer settings the tests start from: JVM platform, process 1 named app, a fixed clock. */
    static CipherLogConfig.Builder config(File dir) {
        return config(dir, new Clock());
    }

    static CipherLogConfig.Builder config(File dir, CipherLogConfig.Clock clock) {
        return CipherLogConfig.builder(dir, key())
                .platform(CipherLogConfig.PLATFORM_JVM)
                .process(1)
                .processName("app")
                .flushDelayMs(100)
                .clock(clock);
    }

    static List<File> logFiles(File dir) {
        return logFiles(dir, null);
    }

    static List<File> logFiles(File dir, String processName) {
        File[] all = dir.listFiles();
        List<File> out = new ArrayList<>();
        if (all == null) return out;
        for (File f : all) {
            if (f.getName().endsWith(".cipherlog") && (processName == null || f.getName().startsWith(processName + "-"))) {
                out.add(f);
            }
        }
        Collections.sort(out, Comparator.comparing(File::getName));
        return out;
    }

    static File single(List<File> files) {
        if (files.size() != 1) throw new AssertionError("expected one file, got " + files);
        return files.get(0);
    }

    static CipherLogFile read(File file) {
        return reader().readFile(readBytes(file), file.getName());
    }

    /** Lines without the time stamp, to compare text without caring about the clock. */
    static List<String> bodies(CipherLogFile file) {
        List<String> out = new ArrayList<>();
        for (String line : file.lines()) out.add(line.substring(line.indexOf(' ') + 1));
        return out;
    }

    static String repeat(String s, int n) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < n; i++) out.append(s);
        return out.toString();
    }

    static byte[] concat(byte[]... parts) {
        return Format.concat(parts);
    }

    static List<byte[]> list(byte[]... items) {
        return new ArrayList<>(Arrays.asList(items));
    }
}
