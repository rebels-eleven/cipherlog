package com.rebels11.cipherlog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;

/**
 * vectors/samples/&lt;impl&gt;/ (SPEC.md 8): this implementation's samples and every other implementation's.
 *
 * <p>{@code CIPHERLOG_WRITE_SAMPLES=1 ./gradlew :cipherlog-core:test --tests '*SamplesTest*'} rewrites
 * vectors/samples/java/.
 */
public class SamplesTest {
    private final File samples = new File(TestSupport.VECTORS, "samples");

    private static final String[][] EVENTS = {
        {"D", "boot: cold start"},
        {"I", "net: GET /status 200 in 84 ms"},
        {"N", "auth: signed in"},
        {"I", "ui: Grüße aus München, ünïcödé ✓"},
        {"I", "ui: 日本語のテキスト"},
        {"I", "ui: emoji 🦭🎉"},
        {"D", "cache: 12 items, 3.4 MB"},
        {"W", "net: retry 1 of 3"},
        {"I", "sync: started"},
        {"D", "sync: page 1"},
        {"D", "sync: page 2"},
        {"I", "sync: done, 42 changes"},
        {"E", "db: write failed"},
        {"I", "player: tab\there"},
        {"I", "player: line one\nline two"},
        {"N", "push: token refreshed"},
        {"D", "camera: preview 1920x1080"},
        {"I", "share: sheet opened"},
        {"W", "storage: 91% full"},
        {"I", "widget: timeline reloaded"},
        {"F", "crash: fatal state"},
        {"I", "app: background"},
    };

    @Test
    public void writeJavaSamples() {
        assumeTrue("1".equals(System.getenv("CIPHERLOG_WRITE_SAMPLES")));
        File out = new File(samples, "java");
        assertTrue(out.isDirectory() || out.mkdirs());
        byte[] closed = writeSample(true);
        byte[] unclosed = writeSample(false);
        TestSupport.writeBytes(new File(out, "sample.cipherlog"), closed);
        TestSupport.writeBytes(new File(out, "unclosed.cipherlog"), unclosed);
        TestSupport.writeBytes(new File(out, "expected.txt"), expectedText(closed).getBytes(Format.UTF_8));
        TestSupport.writeBytes(new File(out, "unclosed.expected.txt"), expectedText(unclosed).getBytes(Format.UTF_8));
        byte[] bundle = Bundle.encode(TestSupport.list(closed, unclosed));
        TestSupport.writeBytes(new File(out, "sample.cipherlogs"), bundle);
        TestSupport.writeBytes(new File(out, "sample.cipherlogs.txt"), Format.ascii(CipherLogArmor.armor(bundle)));
    }

    /** One file written by the real writer with a clock that ticks 1 ms per reading. */
    private byte[] writeSample(boolean close) {
        File dir = TestSupport.tempDir();
        final AtomicLong tick = new AtomicLong(1_795_000_000_000L);
        CipherLog log = new CipherLog(CipherLogConfig.builder(dir, TestSupport.key())
                .platform(CipherLogConfig.PLATFORM_ANDROID)
                .process(1)
                .processName("sample")
                .addCollector(CipherLogCollector.of("phone",
                        () -> Collections.singletonList("Pixel 9 · Android 16 (API 36)")))
                .clock(tick::getAndIncrement)
                .build());
        // The first file opens on the worker: wait for it so the device block's times come first, deterministically.
        if (!log.flush(5000)) throw new AssertionError("flush timed out");
        for (String[] event : EVENTS) {
            CipherLogLevel level = CipherLogLevel.valueOf(event[0]);
            String text = event[1];
            String category = text.substring(0, text.indexOf(": "));
            String message = text.substring(text.indexOf(": ") + 2);
            if (level == CipherLogLevel.E) log.log(level, category, message, new IllegalStateException("disk I/O"));
            else log.log(level, category, message);
        }
        if (close) {
            log.close();
        } else {
            if (!log.flush(5000)) throw new AssertionError("flush timed out");
            log.simulateCrash();
        }
        byte[] bytes = TestSupport.readBytes(TestSupport.single(TestSupport.logFiles(dir)));
        int offset = 118;
        int records = 0;
        while (offset < bytes.length) {
            offset += 9 + (int) Format.readU32(bytes, offset);
            records++;
        }
        if (records < 3) throw new AssertionError("only " + records + " records");
        return bytes;
    }

    /** The text, cross-checked against an independent rendering of the same events. */
    private String expectedText(byte[] bytes) {
        Format.HeaderPlain header = Format.openHeader(TestSupport.testPrivateKey(), Arrays.copyOfRange(bytes, 4, 12),
                Arrays.copyOfRange(bytes, 12, 118));
        String text = TestSupport.reader().readFile(bytes).text();
        String fileId8 = Format.hex(header.fileId).substring(0, 8);
        String[] lines = text.split("\n");
        check(lines[0].endsWith("I sample device: cipherlog " + LibraryVersion.VERSION + " · file " + fileId8
                + " · platform 2 · process 1"));
        check(text.contains(" E sample db: write failed · IllegalStateException: disk I/O\n"));
        check(text.contains(" I sample player: line one\\nline two\n"));
        check(text.contains(" I sample ui: 日本語のテキスト\n"));
        check(lines.length == 2 + EVENTS.length);
        for (int i = 0; i < EVENTS.length; i++) {
            String event = EVENTS[i][1].replace("\n", "\\n");
            String line = lines[2 + i];
            check(line.startsWith(Lines.time(1_795_000_000_001L + i) + " " + EVENTS[i][0] + " sample "));
            check(line.contains(" sample " + event));
        }
        return text;
    }

    private static void check(boolean ok) {
        if (!ok) throw new AssertionError("sample check failed");
    }

    @Test
    public void readEverySampleDirectory() {
        File[] all = samples.listFiles();
        List<File> dirs = new ArrayList<>();
        if (all != null) for (File f : all) if (f.isDirectory()) dirs.add(f);
        Collections.sort(dirs, Comparator.comparing(File::getName));
        assertTrue("vectors/samples/java must exist", new File(samples, "java").isDirectory());
        int checked = 0;
        List<String> seen = new ArrayList<>();
        for (File dir : dirs) {
            String name = dir.getName();
            File sample = new File(dir, "sample.cipherlog");
            File expected = new File(dir, "expected.txt");
            if (sample.isFile() && expected.isFile()) {
                CipherLogFile file = TestSupport.reader().readFile(TestSupport.readBytes(sample), name + "/sample.cipherlog");
                assertTrue(name + ": " + file.notes(), file.opened());
                assertEquals(name + "/sample.cipherlog", TestSupport.readText(expected), file.text());
                assertTrue(name + "/sample.cipherlog must be closed: " + file.notes(), file.closed());
                assertEquals(name + ": " + file.notes(), Collections.emptyList(), file.notes());
                // SPEC.md 4.1: an armored payload may be a single file, not only a bundle.
                byte[] armored = Format.ascii(CipherLogArmor.armor(TestSupport.readBytes(sample)));
                CipherLogReadResult fromArmor = TestSupport.reader().read(armored, name + "/sample.cipherlog.txt");
                assertEquals(name + " armored file: " + fromArmor.notes(), Collections.emptyList(), fromArmor.notes());
                assertEquals(name + " armored file", 1, fromArmor.files().size());
                assertEquals(name + " armored file", TestSupport.readText(expected), fromArmor.files().get(0).text());
                assertTrue(name + " armored file", fromArmor.files().get(0).closed());
                checked++;
                seen.add(name);
            } else {
                assertFalse(name + " has no sample", name.equals("java"));
            }
            File unclosed = new File(dir, "unclosed.cipherlog");
            File unclosedExpected = new File(dir, "unclosed.expected.txt");
            if (unclosed.isFile() && unclosedExpected.isFile()) {
                CipherLogFile file = TestSupport.reader().readFile(TestSupport.readBytes(unclosed), name + "/unclosed.cipherlog");
                assertEquals(name + "/unclosed.cipherlog", TestSupport.readText(unclosedExpected), file.text());
                assertFalse(name + "/unclosed.cipherlog must not be closed", file.closed());
                assertEquals(Collections.singletonList("not closed (crash or still open), completeness unknown"), file.notes());
                checked++;
            }
            for (String bundleName : new String[] {"sample.cipherlogs", "sample.cipherlogs.txt"}) {
                File bundle = new File(dir, bundleName);
                if (!bundle.isFile()) continue;
                CipherLogReadResult result = TestSupport.reader().read(TestSupport.readBytes(bundle), bundleName);
                assertEquals(name + "/" + bundleName, Collections.emptyList(), result.notes());
                boolean closedFound = !expected.isFile();
                boolean unclosedFound = !unclosedExpected.isFile();
                for (CipherLogFile f : result.files()) {
                    if (expected.isFile() && f.closed() && f.text().equals(TestSupport.readText(expected))) closedFound = true;
                    if (unclosedExpected.isFile() && !f.closed() && f.text().equals(TestSupport.readText(unclosedExpected))) {
                        unclosedFound = true;
                    }
                }
                assertTrue(name + "/" + bundleName, closedFound && unclosedFound);
                checked++;
            }
        }
        assertTrue(seen.toString(), seen.contains("java"));
        assertTrue(checked >= 3);
    }
}
