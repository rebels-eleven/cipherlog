package com.rebels11.cipherlog;

import static com.rebels11.cipherlog.TestSupport.bodies;
import static com.rebels11.cipherlog.TestSupport.config;
import static com.rebels11.cipherlog.TestSupport.logFiles;
import static com.rebels11.cipherlog.TestSupport.read;
import static com.rebels11.cipherlog.TestSupport.readBytes;
import static com.rebels11.cipherlog.TestSupport.single;
import static com.rebels11.cipherlog.TestSupport.tempDir;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;

public class WriterTest {
    private final SecureRandom random = new SecureRandom();

    private String noise(int chars) {
        byte[] bytes = new byte[chars / 2];
        random.nextBytes(bytes);
        return Format.hex(bytes);
    }

    @Test
    public void roundTrip() {
        File dir = tempDir();
        TestSupport.Clock clock = new TestSupport.Clock(1_795_000_000_123L);
        CipherLog log = new CipherLog(config(dir, clock)
                .addCollector(CipherLogCollector.of("phone", () -> Collections.singletonList("Pixel 9 · Android 16")))
                .build());
        assertTrue(log.flush(2000));
        log.log(CipherLogLevel.I, "spotify", "connect");
        clock.advance(5);
        log.log(CipherLogLevel.D, null, "héllo wörld ✓ 🦭");
        log.log(CipherLogLevel.E, "net", "request failed", new IOException("timeout\nat host"));
        log.close();
        assertFalse(log.isOn());

        File path = single(logFiles(dir));
        CipherLogFile file = read(path);
        assertTrue(file.notes().toString(), file.closed());
        assertEquals(Collections.emptyList(), file.notes());
        assertEquals(Integer.valueOf(3), file.platform());
        assertEquals(Integer.valueOf(1), file.process());
        assertEquals(Long.valueOf(1_795_000_000_123L), file.createdAt());
        List<String> lines = file.lines();
        String id8 = file.fileIdHex().substring(0, 8);
        assertEquals("2026-11-18T11:06:40.123Z I app device: cipherlog " + LibraryVersion.VERSION + " · file " + id8
                + " · platform 3 · process 1", lines.get(0));
        assertEquals("2026-11-18T11:06:40.123Z I app device: phone · Pixel 9 · Android 16", lines.get(1));
        assertEquals("2026-11-18T11:06:40.123Z I app spotify: connect", lines.get(2));
        assertEquals("2026-11-18T11:06:40.128Z D app -: héllo wörld ✓ 🦭", lines.get(3));
        assertEquals("2026-11-18T11:06:40.128Z E app net: request failed · IOException: timeout\\nat host", lines.get(4));
        assertEquals(5, lines.size());
        assertTrue(file.text().endsWith("\n"));
        // The name: <process name>-<createdAt, 13 digits>-<fileId, 8 hex>.cipherlog
        assertEquals("app-1795000000123-" + id8 + ".cipherlog", path.getName());
    }

    @Test
    public void versionComesFromGradleProperties() {
        assertTrue(LibraryVersion.VERSION, LibraryVersion.VERSION.matches("\\d+\\.\\d+\\.\\d+(-[0-9A-Za-z.]+)?"));
    }

    @Test
    public void noStackTraceInLines() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        IllegalStateException error = new IllegalStateException("bad state", new RuntimeException("cause"));
        log.log(CipherLogLevel.E, "x", "failed", error);
        log.close();
        String text = read(single(logFiles(dir))).text();
        assertTrue(text.contains("failed · IllegalStateException: bad state\n"));
        assertFalse(text.contains("\tat "));
        assertFalse(text.contains("WriterTest"));
    }

    @Test
    public void scrubRunsOverMessagesAndErrors() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).scrub(t -> t.replaceAll("[0-9]{4,}", "<n>")).build());
        log.log(CipherLogLevel.I, "pay", "card 4242424242424242", new RuntimeException("id 123456"));
        log.close();
        assertTrue(read(single(logFiles(dir))).text().contains("I app pay: card <n> · RuntimeException: id <n>\n"));
    }

    @Test
    public void newFileEveryStartWithNewKeyAndSeqZero() {
        File dir = tempDir();
        TestSupport.Clock clock = new TestSupport.Clock();
        for (int i = 0; i < 3; i++) {
            CipherLog log = new CipherLog(config(dir, clock).build());
            log.log(CipherLogLevel.I, null, "run " + i);
            log.close();
            clock.advance(1000);
        }
        List<File> files = logFiles(dir);
        assertEquals(3, files.size());
        Set<String> keys = new HashSet<>();
        List<String> last = new ArrayList<>();
        for (File file : files) {
            byte[] bytes = readBytes(file);
            Format.HeaderPlain header = Format.openHeader(TestSupport.testPrivateKey(), Arrays.copyOfRange(bytes, 4, 12),
                    Arrays.copyOfRange(bytes, 12, 118));
            assertNotNull(header);
            // The first record has seq 0.
            assertEquals(0L, Format.readU32(bytes, 118 + 4));
            CipherLogFile read = read(file);
            assertTrue(read.closed());
            keys.add(Format.hex(header.fileKey) + Format.hex(header.fileId));
            String line = read.lines().get(read.lines().size() - 1);
            last.add(line.substring(line.indexOf("-: ") + 3));
        }
        assertEquals(3, keys.size());
        assertEquals(Arrays.asList("run 0", "run 1", "run 2"), last);
    }

    @Test
    public void truncationAtEveryByteOfTheLastRecord() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        log.log(CipherLogLevel.I, "a", "one");
        log.log(CipherLogLevel.W, "a", "two");
        log.log(CipherLogLevel.W, "a", "three");
        log.close();
        byte[] bytes = readBytes(single(logFiles(dir)));
        CipherLogFile full = TestSupport.reader().readFile(bytes);
        assertTrue(full.closed());
        int offset = 118;
        int lastStart = offset;
        while (offset < bytes.length) {
            lastStart = offset;
            offset += 9 + (int) Format.readU32(bytes, offset);
        }
        assertEquals(bytes.length, offset);
        for (int cut = lastStart; cut < bytes.length; cut++) {
            CipherLogFile result = TestSupport.reader().readFile(Arrays.copyOf(bytes, cut));
            assertFalse("cut " + cut, result.closed());
            assertEquals("cut " + cut, full.records() - 1, result.records());
            // The final record carries only the end of the stream, so every line is still there.
            assertEquals("cut " + cut, full.text(), result.text());
            assertTrue(result.notes().contains("not closed (crash or still open), completeness unknown"));
            if (cut > lastStart) {
                boolean truncated = false;
                for (String note : result.notes()) truncated |= note.contains("truncated");
                assertTrue(result.notes().toString(), truncated);
            }
        }
    }

    @Test
    public void corruptionInTheMiddleStopsAtThatRecord() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        log.log(CipherLogLevel.W, "a", "first");
        log.log(CipherLogLevel.W, "a", "second");
        log.log(CipherLogLevel.W, "a", "third");
        log.close();
        byte[] bytes = readBytes(single(logFiles(dir)));
        List<Integer> starts = new ArrayList<>();
        int offset = 118;
        while (offset < bytes.length) {
            starts.add(offset);
            offset += 9 + (int) Format.readU32(bytes, offset);
        }
        assertTrue(starts.size() >= 4);
        // Record 2 holds "second": flip one ciphertext byte of it.
        byte[] damaged = bytes.clone();
        damaged[starts.get(2) + 12] ^= 1;
        CipherLogFile result = TestSupport.reader().readFile(damaged);
        assertEquals(2, result.records());
        assertTrue(result.notes().toString(), result.notes().contains("readable up to record 2 (authentication failed)"));
        assertFalse(result.closed());
        assertTrue(result.text().contains("W app a: first\n"));
        assertFalse(result.text().contains("second"));
    }

    @Test
    public void dataAfterFinalIsNoted() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        log.log(CipherLogLevel.W, "a", "closed");
        log.close();
        byte[] bytes = readBytes(single(logFiles(dir)));
        CipherLogFile result = TestSupport.reader().readFile(TestSupport.concat(bytes, new byte[] {1, 2, 3}));
        assertTrue(result.closed());
        assertEquals(1, result.notes().size());
        assertTrue(result.notes().get(0), result.notes().get(0).endsWith("(data after final)"));
        assertTrue(result.text().contains("closed"));
    }

    @Test
    public void fileWithoutFinalIsNotClosed() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        log.log(CipherLogLevel.I, "a", "still writing");
        assertTrue(log.flush(2000));
        CipherLogFile file = read(single(logFiles(dir)));
        assertFalse(file.closed());
        assertEquals(Collections.singletonList("not closed (crash or still open), completeness unknown"), file.notes());
        assertTrue(file.text().endsWith("I app a: still writing\n"));
        log.close();
        assertTrue(read(single(logFiles(dir))).closed());
    }

    @Test
    public void linesBelowWarningAreFlushedAfterTheDelay() throws Exception {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        assertTrue(log.flush(2000));
        log.log(CipherLogLevel.D, "a", "later");
        long deadline = System.currentTimeMillis() + 3000;
        while (!read(single(logFiles(dir))).text().contains("later") && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        assertTrue(read(single(logFiles(dir))).text().contains("D app a: later\n"));
        log.close();
    }

    @Test
    public void rotationAtMaxFileBytes() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).maxFileBytes(2000).build());
        List<String> sent = new ArrayList<>();
        for (int i = 0; i < 60; i++) sent.add("line " + i + " " + noise(100));
        for (String line : sent) log.log(CipherLogLevel.I, "r", line);
        log.close();
        List<File> files = logFiles(dir);
        assertTrue("files: " + files.size(), files.size() >= 3);
        List<String> got = new ArrayList<>();
        for (File f : files) {
            CipherLogFile file = read(f);
            assertTrue(file.notes().toString(), file.closed());
            assertTrue(file.lines().get(0).contains(" I app device: cipherlog "));
            for (String body : bodies(file)) if (body.startsWith("I app r: ")) got.add(body.substring(9));
        }
        // Every file but the last reached the limit.
        for (File f : files.subList(0, files.size() - 1)) assertTrue(f.length() >= 2000);
        assertEquals(sent, got);
    }

    @Test
    public void recordsStayWithinBoundsForHugeBatches() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).maxFileBytes(1024L * 1024).build());
        String big = noise(300_000);
        log.log(CipherLogLevel.I, "big", big);
        log.close();
        File file = single(logFiles(dir));
        byte[] bytes = readBytes(file);
        int offset = 118;
        int records = 0;
        while (offset < bytes.length) {
            long len = Format.readU32(bytes, offset);
            assertTrue(len >= 16 && len <= 65552);
            offset += 9 + (int) len;
            records++;
        }
        assertTrue("records: " + records, records >= 3);
        assertTrue(read(file).text().contains(big));
    }

    @Test
    public void retentionKeepsTheProcessUnderTheLimit() {
        File dir = tempDir();
        // The clock runs a day ahead of the files' real modification times: every closed file is old.
        TestSupport.Clock clock = new TestSupport.Clock(System.currentTimeMillis() + 24L * 60 * 60 * 1000);
        CipherLog other = new CipherLog(config(dir, clock).processName("widget").build());
        other.log(CipherLogLevel.I, null, "other process");
        other.close();
        CipherLog log = new CipherLog(config(dir, clock).maxFileBytes(2000).maxProcessBytes(6000).build());
        for (int i = 0; i < 100; i++) {
            clock.advance(1);
            log.log(CipherLogLevel.I, "r", noise(100));
        }
        assertTrue(log.flush(5000));
        File current = log.currentPath();
        assertNotNull(current);
        List<File> mine = logFiles(dir, "app");
        long closedTotal = 0;
        for (File f : mine) if (!f.equals(current)) closedTotal += f.length();
        assertTrue("closed files: " + closedTotal, closedTotal <= 6000);
        assertTrue(mine.size() >= 2);
        // The newest files stay, the oldest went.
        assertTrue(mine.size() < 100 * 100 / 2000);
        // Another process's files are not this process's to delete.
        assertEquals(1, logFiles(dir, "widget").size());
        log.close();
    }

    @Test
    public void retentionNeverDeletesFreshFiles() {
        File dir = tempDir();
        TestSupport.Clock clock = new TestSupport.Clock(System.currentTimeMillis());
        CipherLog log = new CipherLog(config(dir, clock).maxFileBytes(2000).maxProcessBytes(3000).build());
        for (int i = 0; i < 60; i++) log.log(CipherLogLevel.I, "r", noise(100));
        log.close();
        List<File> files = logFiles(dir, "app");
        long total = 0;
        int lines = 0;
        for (File f : files) {
            total += f.length();
            for (String line : read(f).lines()) if (line.contains(" I app r: ")) lines++;
        }
        assertTrue(total > 3000);
        // Every file was modified within the last 10 minutes: none went.
        assertEquals(60, lines);
    }

    @Test
    public void collectorsIncludingAThrowingOne() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir)
                .addCollector(CipherLogCollector.of("phone", () -> Arrays.asList("Pixel 9", "Android 16")))
                .addCollector(CipherLogCollector.of("app", () -> {
                    throw new IllegalStateException("no version");
                }))
                .addCollector(CipherLogCollector.of("empty", Collections::emptyList))
                .addCollector(CipherLogCollector.of("net", () -> Collections.singletonList("wifi\nup")))
                .build());
        log.close();
        List<String> lines = bodies(read(single(logFiles(dir))));
        assertEquals(Arrays.asList(
                "I app device: phone · Pixel 9",
                "I app device: phone · Android 16",
                "I app device: app · failed IllegalStateException",
                "I app device: net · wifi\\nup"), lines.subList(1, lines.size()));
    }

    @Test
    public void collectorLinesPassThroughScrub() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir)
                .scrub(t -> t.replace("secret", "***"))
                .addCollector(CipherLogCollector.of("acct", () -> Collections.singletonList("secret token")))
                .build());
        log.close();
        assertTrue(read(single(logFiles(dir))).text().contains("I app device: acct · *** token\n"));
    }

    @Test
    public void flushFromTheWorkerThreadRunsInline() {
        File dir = tempDir();
        AtomicReference<CipherLog> ref = new AtomicReference<>();
        AtomicReference<Boolean> inlineResult = new AtomicReference<>();
        AtomicLong inlineMs = new AtomicLong(-1);
        CipherLogCollector collector = CipherLogCollector.of("probe", () -> {
            while (ref.get() == null) Thread.sleep(1);
            long started = System.nanoTime();
            inlineResult.set(ref.get().flush(10_000));
            inlineMs.set((System.nanoTime() - started) / 1_000_000);
            return Collections.singletonList("ok");
        });
        CipherLog log = new CipherLog(config(dir).addCollector(collector).build());
        ref.set(log);
        assertTrue(log.flush(5000));
        assertEquals(Boolean.TRUE, inlineResult.get());
        assertTrue("inline flush took " + inlineMs.get() + " ms", inlineMs.get() >= 0 && inlineMs.get() <= 1000);
        log.close();
        assertTrue(read(single(logFiles(dir))).text().contains("probe · ok"));
    }

    @Test
    public void flushHonoursItsTimeout() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).addCollector(CipherLogCollector.of("slow", () -> {
            Thread.sleep(1500);
            return Collections.singletonList("done");
        })).build());
        long started = System.nanoTime();
        boolean result = log.flush(100);
        long ms = (System.nanoTime() - started) / 1_000_000;
        assertFalse(result);
        assertTrue("flush waited " + ms + " ms", ms < 1000);
        assertTrue(log.flush(5000));
        log.close();
    }

    @Test
    public void logNeverBlocks() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).addCollector(CipherLogCollector.of("slow", () -> {
            Thread.sleep(1000);
            return Collections.singletonList("done");
        })).build());
        long started = System.nanoTime();
        for (int i = 0; i < 10_000; i++) log.log(CipherLogLevel.D, "q", "line " + i);
        long ms = (System.nanoTime() - started) / 1_000_000;
        assertTrue("10k log calls took " + ms + " ms", ms < 900);
        log.close(10_000);
        int count = 0;
        for (String line : read(single(logFiles(dir))).lines()) if (line.contains(" D app q: line ")) count++;
        assertEquals(10_000, count);
    }

    @Test
    public void wipeDeletesEverythingAndOpensANewFile() throws Exception {
        File dir = tempDir();
        File exports = new File(dir, "exports-root");
        CipherLog widget = new CipherLog(config(dir).processName("widget").process(2).build());
        widget.log(CipherLogLevel.I, null, "widget line");
        widget.close();
        CipherLog log = new CipherLog(config(dir).exportRoot(exports).build());
        log.log(CipherLogLevel.I, null, "before wipe");
        File bundle = log.exportBundle();
        assertTrue(bundle.isFile());
        File otherRoot = new File(dir, "other-exports");
        File bundle2 = log.exportBundle(otherRoot, false, 10_000);
        File unrelated = new File(otherRoot, "keep-me.txt");
        TestSupport.writeBytes(unrelated, new byte[] {1});
        File oldName = log.currentPath();
        assertTrue(log.wipe());
        assertFalse(bundle.exists());
        assertFalse(bundle.getParentFile().exists());
        assertFalse(bundle2.exists());
        assertTrue("nothing else in an export root is touched", unrelated.exists());
        List<File> files = logFiles(dir);
        assertEquals(1, files.size());
        assertNotEquals(oldName, files.get(0));
        assertTrue(files.get(0).getName().startsWith("app-"));
        log.log(CipherLogLevel.I, null, "after wipe");
        log.close();
        String text = read(files.get(0)).text();
        assertTrue(text.contains(" I app device: cipherlog "));
        assertTrue(text.contains("after wipe"));
        assertFalse(text.contains("before wipe"));
    }

    @Test
    public void wipeAfterCloseDeletesButOpensNothing() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        log.log(CipherLogLevel.I, null, "x");
        log.close();
        assertEquals(1, logFiles(dir).size());
        assertTrue(log.wipe());
        assertEquals(Collections.emptyList(), logFiles(dir));
    }

    @Test
    public void recentBundleTakesThePreviousFileWhenTheCurrentOneIsSmall() {
        File dir = tempDir();
        TestSupport.Clock clock = new TestSupport.Clock();
        CipherLog first = new CipherLog(config(dir, clock).build());
        first.log(CipherLogLevel.I, null, "first run");
        first.close();
        clock.advance(1000);
        CipherLog log = new CipherLog(config(dir, clock).build());
        log.log(CipherLogLevel.I, null, "second run");
        CipherLogReadResult small = TestSupport.reader().readBundle(log.recentBundle());
        assertEquals(2, small.files().size());
        assertTrue(small.files().get(0).text().contains("first run"));
        assertTrue(small.files().get(0).closed());
        assertTrue(small.files().get(1).text().contains("second run"));
        assertFalse(small.files().get(1).closed());

        for (int i = 0; i < 20; i++) log.log(CipherLogLevel.I, null, noise(400));
        CipherLogReadResult large = TestSupport.reader().readBundle(log.recentBundle());
        assertEquals(1, large.files().size());
        assertTrue(large.files().get(0).text().contains("second run"));
        log.close();
        // Closed: the newest file of this process stands in.
        CipherLogReadResult afterClose = TestSupport.reader().readBundle(log.recentBundle());
        assertTrue(afterClose.files().get(afterClose.files().size() - 1).text().contains("second run"));
    }

    @Test
    public void previousRunBundle() {
        File dir = tempDir();
        TestSupport.Clock clock = new TestSupport.Clock();
        CipherLog none = new CipherLog(config(dir, clock).build());
        assertNull(none.previousRunBundle());
        none.log(CipherLogLevel.I, null, "run one");
        none.close();
        clock.advance(1000);
        CipherLog rotating = new CipherLog(config(dir, clock).maxFileBytes(2000).build());
        for (int i = 0; i < 30; i++) {
            clock.advance(1);
            rotating.log(CipherLogLevel.I, null, "run two " + i + " " + noise(100));
        }
        rotating.log(CipherLogLevel.I, null, "run two last");
        rotating.close();
        clock.advance(1000);
        CipherLog log = new CipherLog(config(dir, clock).build());
        CipherLogReadResult result = TestSupport.reader().readBundle(log.previousRunBundle());
        assertEquals(1, result.files().size());
        assertTrue(result.files().get(0).text().contains("run two last"));
        assertTrue(result.files().get(0).closed());
        log.close();
    }

    @Test
    public void crashLeavesAnUnclosedFileAndTheNextStartAppendsNothing() {
        File dir = tempDir();
        TestSupport.Clock clock = new TestSupport.Clock();
        CipherLog log = new CipherLog(config(dir, clock).build());
        log.log(CipherLogLevel.F, "crash", "boom");
        log.simulateCrash();
        File crashed = single(logFiles(dir));
        byte[] before = readBytes(crashed);
        clock.advance(10);
        CipherLog next = new CipherLog(config(dir, clock).build());
        next.log(CipherLogLevel.I, null, "after restart");
        next.close();
        assertArrayEquals(before, readBytes(crashed));
        assertEquals(2, logFiles(dir).size());
        CipherLogFile first = read(crashed);
        assertFalse(first.closed());
        assertTrue(first.text().contains("F app crash: boom\n"));
    }

    @Test
    public void wipeAfterARestartDeletesExportsInTheDefaultRoot() throws Exception {
        File dir = tempDir();
        CipherLog first = new CipherLog(config(dir).build());
        first.log(CipherLogLevel.I, null, "run 1");
        File bundle = first.exportBundle();
        assertEquals(new File(dir, "exports"), bundle.getParentFile().getParentFile());
        first.close();
        assertTrue(bundle.isFile());
        // A new process run: this writer never exported, exportRoot is null.
        CipherLog second = new CipherLog(config(dir).build());
        assertTrue(second.wipe());
        assertFalse(bundle.exists());
        assertFalse(bundle.getParentFile().exists());
        second.close();
    }

    @Test
    public void aWipeByAnotherProcessMakesTheWriterOpenANewFile() {
        File dir = tempDir();
        CipherLog widget = new CipherLog(config(dir).processName("widget").process(2).build());
        widget.log(CipherLogLevel.I, null, "before the wipe");
        assertTrue(widget.flush(2000));
        File before = widget.currentPath();
        assertNotNull(before);
        CipherLog app = new CipherLog(config(dir).build());
        assertTrue(app.wipe());
        assertFalse(before.exists());
        widget.log(CipherLogLevel.I, null, "after the wipe");
        byte[] recent = widget.recentBundle();
        assertNotNull("recentBundle after a wipe by another process", recent);
        boolean found = false;
        for (CipherLogFile f : TestSupport.reader().read(recent).files()) found |= f.text().contains("after the wipe");
        assertTrue(found);
        widget.close();
        app.close();
        File now = single(logFiles(dir, "widget"));
        assertNotEquals(before, now);
        String text = read(now).text();
        assertTrue(text.contains(" I widget device: cipherlog "));
        assertFalse(text.contains("before the wipe"));
    }

    @Test
    public void theWorkerThreadStaysAlive() {
        // A thread started later (from a crash handler) can fail with OutOfMemoryError: the one worker starts at once
        // and never times out.
        CipherLog log = new CipherLog(config(tempDir()).build());
        assertTrue(log.keepsWorkerAlive());
        log.close();
    }

    @Test
    public void testKeyWarningGoesToDiagnosticsOnlyWhenAsked() throws Exception {
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        CipherLog warned = new CipherLog(config(tempDir()).warnIfTestKey(true).diagnostics(diagnostics::add).build());
        assertTrue(warned.flush(2000));
        assertEquals(Collections.singletonList(CipherLog.TEST_KEY_WARNING), diagnostics);
        assertTrue(warned.isOn());
        warned.close();
        diagnostics.clear();
        CipherLog quiet = new CipherLog(config(tempDir()).diagnostics(diagnostics::add).build());
        assertTrue(quiet.flush(2000));
        quiet.close();
        assertEquals(Collections.emptyList(), diagnostics);
    }

    @Test
    public void fastRotationKeepsNameOrderUnderACoarseClock() {
        File dir = tempDir();
        // The clock never moves: every new file still gets a later createdAt, so name order is write order.
        CipherLog log = new CipherLog(config(dir, new TestSupport.Clock()).maxFileBytes(1000).build());
        for (int i = 0; i < 40; i++) log.log(CipherLogLevel.W, "r", i + " " + noise(200));
        log.close();
        List<File> files = logFiles(dir);
        assertTrue(files.size() >= 3);
        long previous = -1;
        int expected = 0;
        for (File f : files) {
            long createdAt = CipherLog.createdAtOf(f.getName());
            assertTrue(createdAt > previous);
            previous = createdAt;
            for (String body : bodies(read(f))) {
                if (!body.startsWith("W app r: ")) continue;
                assertEquals(expected + " ", body.substring(9, 9 + String.valueOf(expected).length() + 1));
                expected++;
            }
        }
        assertEquals(40, expected);
    }
}
