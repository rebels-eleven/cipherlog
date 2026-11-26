package com.rebels11.cipherlog;

import static com.rebels11.cipherlog.TestSupport.config;
import static com.rebels11.cipherlog.TestSupport.logFiles;
import static com.rebels11.cipherlog.TestSupport.read;
import static com.rebels11.cipherlog.TestSupport.single;
import static com.rebels11.cipherlog.TestSupport.tempDir;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

/** SPEC.md 3.6: write failures. */
public class FailureTest {
    /** Writes go through until {@code limit} bytes, then fail with {@code message}. */
    static class FailingDisk extends CipherLogFileSystem.Default {
        volatile long limit;
        final String message;

        FailingDisk(long limit, String message) {
            this.limit = limit;
            this.message = message;
        }

        @Override
        public OutputStream createNew(File file) throws IOException {
            final OutputStream real = super.createNew(file);
            return new OutputStream() {
                long written = 0;

                @Override
                public void write(int b) throws IOException {
                    write(new byte[] {(byte) b}, 0, 1);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    if (written + len > limit) throw new IOException(message);
                    real.write(b, off, len);
                    written += len;
                }

                @Override
                public void close() throws IOException {
                    real.close();
                }
            };
        }
    }

    /** Opening fails while {@code failing} is true. */
    static class Locked extends CipherLogFileSystem.Default {
        volatile boolean failing = true;
        volatile String message = "Operation not permitted";
        final AtomicInteger attempts = new AtomicInteger();

        @Override
        public OutputStream createNew(File file) throws IOException {
            attempts.incrementAndGet();
            if (failing) throw new IOException(message);
            return super.createNew(file);
        }
    }

    @Test
    public void diskFullTurnsTheWriterOffWithOneDiagnosticsLine() {
        File dir = tempDir();
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        CipherLog log = new CipherLog(config(dir).fileSystem(new FailingDisk(600, "No space left on device"))
                .diagnostics(diagnostics::add).build());
        log.log(CipherLogLevel.W, "a", "fits");
        assertTrue(log.flush(2000));
        assertTrue(log.isOn());
        for (int i = 0; i < 50; i++) log.log(CipherLogLevel.W, "a", "line " + i + " " + TestSupport.repeat("x", 40) + i);
        log.flush(2000);
        assertFalse(log.isOn());
        for (int i = 0; i < 10; i++) log.log(CipherLogLevel.E, "a", "dropped " + i);
        log.flush(2000);
        log.close();
        assertEquals(Collections.singletonList("cipherlog off: disk full"), new ArrayList<>(diagnostics));
        // What was written before stays readable.
        CipherLogFile file = read(single(logFiles(dir)));
        assertTrue(file.text().contains("W app a: fits\n"));
        assertFalse(file.closed());
        assertFalse(file.text().contains("dropped"));
    }

    @Test
    public void aWriteErrorNamesTheErrno() {
        // Android's libcore reports "write failed: EIO (I/O error)"; the JVM "Input/output error".
        String[][] cases = {
            {"write failed: EIO (I/O error)", "cipherlog off: write failed (EIO)"},
            {"Input/output error", "cipherlog off: write failed (EIO)"},
            {"write failed: EPERM (Operation not permitted)", "cipherlog off: write failed (EPERM)"},
            {"write failed: ENOSPC (No space left on device)", "cipherlog off: disk full"},
            {"Disk quota exceeded", "cipherlog off: disk full"},
            {"something odd", "cipherlog off: write failed"},
        };
        for (String[] c : cases) {
            List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
            FailingDisk fs = new FailingDisk(Long.MAX_VALUE, c[0]);
            CipherLog log = new CipherLog(config(tempDir()).fileSystem(fs).diagnostics(diagnostics::add).build());
            assertTrue(log.flush(2000));
            fs.limit = 0;
            log.log(CipherLogLevel.W, "a", "fails");
            log.flush(2000);
            log.close();
            assertEquals(c[0], Collections.singletonList(c[1]), new ArrayList<>(diagnostics));
        }
    }

    @Test
    public void cryptoFailureTurnsTheWriterOff() {
        File dir = tempDir();
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        // A low-order X25519 point (all zeros): HPKE refuses it.
        CipherLog log = new CipherLog(CipherLogConfig.builder(dir, new CipherLogKey(new byte[32]))
                .diagnostics(diagnostics::add).build());
        log.log(CipherLogLevel.W, "a", "never written");
        log.flush(2000);
        log.close();
        assertEquals(Collections.singletonList("cipherlog off: crypto error"), new ArrayList<>(diagnostics));
        assertFalse(log.isOn());
        assertEquals(Collections.emptyList(), logFiles(dir));
    }

    @Test
    public void openFailureRetriesOnceAMinuteAndCountsDroppedLines() {
        File dir = tempDir();
        TestSupport.Clock clock = new TestSupport.Clock();
        Locked fs = new Locked();
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        CipherLog log = new CipherLog(config(dir, clock).fileSystem(fs).diagnostics(diagnostics::add).build());
        log.log(CipherLogLevel.I, "a", "one");
        log.log(CipherLogLevel.I, "a", "two");
        assertTrue(log.flush(2000));
        assertEquals(1, fs.attempts.get());
        clock.advance(30_000);
        log.log(CipherLogLevel.W, "a", "three");
        assertTrue(log.flush(2000));
        assertEquals(1, fs.attempts.get());
        clock.advance(30_000);
        log.log(CipherLogLevel.I, "a", "four");
        assertTrue(log.flush(2000));
        assertEquals(2, fs.attempts.get());
        fs.failing = false;
        clock.advance(59_999);
        log.log(CipherLogLevel.I, "a", "five");
        assertTrue(log.flush(2000));
        assertEquals(2, fs.attempts.get());
        clock.advance(1);
        log.log(CipherLogLevel.I, "a", "six");
        log.close();
        assertEquals(3, fs.attempts.get());
        assertEquals(Collections.emptyList(), diagnostics);
        List<String> lines = TestSupport.bodies(read(single(logFiles(dir))));
        assertTrue(lines.get(0).startsWith("I app device: cipherlog "));
        assertEquals("W app cipherlog: not written 5 lines", lines.get(1));
        assertEquals("I app a: six", lines.get(2));
        assertEquals(3, lines.size());
    }

    @Test
    public void diskFullWhileOpeningTurnsTheWriterOff() {
        File dir = tempDir();
        Locked fs = new Locked();
        fs.message = "No space left on device";
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        CipherLog log = new CipherLog(config(dir).fileSystem(fs).diagnostics(diagnostics::add).build());
        log.log(CipherLogLevel.W, "a", "never written");
        log.flush(2000);
        assertFalse(log.isOn());
        assertEquals(Collections.singletonList("cipherlog off: disk full"), new ArrayList<>(diagnostics));
        log.close();
    }

    @Test
    public void aHeaderWriteFailureLeavesNoEmptyFile() {
        File dir = tempDir();
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        CipherLog log = new CipherLog(config(dir).fileSystem(new FailingDisk(0, "No space left on device"))
                .diagnostics(diagnostics::add).build());
        log.log(CipherLogLevel.W, "a", "never written");
        log.flush(2000);
        assertFalse(log.isOn());
        assertEquals(Collections.singletonList("cipherlog off: disk full"), new ArrayList<>(diagnostics));
        assertEquals(Collections.emptyList(), logFiles(dir));
        log.close();
    }

    @Test
    public void anErrorFromTheStreamTurnsTheWriterOff() {
        File dir = tempDir();
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        final boolean[] broken = {false};
        CipherLogFileSystem fs = new CipherLogFileSystem.Default() {
            @Override
            public OutputStream createNew(File file) throws IOException {
                final OutputStream real = super.createNew(file);
                return new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        write(new byte[] {(byte) b}, 0, 1);
                    }

                    @Override
                    public void write(byte[] b, int off, int len) throws IOException {
                        if (broken[0]) throw new StackOverflowError();
                        real.write(b, off, len);
                    }

                    @Override
                    public void close() throws IOException {
                        real.close();
                    }
                };
            }
        };
        CipherLog log = new CipherLog(config(dir).fileSystem(fs).diagnostics(diagnostics::add).build());
        assertTrue(log.flush(2000));
        broken[0] = true;
        log.log(CipherLogLevel.W, "a", "fails");
        log.flush(2000);
        assertFalse(log.isOn());
        assertEquals(Collections.singletonList("cipherlog off: internal error (StackOverflowError)"),
                new ArrayList<>(diagnostics));
        log.close();
    }

    @Test
    public void aThrowingDiagnosticsCallbackChangesNothing() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).fileSystem(new FailingDisk(0, "No space left on device"))
                .diagnostics(line -> {
                    throw new IllegalStateException("callback");
                }).build());
        log.log(CipherLogLevel.W, "a", "x");
        assertTrue(log.flush(2000));
        assertFalse(log.isOn());
        log.close();
    }

    @Test
    public void logAndFlushNeverThrowEvenForErrors() {
        File dir = tempDir();
        TestSupport.Clock clock = new TestSupport.Clock();
        final boolean[] clockFails = {false};
        final Thread caller = Thread.currentThread();
        // Only the caller's clock read fails (the worker reads the clock too).
        CipherLog log = new CipherLog(config(dir, () -> {
            if (clockFails[0] && Thread.currentThread() == caller) throw new OutOfMemoryError("test");
            return clock.nowMs();
        }).scrub(t -> {
            if (t.contains("boom")) throw new StackOverflowError();
            return t;
        }).build());
        log.log(CipherLogLevel.F, "crash", "boom");
        clockFails[0] = true;
        log.log(CipherLogLevel.F, "crash", "no time");
        clockFails[0] = false;
        log.log(CipherLogLevel.F, "crash", "kept");
        log.log(null, null, null, null);
        assertTrue(log.flush(2000));
        log.close();
        String text = read(single(logFiles(dir))).text();
        assertTrue(text.contains("<scrub failed>") || !text.contains("boom"));
        assertFalse(text.contains("no time"));
        assertTrue(text.contains("F app crash: kept\n"));
    }
}
