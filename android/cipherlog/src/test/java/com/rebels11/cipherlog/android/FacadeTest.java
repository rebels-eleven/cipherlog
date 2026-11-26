package com.rebels11.cipherlog.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.ApplicationInfo;
import com.rebels11.cipherlog.CipherLogFile;
import com.rebels11.cipherlog.CipherLogKey;
import com.rebels11.cipherlog.CipherLogReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * The facade on the JVM: android.jar stubs return default values (Logcat returns 0, the package manager is null), so
 * this checks the file side of start and logging. Only the published test key is used.
 */
public class FacadeTest {
    /** The public half of vectors/test-key.json (tests only). */
    private static final String TEST_KEY =
            "cipherlog-pub-v1:ecd8b29e913351f6a28fda6e663ad350273ed38a9b44fe8f1b8116a236154170";

    private static final File VECTORS = new File(System.getProperty("cipherlog.repoRoot", "../.."), "vectors");

    /** A context whose directories are temp folders; nothing else works on the stubs. */
    static final class FakeContext extends ContextWrapper {
        final File root;
        final ApplicationInfo info = new ApplicationInfo();

        FakeContext(File root) {
            super(null);
            this.root = root;
        }

        @Override
        public Context getApplicationContext() {
            return this;
        }

        @Override
        public String getPackageName() {
            return "com.example.app";
        }

        @Override
        public File getNoBackupFilesDir() {
            return new File(root, "no_backup");
        }

        @Override
        public File getFilesDir() {
            return new File(root, "files");
        }

        @Override
        public File getCacheDir() {
            return new File(root, "cache");
        }

        @Override
        public ApplicationInfo getApplicationInfo() {
            return info;
        }

        @Override
        public Object getSystemService(String name) {
            return null;
        }
    }

    private static String testPrivateHex() throws IOException {
        String json = new String(Files.readAllBytes(new File(VECTORS, "test-key.json").toPath()), StandardCharsets.UTF_8);
        int at = json.indexOf("\"privateKey\"");
        int start = json.indexOf('"', json.indexOf(':', at)) + 1;
        return json.substring(start, json.indexOf('"', start));
    }

    @Before
    public void pretendToBeTheMainProcess() {
        // On Linux /proc/self/cmdline names the test JVM; on a phone it names the app.
        ProcessNames.forcedForTests = "com.example.app";
    }

    @After
    public void tearDown() {
        ProcessNames.forcedForTests = null;
        CipherLog.reset();
    }

    @Test
    public void beforeStartNothingThrowsAndNothingIsWritten() {
        assertFalse(CipherLog.isStarted());
        assertEquals(0, CipherLog.d("tag", "before start"));
        assertEquals(0, CipherLog.e("tag", null, new IOException("x")));
        assertFalse(CipherLog.flush(100));
        assertNull(CipherLog.recentBundle(100));
        assertNull(CipherLog.previousRunBundle(100));
        assertFalse(CipherLog.wipe());
        assertNull(CipherLog.shareIntent(new FakeContext(tempDir()), "a@b.c", "logs"));
    }

    @Test
    public void aWrongKeyStringReturnsNullWithoutEchoingIt() throws Exception {
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        String priv = "cipherlog-priv-v1:" + testPrivateHex();
        assertNull(CipherLog.start(new FakeContext(tempDir()), priv,
                new CipherLog.Options().diagnostics(diagnostics::add)));
        assertFalse(CipherLog.isStarted());
        long deadline = System.currentTimeMillis() + 2000;
        while (diagnostics.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(10);
        assertEquals(1, diagnostics.size());
        assertTrue(diagnostics.get(0), diagnostics.get(0).startsWith("cipherlog not started: cipherlog key: this is a PRIVATE key"));
        assertFalse(diagnostics.get(0).contains(testPrivateHex().substring(0, 6)));
    }

    /** SPEC.md 7.1: the full-config overload never throws either; it returns null and reports why. */
    @Test
    public void theConfigOverloadReturnsNullInsteadOfThrowing() throws Exception {
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        CipherLog.Options options = new CipherLog.Options().diagnostics(diagnostics::add);
        assertNull(CipherLog.start(new FakeContext(tempDir()), (com.rebels11.cipherlog.CipherLogConfig) null, options));
        com.rebels11.cipherlog.CipherLogConfig config = com.rebels11.cipherlog.CipherLogConfig
                .builder(new File(tempDir(), "logs"), CipherLogKey.parse(TEST_KEY)).build();
        assertNull(CipherLog.start(null, config, options));
        assertFalse(CipherLog.isStarted());
        long deadline = System.currentTimeMillis() + 2000;
        while (diagnostics.size() < 2 && System.currentTimeMillis() < deadline) Thread.sleep(10);
        assertEquals(Arrays.asList("cipherlog not started: NullPointerException",
                "cipherlog not started: NullPointerException"), new ArrayList<>(diagnostics));
        // Nothing was left half set: a later start works.
        assertNotNull(CipherLog.start(new FakeContext(tempDir()), config, null));
    }

    @Test
    public void startWritesToNoBackupAndMirrorsTheFacade() throws Exception {
        File root = tempDir();
        FakeContext context = new FakeContext(root);
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        List<LogLine> seen = Collections.synchronizedList(new ArrayList<>());
        com.rebels11.cipherlog.CipherLog writer = CipherLog.start(context, TEST_KEY,
                new CipherLog.Options().diagnostics(diagnostics::add).addTarget(seen::add).logcat(false));
        assertNotNull(writer);
        assertSame(writer, CipherLog.start(context, "not even a key"));
        assertSame(writer, CipherLog.writer());
        CipherLog.v("Net", "verbose");
        CipherLog.d("Net", "debug");
        CipherLog.i("Net", "info");
        CipherLog.w("Net", "warn");
        CipherLog.e("Net", "failed", new IllegalStateException("boom"));
        CipherLog.wtf("Net", "never");
        assertTrue(CipherLog.flush(5000));
        assertEquals(6, seen.size());

        File dir = new File(root, "no_backup/cipherlog");
        File[] files = dir.listFiles((d, name) -> name.endsWith(".cipherlog"));
        assertNotNull(files);
        assertEquals(1, files.length);
        assertTrue(files[0].getName(), files[0].getName().startsWith("app-"));
        CipherLogReader reader = new CipherLogReader(Collections.singletonList(CipherLogKey.parsePrivateKey(
                "cipherlog-priv-v1:" + testPrivateHex())));
        CipherLogFile file = reader.readFile(Files.readAllBytes(files[0].toPath()), files[0].getName());
        String text = file.text();
        assertEquals(Integer.valueOf(2), file.platform());
        assertEquals(Integer.valueOf(1), file.process());
        assertTrue(text, text.contains(" D app Net: verbose\n"));
        assertTrue(text.contains(" D app Net: debug\n"));
        assertTrue(text.contains(" I app Net: info\n"));
        assertTrue(text.contains(" W app Net: warn\n"));
        assertTrue(text.contains(" E app Net: failed · IllegalStateException: boom\n"));
        assertTrue(text.contains(" F app Net: never\n"));
        assertFalse(text.contains("\tat "));
        // Built-in collectors ran (the stubs have no package manager, so app fails by type name only).
        assertTrue(text.contains(" I app device: app · failed "));
        assertTrue(text.contains(" I app device: system · "));
        assertTrue(text.contains(" I app device: locale · "));
        assertTrue(text.contains(" I app device: disk · "));
        // Not debuggable + the test key: the warning reached diagnostics.
        assertEquals(Collections.singletonList(com.rebels11.cipherlog.CipherLog.TEST_KEY_WARNING), diagnostics);

        File export = CipherLog.export(true);
        assertEquals(new File(root, "cache/cipherlog-exports"), export.getParentFile().getParentFile());
        assertTrue(export.getName().endsWith(".cipherlogs.txt"));
        assertEquals(2, reader.read(export).files().size());
        // No mail app on the stubs: null, and nothing thrown.
        assertNull(CipherLog.shareIntent(context, "support@example.com", "Logs"));
        assertTrue(CipherLog.wipe());
        assertFalse(export.exists());
    }

    @Test
    public void aDebuggableAppGetsNoTestKeyWarning() throws Exception {
        FakeContext context = new FakeContext(tempDir());
        context.info.flags |= ApplicationInfo.FLAG_DEBUGGABLE;
        List<String> diagnostics = Collections.synchronizedList(new ArrayList<>());
        assertNotNull(CipherLog.start(context, TEST_KEY,
                new CipherLog.Options().diagnostics(diagnostics::add)));
        assertTrue(CipherLog.flush(5000));
        assertEquals(Collections.emptyList(), diagnostics);
    }

    private static File tempDir() {
        try {
            File dir = Files.createTempDirectory("cipherlog-android").toFile();
            dir.deleteOnExit();
            return dir;
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}
