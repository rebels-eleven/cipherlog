package com.rebels11.cipherlog.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.PackageManager;
import com.rebels11.cipherlog.CipherLogCollector;
import com.rebels11.cipherlog.CipherLogFile;
import com.rebels11.cipherlog.CipherLogKey;
import com.rebels11.cipherlog.CipherLogReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/** The optional collectors: every pure part, plus a facade start on the stubs. */
public class OptionalCollectorsTest {
    private static final String TEST_KEY =
            "cipherlog-pub-v1:ecd8b29e913351f6a28fda6e663ad350273ed38a9b44fe8f1b8116a236154170";
    private static final File VECTORS = new File(System.getProperty("cipherlog.repoRoot", "../.."), "vectors");
    private static final long DAY = 86_400_000L;
    /** 2026-11-20T12:00:00Z. */
    private static final long NOV_20 = 1_795_176_000_000L;

    static final class MapStore implements VersionHistory.Store {
        final Map<String, String> map = new HashMap<>();
        int puts;

        @Override
        public String get(String key) {
            return map.get(key);
        }

        @Override
        public void put(String key, String value) {
            puts++;
            map.put(key, value);
        }
    }

    /** No permissions granted. */
    static final class NoPermissionContext extends ContextWrapperProbe {
        NoPermissionContext(File root) {
            super(root);
        }

        @Override
        public int checkSelfPermission(String permission) {
            return PackageManager.PERMISSION_DENIED;
        }
    }

    /** Permission granted but no system services (the stubs have none). */
    static class ContextWrapperProbe extends ContextWrapper {
        ContextWrapperProbe(File root) {
            super(null);
        }

        @Override
        public Context getApplicationContext() {
            return this;
        }

        @Override
        public Object getSystemService(String name) {
            return null;
        }

        @Override
        public int checkSelfPermission(String permission) {
            return PackageManager.PERMISSION_GRANTED;
        }
    }

    @Before
    public void pretendToBeTheMainProcess() {
        ProcessNames.forcedForTests = "com.example.app";
    }

    @After
    public void tearDown() {
        ProcessNames.forcedForTests = null;
        CipherLog.reset();
    }

    @Test
    public void utcDays() {
        assertEquals("2026-11-20", VersionHistory.utcDay(NOV_20));
        assertEquals("1970-01-01", VersionHistory.utcDay(0));
        assertEquals("2026-11-20", VersionHistory.utcDay(NOV_20 + DAY / 2 - 1));
        assertEquals("2026-11-21", VersionHistory.utcDay(NOV_20 + DAY / 2));
    }

    @Test
    public void historyRecordsNewVersionsOnTopOnce() {
        MapStore store = new MapStore();
        assertEquals("none", VersionHistory.format(VersionHistory.read(store)));
        VersionHistory.record(store, "1.4", 15, NOV_20 - 8 * DAY);
        VersionHistory.record(store, "1.4", 15, NOV_20 - 7 * DAY);
        assertEquals(1, store.puts);
        List<VersionHistory.Entry> entries = VersionHistory.record(store, "1.4.1", 16, NOV_20);
        assertEquals("1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-12", VersionHistory.format(entries));
        // A downgrade back to a known version keeps its first-seen day and the order.
        VersionHistory.record(store, "1.4", 15, NOV_20 + DAY);
        assertEquals(2, store.puts);
        // Same name, new code is a new entry.
        VersionHistory.record(store, "1.4.1", 17, NOV_20 + DAY);
        assertEquals("1.4.1 (17) since 2026-11-21 · 1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-12",
                VersionHistory.format(VersionHistory.read(store)));
    }

    @Test
    public void historyKeepsTwentyAndPersists() {
        MapStore store = new MapStore();
        for (int i = 1; i <= 25; i++) VersionHistory.record(store, "1." + i, i, NOV_20 + i * DAY);
        List<VersionHistory.Entry> entries = VersionHistory.read(store);
        assertEquals(VersionHistory.LIMIT, entries.size());
        assertEquals("1.25", entries.get(0).name);
        assertEquals("1.6", entries.get(19).name);
        // A fresh store over the same saved text reads the same history.
        MapStore reopened = new MapStore();
        reopened.map.putAll(store.map);
        assertEquals(entries, VersionHistory.read(reopened));
        assertTrue(store.map.containsKey("cipherlog.versionHistory"));
    }

    @Test
    public void historyDecodeIsForgiving() {
        assertEquals(Collections.emptyList(), VersionHistory.decode(null));
        List<VersionHistory.Entry> entries = VersionHistory.decode("x\t2026-01-01\tbad\n7\t2026-01-02\t2.0\njunk\n");
        assertEquals(1, entries.size());
        assertEquals("2.0 (7) since 2026-01-02", entries.get(0).toString());
        // Tabs and breaks in a name cannot corrupt the stored text.
        MapStore store = new MapStore();
        VersionHistory.record(store, "1.0\tbeta\nx", 1, NOV_20);
        VersionHistory.record(store, null, 2, NOV_20);
        assertEquals("- (2) since 2026-11-20 · 1.0 beta x (1) since 2026-11-20",
                VersionHistory.format(VersionHistory.read(store)));
    }

    @Test
    public void installLines() {
        assertEquals("installed 2026-11-12 · updated 2026-11-20",
                OptionalCollectors.installLine(NOV_20 - 8 * DAY, NOV_20));
        assertEquals("installed unknown · updated unknown", OptionalCollectors.installLine(0, 0));
    }

    @Test
    public void memoryLines() {
        long gib = 1L << 30;
        assertEquals("8 GB", OptionalCollectors.halfGb(8 * gib));
        assertEquals("7.5 GB", OptionalCollectors.halfGb((long) (7.4 * gib)));
        assertEquals("7.5 GB", OptionalCollectors.halfGb((long) (7.7 * gib)));
        assertEquals("8 GB", OptionalCollectors.halfGb((long) (7.8 * gib)));
        assertEquals("0.5 GB", OptionalCollectors.halfGb(gib / 3));
        assertEquals("unknown", OptionalCollectors.halfGb(0));
        assertEquals("RAM 7.5 GB · class 256 MB · large class 512 MB · low-RAM device no · low memory now yes"
                        + " · power save on",
                OptionalCollectors.memoryLine((long) (7.4 * gib), 256, 512, false, true, true));
        assertTrue(OptionalCollectors.memoryLine(gib, 1, 2, true, false, null).endsWith("power save unknown"));
    }

    @Test
    public void screenLines() {
        assertEquals("411×914 dp · xxhdpi (420 dpi) · font 1.15 · dark yes",
                OptionalCollectors.screenLine(411, 914, 420, 1.15f, true));
        assertEquals("ldpi", OptionalCollectors.densityBucket(120));
        assertEquals("mdpi", OptionalCollectors.densityBucket(160));
        assertEquals("tvdpi", OptionalCollectors.densityBucket(213));
        assertEquals("hdpi", OptionalCollectors.densityBucket(240));
        assertEquals("xhdpi", OptionalCollectors.densityBucket(320));
        assertEquals("xxhdpi", OptionalCollectors.densityBucket(480));
        assertEquals("xxxhdpi", OptionalCollectors.densityBucket(560));
        assertEquals("unknown", OptionalCollectors.densityBucket(0));
        assertEquals("1", OptionalCollectors.fontScale(1f));
        assertEquals("0.85", OptionalCollectors.fontScale(0.85f));
        assertEquals("1.3", OptionalCollectors.fontScale(1.3f));
        assertEquals("2", OptionalCollectors.fontScale(2f));
    }

    @Test
    public void networkLines() {
        assertEquals("wifi · expensive no · constrained no", OptionalCollectors.networkLine("wifi", false, false));
        assertEquals("cellular · expensive yes · constrained yes",
                OptionalCollectors.networkLine("cellular", true, true));
        assertEquals("none", OptionalCollectors.networkLine(null, true, true));
    }

    @Test
    public void constrainedOnlyOnMeteredNetworksUnderDataSaver() {
        int enabled = android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED;
        int whitelisted = android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED;
        assertTrue(OptionalCollectors.constrained(true, enabled));
        // Data Saver on, but unmetered Wi-Fi: nothing is restricted on this network.
        assertFalse(OptionalCollectors.constrained(false, enabled));
        assertFalse(OptionalCollectors.constrained(true, whitelisted));
        assertFalse(OptionalCollectors.constrained(true, 0));
    }

    @Test
    public void walkNeverAsksTheListerForMoreThanTheBudget() {
        // A fake flat directory far larger than the cap: the listing must stop at the cap, not after reading it all.
        final int[] handed = {0};
        FolderSizes.Lister huge = (dir, visitor) -> {
            for (int i = 0; i < FolderSizes.MAX_ENTRIES * 10; i++) {
                handed[0]++;
                if (!visitor.visit(new File(dir, "f" + i))) return;
            }
        };
        File root = new File(System.getProperty("java.io.tmpdir"));
        FolderSizes.Budget budget = budget(FolderSizes.MAX_ENTRIES, Long.MAX_VALUE / 4);
        FolderSizes.Size size = FolderSizes.walk(root, budget, f -> false, huge);
        assertFalse(size.complete);
        assertEquals(FolderSizes.MAX_ENTRIES + 1, handed[0]);
        // Once over budget, no further directory is read at all.
        handed[0] = 0;
        assertFalse(FolderSizes.walk(root, budget, f -> false, huge).complete);
        assertEquals(0, handed[0]);
    }

    @Test
    public void walkChecksTheDeadlineBeforeEachDirectoryRead() throws IOException {
        File root = tempDir();
        write(new File(root, "a/x"), 1_000);
        write(new File(root, "b/y"), 1_000);
        final long[] now = {0};
        final List<File> read = new ArrayList<>();
        FolderSizes.Budget budget = new FolderSizes.Budget(1_000, 100, () -> now[0]);
        FolderSizes.Lister lister = (dir, visitor) -> {
            read.add(dir);
            FolderSizes.listAll(dir, visitor);
            now[0] += 1_000; // the read itself overran the deadline
        };
        FolderSizes.Size size = FolderSizes.walk(root, budget, f -> false, lister);
        assertFalse(size.complete);
        assertEquals(1, read.size());
    }

    @Test
    public void lazyAndEagerListingsCountTheSame() throws IOException {
        File root = tempDir();
        write(new File(root, "a"), 1_000);
        write(new File(root, "sub/b"), 2_000);
        FolderSizes.Size lazy = FolderSizes.walk(root, budget(100, Long.MAX_VALUE / 4), f -> false,
                FolderSizes::listLazily);
        FolderSizes.Size eager = FolderSizes.walk(root, budget(100, Long.MAX_VALUE / 4), f -> false,
                FolderSizes::listAll);
        assertEquals(3_000, lazy.bytes);
        assertEquals(3_000, eager.bytes);
        assertTrue(lazy.complete && eager.complete);
    }

    @Test
    public void storageLineSaysNoneAndNotCountedLikeIos() throws IOException {
        File root = tempDir();
        for (int i = 0; i < 5; i++) write(new File(root, "files/f" + i), 1_000);
        write(new File(root, "cache/x"), 1_000);
        String line = OptionalCollectors.storageLine(Arrays.asList("files", "cache", "databases"),
                Arrays.asList(new File(root, "files"), new File(root, "cache"), new File(root, "missing")),
                budget(3, Long.MAX_VALUE / 4), f -> false);
        assertEquals("files ≥ 3 KB · cache not counted · databases none", line);
    }

    @Test
    public void allPassesTheLogDirectoryToStorageUsage() throws Exception {
        File root = tempDir();
        FacadeTest.FakeContext context = new FacadeTest.FakeContext(root);
        File logs = new File(root, "files/custom-logs");
        write(new File(logs, "x.cipherlog"), 2_000);
        List<CipherLogCollector> all = OptionalCollectors.all(context, logs);
        CipherLogCollector storage = all.get(all.size() - 1);
        assertEquals("storageUsage", storage.name());
        String line = String.join("\n", storage.lines());
        assertTrue(line, line.contains("logs 2 KB"));
    }

    @Test
    public void networkWithoutPermissionSaysSoAndDoesNotThrow() throws Exception {
        File root = tempDir();
        assertEquals("unknown (no ACCESS_NETWORK_STATE)",
                OptionalCollectors.networkText(new NoPermissionContext(root)));
        assertEquals(Collections.singletonList("unknown (no ACCESS_NETWORK_STATE)"),
                OptionalCollectors.network(new NoPermissionContext(root)).lines());
        // Granted but no ConnectivityManager: unknown, still no throw.
        assertEquals("unknown", OptionalCollectors.networkText(new ContextWrapperProbe(root)));
    }

    @Test
    public void roundedSizes() {
        assertEquals("0 KB", FolderSizes.rounded(0));
        assertEquals("0 KB", FolderSizes.rounded(-3));
        assertEquals("1 KB", FolderSizes.rounded(600));
        assertEquals("340 KB", FolderSizes.rounded(340_200));
        assertEquals("999 KB", FolderSizes.rounded(999_400));
        assertEquals("1.0 MB", FolderSizes.rounded(999_600));
        assertEquals("1.2 MB", FolderSizes.rounded(1_234_567));
        assertEquals("999.9 MB", FolderSizes.rounded(999_940_000));
        assertEquals("1.0 GB", FolderSizes.rounded(999_960_000));
        assertEquals("12.3 GB", FolderSizes.rounded(12_340_000_000L));
    }

    @Test
    public void walkCountsEverything() throws IOException {
        File root = tempDir();
        write(new File(root, "a"), 1_000);
        write(new File(root, "sub/b"), 2_000);
        write(new File(root, "sub/deeper/c"), 3_000);
        FolderSizes.Size size = FolderSizes.walk(root, budget(100, Long.MAX_VALUE / 4), f -> false);
        assertTrue(size.complete);
        assertEquals(6_000, size.bytes);
        assertEquals("6 KB", size.text());
        FolderSizes.Size missing = FolderSizes.walk(new File(root, "nope"), budget(100, 1_000), f -> false);
        assertTrue(missing.complete);
        assertEquals(0, missing.bytes);
    }

    @Test
    public void walkStopsAtTheEntryCap() throws IOException {
        File root = tempDir();
        for (int i = 0; i < 10; i++) write(new File(root, "f" + i), 1_000);
        FolderSizes.Budget budget = budget(4, Long.MAX_VALUE / 4);
        FolderSizes.Size size = FolderSizes.walk(root, budget, f -> false);
        assertFalse(size.complete);
        assertEquals(4_000, size.bytes);
        assertEquals("≥ 4 KB", size.text());
        // The budget is shared: the next folder gets nothing more.
        FolderSizes.Size next = FolderSizes.walk(root, budget, f -> false);
        assertFalse(next.complete);
        assertEquals("≥ 0 KB", next.text());
    }

    @Test
    public void walkStopsAtTheDeadline() throws IOException {
        File root = tempDir();
        for (int i = 0; i < 10; i++) write(new File(root, "f" + i), 1_000);
        final long[] now = {0};
        // Every clock read moves 30 ns; the deadline is 100 ns after the start.
        FolderSizes.Budget budget = new FolderSizes.Budget(1_000, 100, () -> now[0] += 30);
        FolderSizes.Size size = FolderSizes.walk(root, budget, f -> false);
        assertFalse(size.complete);
        assertTrue(size.bytes < 10_000);
    }

    @Test
    public void walkDoesNotFollowLinks() throws IOException {
        File root = tempDir();
        write(new File(root, "real/a"), 1_000);
        write(new File(root, "link/b"), 5_000);
        FolderSizes.Size size = FolderSizes.walk(root, budget(100, Long.MAX_VALUE / 4),
                f -> f.getName().equals("link"));
        assertEquals(1_000, size.bytes);
    }

    @Test
    public void storageLineLabelsEveryFolderAndNoNames() throws IOException {
        File root = tempDir();
        write(new File(root, "files/secret-name.txt"), 1_234_567);
        write(new File(root, "cache/x"), 340_200);
        String line = OptionalCollectors.storageLine(Arrays.asList("files", "cache", "logs"),
                Arrays.asList(new File(root, "files"), new File(root, "cache"), new File(root, "none")),
                budget(100, Long.MAX_VALUE / 4), f -> false);
        assertEquals("files 1.2 MB · cache 340 KB · logs none", line);
        assertFalse(line.contains("secret"));
        assertEquals("unknown", OptionalCollectors.storageLine(new ArrayList<String>(), new ArrayList<File>(),
                budget(1, 1), f -> false));
    }

    @Test
    public void notInTheDefaultsAndRunOnStart() throws Exception {
        File root = tempDir();
        FacadeTest.FakeContext context = new FacadeTest.FakeContext(root);
        // Defaults stay the four built-in collectors.
        List<String> defaults = new ArrayList<>();
        for (CipherLogCollector c : DeviceCollectors.defaults(context, root)) defaults.add(c.name());
        assertEquals(Arrays.asList("app", "system", "locale", "disk"), defaults);

        // Creating them on the stubs (no package manager, no services) never throws.
        List<CipherLogCollector> all = OptionalCollectors.all(context);
        List<String> names = new ArrayList<>();
        for (CipherLogCollector c : all) names.add(c.name());
        assertEquals(Arrays.asList("versionHistory", "installDates", "memory", "screen", "network", "storageUsage"),
                names);

        assertNotNull(CipherLog.start(context, TEST_KEY,
                new CipherLog.Options().logcat(false).addCollectors(all)));
        assertTrue(CipherLog.flush(5000));
        File[] files = new File(root, "no_backup/cipherlog").listFiles((d, name) -> name.endsWith(".cipherlog"));
        assertNotNull(files);
        CipherLogReader reader = new CipherLogReader(Collections.singletonList(CipherLogKey.parsePrivateKey(
                "cipherlog-priv-v1:" + testPrivateHex())));
        CipherLogFile file = reader.readFile(Files.readAllBytes(files[0].toPath()), files[0].getName());
        String text = file.text();
        // Each one gives a line (a failure on the stubs is "failed <type>"), after the built-in ones.
        int disk = text.indexOf(" I app device: disk · ");
        assertTrue(text, disk > 0);
        for (String name : names) {
            int at = text.indexOf(" I app device: " + name + " · ");
            assertTrue(text, at > disk);
        }
        assertTrue(text, text.contains(" I app device: storageUsage · files "));
    }

    private static FolderSizes.Budget budget(int entries, long nanos) {
        return new FolderSizes.Budget(entries, nanos, System::nanoTime);
    }

    private static void write(File file, int bytes) throws IOException {
        assertTrue(file.getParentFile().isDirectory() || file.getParentFile().mkdirs());
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(new byte[bytes]);
        }
    }

    private static String testPrivateHex() throws IOException {
        String json = new String(Files.readAllBytes(new File(VECTORS, "test-key.json").toPath()), StandardCharsets.UTF_8);
        int at = json.indexOf("\"privateKey\"");
        int start = json.indexOf('"', json.indexOf(':', at)) + 1;
        return json.substring(start, json.indexOf('"', start));
    }

    private static File tempDir() throws IOException {
        File dir = Files.createTempDirectory("cipherlog-optional").toFile();
        dir.deleteOnExit();
        return dir;
    }
}
