package com.rebels11.cipherlog;

import static com.rebels11.cipherlog.TestSupport.config;
import static com.rebels11.cipherlog.TestSupport.readBytes;
import static com.rebels11.cipherlog.TestSupport.tempDir;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.zip.Deflater;
import org.junit.Test;

/** SPEC.md 4, 4.1 and 5.1. */
public class BundleTest {
    @Test
    public void exportRoundTrip() throws Exception {
        File dir = tempDir();
        File root = new File(dir, "exports");
        TestSupport.Clock clock = new TestSupport.Clock(Instant.parse("2026-11-26T10:07:00Z").toEpochMilli());
        CipherLog widget = new CipherLog(config(dir, clock).processName("widget").process(2).build());
        widget.log(CipherLogLevel.I, null, "from the widget");
        widget.close();
        clock.advance(1000);
        CipherLog log = new CipherLog(config(dir, clock)
                .addCollector(CipherLogCollector.of("phone", () -> Collections.singletonList("model X"))).build());
        log.log(CipherLogLevel.I, "a", "from the app");
        File bundle = log.exportBundle(root, false, 10_000);
        File armored = log.exportBundle(root, true, 10_000);
        log.close();

        assertEquals("cipherlog-20261126-1007.cipherlogs", bundle.getName());
        assertEquals("cipherlog-20261126-1007.cipherlogs.txt", armored.getName());
        assertTrue(bundle.getParentFile().getName().matches("[0-9a-f]{32}"));
        assertEquals(root, bundle.getParentFile().getParentFile());
        assertEquals(root, armored.getParentFile().getParentFile());
        for (File f : Arrays.asList(bundle, armored)) {
            CipherLogReadResult result = TestSupport.reader().read(f);
            assertEquals(Collections.emptyList(), result.notes());
            assertEquals(3, result.files().size());
            // Files oldest first (the widget's, then the app's still open and flushed), `device now` last (SPEC.md 4).
            assertTrue(result.files().get(0).text().contains("from the widget"));
            assertTrue(result.files().get(0).closed());
            assertEquals(Integer.valueOf(2), result.files().get(0).process());
            assertTrue(result.files().get(1).text().contains("from the app"));
            assertFalse(result.files().get(1).closed());
            // device now: only the device block, closed.
            CipherLogFile deviceNow = result.files().get(2);
            assertTrue(deviceNow.closed());
            assertEquals(2, deviceNow.lines().size());
            for (String line : deviceNow.lines()) assertTrue(line.contains(" I app device: "));
            assertTrue(deviceNow.lines().get(1).endsWith("phone · model X"));
        }
        // The armored file is the same kind of bundle as text.
        String text = TestSupport.readText(armored);
        assertTrue(text.startsWith(CipherLogArmor.BEGIN_LINE + "\n"));
        assertTrue(text.endsWith(CipherLogArmor.END_LINE + "\n"));
    }

    @Test
    public void exportBundleDefaultsToArmored() throws Exception {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        File bundle = log.exportBundle();
        log.close();
        assertTrue(bundle.getName(), bundle.getName().endsWith(".cipherlogs.txt"));
        assertEquals(new File(dir, "exports"), bundle.getParentFile().getParentFile());
    }

    @Test
    public void exportCapsAt4MiBDroppingTheOldest() throws Exception {
        File dir = tempDir();
        Random random = new Random(1);
        // Six 1 MiB files of a previous run (their bytes are copied, not read).
        List<String> names = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            String name = "old-" + (1_700_000_000_000L + i) + "-0000000" + i + ".cipherlog";
            byte[] bytes = new byte[1024 * 1024];
            random.nextBytes(bytes);
            TestSupport.writeBytes(new File(dir, name), bytes);
            names.add(name);
        }
        CipherLog log = new CipherLog(config(dir, new TestSupport.Clock(1_800_000_000_000L)).build());
        log.log(CipherLogLevel.I, null, "current");
        byte[] bundle = readBytes(log.exportBundle(new File(dir, "exports"), false, 10_000));
        log.close();
        assertTrue(bundle.length <= 4 * 1024 * 1024);
        List<byte[]> entries = Bundle.split(bundle, new ArrayList<String>());
        // The three newest old files and the current one, oldest first, then device now; the three oldest are dropped.
        assertEquals(5, entries.size());
        for (int i = 0; i < 3; i++) assertArrayEquals(readBytes(new File(dir, names.get(3 + i))), entries.get(i));
        assertTrue(TestSupport.reader().readFile(entries.get(3)).text().contains("current"));
        for (String line : TestSupport.reader().readFile(entries.get(4)).lines()) assertTrue(line.contains(" device: "));
    }

    @Test
    public void exportSkipsFilesShorterThanAHeader() throws Exception {
        File dir = tempDir();
        TestSupport.writeBytes(new File(dir, "other-1700000000000-00000000.cipherlog"), new byte[0]);
        TestSupport.writeBytes(new File(dir, "other-1700000000001-00000001.cipherlog"), Format.ascii("CPL1"));
        CipherLog log = new CipherLog(config(dir).build());
        byte[] bundle = readBytes(log.exportBundle(new File(dir, "exports"), false, 10_000));
        log.close();
        CipherLogReadResult result = TestSupport.reader().readBundle(bundle);
        assertEquals(2, result.files().size());
        for (CipherLogFile f : result.files()) assertTrue(f.opened());
    }

    @Test
    public void exportFoldersOlderThanSevenDaysGo() throws Exception {
        File dir = tempDir();
        File root = new File(dir, "exports");
        long now = System.currentTimeMillis();
        long eightDays = 8L * 24 * 60 * 60 * 1000;
        File old = new File(root, TestSupport.repeat("0", 32));
        assertTrue(old.mkdirs());
        File oldFile = new File(old, "cipherlog-20200101-0000.cipherlogs");
        TestSupport.writeBytes(oldFile, new byte[] {1});
        assertTrue(oldFile.setLastModified(now - eightDays));
        assertTrue(old.setLastModified(now - eightDays));
        // An old folder with a fresh file in it is young: its age is that of the newest file (SPEC.md 4).
        File touched = new File(root, TestSupport.repeat("2", 32));
        assertTrue(touched.mkdirs());
        TestSupport.writeBytes(new File(touched, "x.cipherlogs"), new byte[] {1});
        assertTrue(touched.setLastModified(now - eightDays));
        File recent = new File(root, TestSupport.repeat("1", 32));
        assertTrue(recent.mkdirs());
        File notOurs = new File(root, "keep-me");
        assertTrue(notOurs.mkdirs());
        assertTrue(notOurs.setLastModified(now - 30L * 24 * 60 * 60 * 1000));
        CipherLog log = new CipherLog(config(dir, () -> now).build());
        log.exportBundle(root, true, 10_000);
        log.close();
        assertFalse(old.exists());
        assertTrue(touched.exists());
        assertTrue(recent.exists());
        assertTrue(notOurs.exists());
    }

    @Test
    public void badLengthEndsTheBundleWithANote() {
        File dir = tempDir();
        CipherLog log = new CipherLog(config(dir).build());
        log.log(CipherLogLevel.I, null, "entry");
        log.close();
        byte[] file = readBytes(TestSupport.single(TestSupport.logFiles(dir)));
        byte[] good = Bundle.encode(TestSupport.list(file, file));
        byte[] damaged = good.clone();
        // The second entry's length says more than there is.
        damaged[4 + 4 + file.length] = 0x7f;
        CipherLogReadResult result = TestSupport.reader().readBundle(damaged);
        assertEquals(1, result.files().size());
        assertEquals(Collections.singletonList("bad entry length after entry 1, bundle ends"), result.notes());
        assertEquals(2, TestSupport.reader().readBundle(good).files().size());
        assertEquals(Collections.singletonList("not a cipherlog bundle"), TestSupport.reader().readBundle(file).notes());
        // Fewer than 4 bytes left for a length.
        CipherLogReadResult tail = TestSupport.reader().readBundle(TestSupport.concat(good, new byte[] {0, 0}));
        assertEquals(2, tail.files().size());
        assertEquals(Collections.singletonList("bad entry length after entry 2, bundle ends"), tail.notes());
    }

    /** A file with the test key whose records carry {@code chunks} of a raw deflate stream. */
    static byte[] fileOf(List<byte[]> chunks, boolean last) throws Exception {
        byte[] fileKey = new byte[32];
        for (int i = 0; i < 32; i++) fileKey[i] = (byte) (i * 7);
        byte[] fileId = new byte[16];
        for (int i = 0; i < 16; i++) fileId[i] = (byte) i;
        CipherLogKey key = TestSupport.key();
        byte[] out = Format.sealHeader(key.publicKey(), key.keyId(),
                Format.headerPlain(fileKey, fileId, 1_795_000_000_000L, 3, 1));
        Crypto.RecordCipher aead = Format.newAead(fileKey);
        for (int i = 0; i < chunks.size(); i++) {
            int flags = last && i == chunks.size() - 1 ? 1 : 0;
            out = Format.concat(out, Format.sealRecord(aead, fileId, i, flags, chunks.get(i)));
        }
        return out;
    }

    static byte[] syncDeflate(String text) {
        Deflater d = new Deflater(6, true);
        d.setInput(text.getBytes(Format.UTF_8));
        byte[] buf = new byte[1 << 20];
        int n = d.deflate(buf, 0, buf.length, Deflater.SYNC_FLUSH);
        d.end();
        return Arrays.copyOf(buf, n);
    }

    @Test
    public void aZeroLengthEntryIsSkippedAndLaterEntriesStillRead() throws Exception {
        byte[] a = fileOf(TestSupport.list(syncDeflate("a\n")), true);
        byte[] b = fileOf(TestSupport.list(syncDeflate("b\n")), true);
        CipherLogReadResult result = TestSupport.reader().readBundle(Bundle.encode(TestSupport.list(a, new byte[0], b)));
        assertEquals(3, result.files().size());
        assertEquals("a\n", result.files().get(0).text());
        assertEquals(Collections.singletonList("truncated header"), result.files().get(1).notes());
        assertEquals("b\n", result.files().get(2).text());
        assertEquals(Collections.emptyList(), result.notes());
    }

    @Test
    public void totalOutputIsCappedAcrossTheFilesOfOneRead() throws Exception {
        String text = TestSupport.repeat("x", 600);
        byte[] file = fileOf(TestSupport.list(syncDeflate(text)), true);
        CipherLogReader reader = new CipherLogReader(Collections.singletonList(TestSupport.testPrivateKey()), 1000);
        CipherLogReadResult result = reader.readBundle(Bundle.encode(TestSupport.list(file, file, file)));
        assertEquals(text, result.files().get(0).text());
        assertEquals(Collections.emptyList(), result.files().get(0).notes());
        assertEquals(text.substring(0, 400), result.files().get(1).text());
        assertEquals(Collections.singletonList("total output capped at 1000 bytes"), result.files().get(1).notes());
        assertEquals("", result.files().get(2).text());
        assertEquals(Collections.singletonList("total output capped at 1000 bytes"), result.files().get(2).notes());
        // A new read call has its own budget.
        assertEquals(text, reader.read(file).files().get(0).text());
    }

    @Test
    public void aDamagedStreamKeepsTheTextBeforeTheDamage() throws Exception {
        // A good sync-flushed piece, then a block of the reserved type 3 (bits 111).
        CipherLogFile result = TestSupport.reader().readFile(
                fileOf(TestSupport.list(syncDeflate("kept\n"), new byte[] {0x07, 0, 0}), true));
        assertTrue(result.closed());
        assertEquals("kept\n", result.text());
        assertEquals(Collections.singletonList(CipherLogReader.DAMAGED_NOTE), result.notes());
    }

    @Test
    public void readerDetectsFilesBundlesAndArmor() throws Exception {
        byte[] file = fileOf(TestSupport.list(syncDeflate("one\n")), true);
        byte[] bundle = Bundle.encode(TestSupport.list(file));
        String armored = "Hi, logs attached.\r\n\r\n" + CipherLogArmor.armor(bundle).replace("\n", "\r\n")
                + "-- \r\nSent from my phone\r\n";
        for (byte[] input : TestSupport.list(file, bundle, armored.getBytes(Format.UTF_8))) {
            CipherLogReadResult result = TestSupport.reader().read(input);
            assertEquals(Collections.emptyList(), result.notes());
            assertEquals(1, result.files().size());
            assertEquals("one\n", result.files().get(0).text());
        }
        CipherLogReadResult broken = TestSupport.reader().read(
                (CipherLogArmor.BEGIN_LINE + "\nAAAA\n").getBytes(Format.UTF_8));
        assertEquals(Collections.singletonList("armor: no " + CipherLogArmor.END_LINE + " line"), broken.notes());
        assertEquals(0, broken.files().size());
    }
}
