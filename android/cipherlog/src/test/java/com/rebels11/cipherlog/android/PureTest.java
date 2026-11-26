package com.rebels11.cipherlog.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.rebels11.cipherlog.CipherLogLevel;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

/** The parts of the Android module that need no device. */
public class PureTest {
    @Test
    public void processNames() {
        ProcessNames.Detected main = ProcessNames.of("com.example", "com.example");
        assertEquals(1, main.process);
        assertEquals("app", main.name);
        ProcessNames.Detected sync = ProcessNames.of("com.example:sync", "com.example");
        assertEquals(2, sync.process);
        assertEquals("sync", sync.name);
        ProcessNames.Detected other = ProcessNames.of("com.other.remote", "com.example");
        assertEquals(2, other.process);
        assertEquals("com.other.remote", other.name);
        assertEquals("app", ProcessNames.of(null, "com.example").name);
        assertEquals("app", ProcessNames.of("", "com.example").name);
    }

    @Test
    public void cmdline() {
        assertEquals("com.example:sync",
                ProcessNames.fromCmdline("com.example:sync\0\0\0".getBytes(StandardCharsets.UTF_8)));
        assertEquals("com.example", ProcessNames.fromCmdline("com.example".getBytes(StandardCharsets.UTF_8)));
        assertNull(ProcessNames.fromCmdline(new byte[] {0, 0}));
        assertNull(ProcessNames.fromCmdline(new byte[0]));
    }

    @Test
    public void levels() {
        assertEquals(CipherLogLevel.D, LogLine.levelOf(android.util.Log.VERBOSE));
        assertEquals(CipherLogLevel.D, LogLine.levelOf(android.util.Log.DEBUG));
        assertEquals(CipherLogLevel.I, LogLine.levelOf(android.util.Log.INFO));
        assertEquals(CipherLogLevel.W, LogLine.levelOf(android.util.Log.WARN));
        assertEquals(CipherLogLevel.E, LogLine.levelOf(android.util.Log.ERROR));
        assertEquals(CipherLogLevel.F, LogLine.levelOf(android.util.Log.ASSERT));
        assertEquals(CipherLogLevel.D, LogLine.levelOf(0));
        assertEquals(CipherLogLevel.F, LogLine.levelOf(99));
    }

    @Test
    public void roundedSizes() {
        assertEquals("23 GB", DeviceCollectors.roundedSize(23_400_000_000L));
        assertEquals("24 GB", DeviceCollectors.roundedSize(23_500_000_000L));
        assertEquals("1 GB", DeviceCollectors.roundedSize(1_000_000_000L));
        assertEquals("0.4 GB", DeviceCollectors.roundedSize(420_000_000L));
        assertEquals("0.0 GB", DeviceCollectors.roundedSize(-5));
    }

    @Test
    public void models() {
        assertEquals("Google Pixel 9", DeviceCollectors.model("Google", "Pixel 9"));
        assertEquals("samsung SM-S721B", DeviceCollectors.model("samsung", "SM-S721B"));
        assertEquals("OnePlus 12", DeviceCollectors.model("OnePlus", "OnePlus 12"));
        assertEquals("-", DeviceCollectors.model(null, null));
    }

    @Test
    public void onlyExportsAreServed() {
        String folder = "0123456789abcdef0123456789abcdef";
        assertTrue(CipherLogFileProvider.isExportPath("exports", folder, "cipherlog-20261126-1007.cipherlogs.txt"));
        assertTrue(CipherLogFileProvider.isExportPath("exports", folder, "cipherlog-20261126-1007.cipherlogs"));
        assertFalse(CipherLogFileProvider.isExportPath("exports", folder, "../cipherlog-20261126-1007.cipherlogs"));
        assertFalse(CipherLogFileProvider.isExportPath("exports", "..", "cipherlog-20261126-1007.cipherlogs"));
        assertFalse(CipherLogFileProvider.isExportPath("exports", folder.toUpperCase(), "cipherlog-20261126-1007.cipherlogs"));
        assertFalse(CipherLogFileProvider.isExportPath("files", folder, "cipherlog-20261126-1007.cipherlogs"));
        assertFalse(CipherLogFileProvider.isExportPath("exports", folder, "app-1795000000000-0011aabb.cipherlog"));
        assertFalse(CipherLogFileProvider.isExportPath("exports", folder, "shared_prefs.xml"));
        assertFalse(CipherLogFileProvider.isExportPath("exports", null, null));
        assertEquals("text/plain", CipherLogFileProvider.mimeTypeOf("cipherlog-20261126-1007.cipherlogs.txt"));
        assertEquals("application/octet-stream", CipherLogFileProvider.mimeTypeOf("cipherlog-20261126-1007.cipherlogs"));
    }
}
