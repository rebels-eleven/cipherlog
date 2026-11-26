package com.rebels11.cipherlog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Random;
import org.junit.Test;

/** SPEC.md 2.4: the line format and sanitising. */
public class LinesTest {
    @Test
    public void format() {
        assertEquals("2026-11-26T10:00:00.123Z I app spotify: connect\n",
                Lines.format(Instant.parse("2026-11-26T10:00:00.123Z").toEpochMilli(), CipherLogLevel.I, "app",
                        "spotify", "connect"));
        assertEquals("1970-01-01T00:00:00.000Z F p -: x\n", Lines.format(0, CipherLogLevel.F, "p", null, "x"));
        assertEquals("1970-01-01T00:00:00.000Z D p -: x\n", Lines.format(0, CipherLogLevel.D, "p", "", "x"));
    }

    @Test
    public void timeMatchesJavaTimeEverywhere() {
        // Our calendar (java.time is not on Android 6) against java.time, over leap years and centuries.
        DateTimeFormatter iso = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
        DateTimeFormatter compact = DateTimeFormatter.ofPattern("yyyyMMdd-HHmm").withZone(ZoneOffset.UTC);
        Random random = new Random(7);
        long[] fixed = {0, 951_782_400_000L, 951_868_799_999L, 4_107_542_400_000L, 1_795_000_000_123L,
            253_402_300_799_999L, -1, -86_400_000L, -62_135_596_800_000L};
        for (long t : fixed) assertEquals(iso.format(Instant.ofEpochMilli(t)), Lines.time(t));
        for (int i = 0; i < 200_000; i++) {
            long t = (long) (random.nextDouble() * 253_402_300_799_999L);
            assertEquals(iso.format(Instant.ofEpochMilli(t)), Lines.time(t));
            assertEquals(compact.format(Instant.ofEpochMilli(t)), Lines.compactMinute(t));
        }
    }

    @Test
    public void newlinesBecomeLiteralBackslashN() {
        assertEquals("a\\nb\\nc\\nd", Lines.text("a\r\nb\rc\nd"));
        assertEquals("\\n\\n", Lines.text("\n\r"));
        assertEquals("x\\n", Lines.text("x\r"));
    }

    @Test
    public void controlsBecomeReplacementCharacter() {
        assertEquals("a\tb", Lines.text("a\tb"));
        assertEquals("����", Lines.text("\u0000\u001b\u007f\u0085"));
        assertEquals("[�[31mred", Lines.text("[\u001b[31mred"));
        assertEquals(" é✓🦭", Lines.text(" é✓🦭"));
        // Unpaired surrogates have no UTF-8 form.
        assertEquals("�x�", Lines.text("\uD83Ex\uDC00"));
        // U+2028 and U+2029 stay.
        assertEquals("a b c", Lines.text("a b c"));
    }

    @Test
    public void nameCharset() {
        assertEquals("spotify", Lines.name("spotify"));
        assertEquals("a.b_c-D9", Lines.name("a.b_c-D9"));
        assertEquals("sp_tify__", Lines.name("sp tify/ü"));
        assertEquals("_x", Lines.name("🦭x"));
        assertEquals(TestSupport.repeat("a", 32), Lines.name(TestSupport.repeat("a", 40)));
        assertEquals(TestSupport.repeat("_", 32), Lines.name(TestSupport.repeat("🦭", 40)));
        File dot = new File(".");
        assertEquals("app", CipherLogConfig.builder(dot, TestSupport.key()).processName("app").build().processName());
        assertEquals("my_app", CipherLogConfig.builder(dot, TestSupport.key()).processName("my app").build().processName());
        assertEquals("-", CipherLogConfig.builder(dot, TestSupport.key()).processName("").build().processName());
    }

    @Test
    public void typeNames() {
        assertEquals("IOException", Lines.typeName(new IOException()));
        // An anonymous class has no simple name: the binary name after the package.
        Exception anonymous = new Exception() {
        };
        String name = anonymous.getClass().getName();
        assertEquals(name.substring(name.lastIndexOf('.') + 1), Lines.typeName(anonymous));
        assertFalse(Lines.typeName(anonymous).isEmpty());
    }
}
