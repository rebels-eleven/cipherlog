package com.rebels11.cipherlog;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Base64;
import java.util.Random;
import org.junit.Test;

/** SPEC.md 4.1: armored bundles. */
public class ArmorTest {
    private static String error(String text) {
        return error(text.getBytes(Format.UTF_8));
    }

    private static String error(byte[] bytes) {
        try {
            CipherLogArmor.dearmor(bytes);
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }
        throw new AssertionError("accepted: " + new String(bytes, Format.UTF_8));
    }

    @Test
    public void base64MatchesTheJdk() {
        Random random = new Random(3);
        for (int n = 0; n < 300; n++) {
            byte[] bytes = new byte[n];
            random.nextBytes(bytes);
            String ours = CipherLogArmor.base64(bytes);
            assertEquals(Base64.getEncoder().encodeToString(bytes), ours);
            assertArrayEquals(bytes, CipherLogArmor.unbase64(ours));
        }
        assertNull(CipherLogArmor.unbase64("QQ="));
        assertNull(CipherLogArmor.unbase64("Q=QQ"));
        assertNull(CipherLogArmor.unbase64("QQ==QQ=="));
        assertNull(CipherLogArmor.unbase64("Q==="));
    }

    @Test
    public void layout() {
        byte[] bundle = new byte[200];
        new Random(5).nextBytes(bundle);
        String armored = CipherLogArmor.armor(bundle);
        String[] lines = armored.split("\n", -1);
        assertEquals("-----BEGIN CIPHERLOG BUNDLE-----", lines[0]);
        assertEquals(76, lines[1].length());
        assertEquals(76, lines[2].length());
        assertEquals(76, lines[3].length());
        assertEquals(268 - 3 * 76, lines[4].length());
        assertEquals("-----END CIPHERLOG BUNDLE-----", lines[5]);
        assertEquals("", lines[6]);
        assertEquals(7, lines.length);
        assertArrayEquals(bundle, CipherLogArmor.dearmor(armored.getBytes(Format.UTF_8)));
        // Exactly 76 characters: no empty line before END.
        String exact = CipherLogArmor.armor(new byte[57]);
        assertEquals(3, exact.split("\n").length);
    }

    @Test
    public void mailDamageIsTolerated() {
        byte[] bundle = new byte[500];
        new Random(9).nextBytes(bundle);
        String armored = CipherLogArmor.armor(bundle);
        String mail = "Hello,\r\n\r\nhere are my logs.\r\n\r\n"
                + armored.replace("\n", "  \r\n").replace(CipherLogArmor.BEGIN_LINE, "   " + CipherLogArmor.BEGIN_LINE)
                + "\r\n-- \r\nSent from my phone\r\n";
        assertArrayEquals(bundle, CipherLogArmor.dearmor(mail.getBytes(Format.UTF_8)));
        // Bytes that are not UTF-8 before BEGIN are fine too.
        byte[] prefix = {(byte) 0xff, (byte) 0xfe, 0, '\n'};
        assertArrayEquals(bundle, CipherLogArmor.dearmor(Format.concat(prefix, armored.getBytes(Format.UTF_8))));
        // Blank lines between the markers are ignored.
        assertArrayEquals(bundle, CipherLogArmor.dearmor(armored.replace("\n", "\n\n").getBytes(Format.UTF_8)));
        assertTrue(CipherLogArmor.looksArmored(mail.getBytes(Format.UTF_8)));
    }

    @Test
    public void rejections() {
        String begin = CipherLogArmor.BEGIN_LINE + "\n";
        String end = CipherLogArmor.END_LINE + "\n";
        assertEquals("armor: no -----BEGIN CIPHERLOG BUNDLE----- line", error("hello"));
        assertEquals("armor: no -----END CIPHERLOG BUNDLE----- line", error(begin + "QUJD\n"));
        assertEquals("armor: line 2 after BEGIN is not base64", error(begin + "QUJD\nQU JD\n" + end));
        assertEquals("armor: line 1 after BEGIN is not base64", error(begin + "QUJD!\n" + end));
        assertEquals("armor: line 1 after BEGIN is not base64", error(begin + "> QUJD\n" + end));
        // Bad padding or length shows at the END line.
        assertEquals("armor: base64 is cut or badly padded", error(begin + "QUJ\n" + end));
        assertEquals("armor: base64 is cut or badly padded", error(begin + "QQ==QQ==\n" + end));
        // Text after BEGIN on the same line: that line is not the BEGIN line.
        assertEquals("armor: no -----BEGIN CIPHERLOG BUNDLE----- line", error(CipherLogArmor.BEGIN_LINE + " x\nQUJD\n" + end));
    }

    /** A payload that is neither a bundle nor a file gives a note, not a file (SPEC.md 4.1). */
    @Test
    public void armoredPayloadThatIsNeitherBundleNorFile() {
        byte[] armored = Format.ascii(CipherLogArmor.armor(Format.ascii("hello")));
        CipherLogReadResult result = TestSupport.reader().read(armored, "x.txt");
        assertEquals(0, result.files().size());
        assertEquals(java.util.Collections.singletonList("not a cipherlog file or bundle"), result.notes());
        // Armor inside armor is not unwrapped a second time.
        byte[] twice = Format.ascii(CipherLogArmor.armor(Format.ascii(CipherLogArmor.armor(new byte[] {'C', 'P', 'B', '1'}))));
        assertEquals(java.util.Collections.singletonList("not a cipherlog file or bundle"),
                TestSupport.reader().read(twice, "x.txt").notes());
    }

    /**
     * Hostile input: 48 MiB of empty lines, with and without a BEGIN line before them. Detection and dearmor scan the
     * lines in place; an implementation that stores one object per line needs over 1 GiB here and runs out of the
     * 512 MiB test heap (build.gradle.kts).
     */
    @Test
    public void manyEmptyLinesCostNoMemory() {
        byte[] newlines = new byte[48 * 1024 * 1024];
        java.util.Arrays.fill(newlines, (byte) '\n');
        assertTrue(!CipherLogArmor.looksArmored(newlines));
        assertEquals("armor: no -----BEGIN CIPHERLOG BUNDLE----- line", error(newlines));
        CipherLogReadResult plain = TestSupport.reader().read(newlines, "x.txt");
        assertEquals(1, plain.files().size());
        assertEquals(java.util.Collections.singletonList("not a cipherlog file"), plain.files().get(0).notes());
        byte[] begin = Format.ascii(CipherLogArmor.BEGIN_LINE);
        System.arraycopy(begin, 0, newlines, 0, begin.length);
        assertTrue(CipherLogArmor.looksArmored(newlines));
        assertEquals("armor: no -----END CIPHERLOG BUNDLE----- line", error(newlines));
        assertEquals(java.util.Collections.singletonList("armor: no -----END CIPHERLOG BUNDLE----- line"),
                TestSupport.reader().read(newlines, "x.txt").notes());
    }

    /** vectors/armor.json: the cases every implementation shares. */
    @Test
    public void sharedVectors() {
        java.util.List<Object> cases = Json.arr(Json.obj(Json.parse(
                new String(TestSupport.readBytes(new java.io.File(TestSupport.VECTORS, "armor.json")), Format.UTF_8)))
                .get("cases"));
        assertTrue(cases.size() > 20);
        for (Object o : cases) {
            java.util.Map<String, Object> c = Json.obj(o);
            String name = (String) c.get("name");
            byte[] input = ((String) c.get("text")).getBytes(Format.UTF_8);
            if (c.containsKey("bytes")) {
                assertArrayEquals(name, Format.unhex((String) c.get("bytes")), CipherLogArmor.dearmor(input));
                assertTrue(name, CipherLogArmor.looksArmored(input));
            } else {
                assertEquals(name, c.get("error"), error(input));
            }
        }
    }
}
