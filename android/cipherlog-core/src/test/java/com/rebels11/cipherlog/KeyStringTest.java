package com.rebels11.cipherlog;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/** SPEC.md 1.1: key strings. */
public class KeyStringTest {
    private static final String PUB_HEX = "ecd8b29e913351f6a28fda6e663ad350273ed38a9b44fe8f1b8116a236154170";

    private static String publicError(String input) {
        try {
            CipherLogKey.parse(input);
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }
        throw new AssertionError("accepted: " + input);
    }

    private static String privateError(String input) {
        try {
            CipherLogKey.parsePrivateKey(input);
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }
        throw new AssertionError("accepted a private key string");
    }

    @Test
    public void publicKeyStringRoundTrips() {
        CipherLogKey key = CipherLogKey.parse("cipherlog-pub-v1:" + PUB_HEX);
        assertEquals(TestSupport.key(), key);
        assertEquals("cipherlog-pub-v1:" + PUB_HEX, key.keyString());
        assertEquals(TestSupport.testKeyIdHex(), key.keyIdHex());
        assertTrue(key.isTestKey());
        // Uppercase hex and whitespace around the string are fine.
        assertEquals(key, CipherLogKey.parse("  \t cipherlog-pub-v1:" + PUB_HEX.toUpperCase() + "\r\n"));
        assertEquals(key, CipherLogKey.fromHex(PUB_HEX));
        byte[] other = new byte[32];
        other[0] = 9;
        assertFalse(new CipherLogKey(other).isTestKey());
    }

    @Test
    public void privateKeyStringRoundTrips() {
        byte[] secret = TestSupport.testPrivateKey();
        String string = CipherLogKey.privateKeyString(secret);
        assertTrue(string.startsWith("cipherlog-priv-v1:"));
        assertArrayEquals(secret, CipherLogKey.parsePrivateKey(string));
        assertArrayEquals(secret, CipherLogKey.parsePrivateKey(" " + string.toUpperCase().replace("CIPHERLOG-PRIV-V1:", "cipherlog-priv-v1:") + "\n"));
    }

    @Test
    public void everyProblemIsNamed() {
        assertEquals("cipherlog key: the key string is empty", publicError("   "));
        assertEquals("cipherlog key: the key string is empty", publicError(null));
        assertEquals("cipherlog key: the key string must start with cipherlog-pub-v1:", publicError(PUB_HEX));
        assertEquals("cipherlog key: the key string must start with cipherlog-pub-v1:",
                publicError("key: cipherlog-pub-v1:" + PUB_HEX));
        assertEquals("cipherlog key: the key string must start with cipherlog-pub-v1:",
                publicError("CIPHERLOG-PUB-V1:" + PUB_HEX));
        assertEquals("cipherlog key: expected 64 hex characters after the prefix, got 63",
                publicError("cipherlog-pub-v1:" + PUB_HEX.substring(1)));
        assertEquals("cipherlog key: character 65 after the prefix is not a hex digit (\".\")",
                publicError("cipherlog-pub-v1:" + PUB_HEX + "."));
        assertEquals("cipherlog key: character 65 after the prefix is not a hex digit (U+0020)",
                publicError("cipherlog-pub-v1:" + PUB_HEX + " trailing"));
        assertEquals("cipherlog key: character 3 after the prefix is not a hex digit (\"g\")",
                publicError("cipherlog-pub-v1:ecg8" + PUB_HEX.substring(4)));
        // Digits of other scripts are not hex.
        assertEquals("cipherlog key: character 1 after the prefix is not a hex digit (U+0661)",
                publicError("cipherlog-pub-v1:١" + PUB_HEX.substring(1)));
        assertEquals("cipherlog key: expected 64 hex characters after the prefix, got 66",
                publicError("cipherlog-pub-v1:" + PUB_HEX + "00"));
    }

    @Test
    public void aPrivateKeyIsNeverEchoed() {
        String secretHex = Format.hex(TestSupport.testPrivateKey());
        String priv = "cipherlog-priv-v1:" + secretHex;
        String given = publicError(priv);
        assertTrue(given, given.contains("PRIVATE"));
        assertFalse(given.contains(secretHex.substring(0, 8)));
        String[] broken = {
            "cipherlog-priv-v1:" + secretHex.substring(0, 10) + "z" + secretHex.substring(11),
            "cipherlog-priv-v1:" + secretHex + "x",
            "cipherlog-priv-v1:" + secretHex.substring(2),
            "cipherlog-pub-v1:" + secretHex,
            secretHex,
        };
        for (String input : broken) {
            String message = privateError(input);
            for (int i = 0; i + 4 <= secretHex.length(); i++) {
                assertFalse(message, message.contains(secretHex.substring(i, i + 4)));
            }
        }
        assertEquals("cipherlog key: character 11 after the prefix is not a hex digit", privateError(broken[0]));
    }

    /** vectors/keys.json: the cases every implementation shares. */
    @Test
    public void sharedVectors() {
        java.util.List<Object> cases = Json.arr(Json.obj(Json.parse(
                new String(TestSupport.readBytes(new java.io.File(TestSupport.VECTORS, "keys.json")), Format.UTF_8)))
                .get("cases"));
        assertTrue(cases.size() > 20);
        String privHex = Format.hex(TestSupport.testPrivateKey());
        for (Object o : cases) {
            java.util.Map<String, Object> c = Json.obj(o);
            String name = (String) c.get("name");
            String input = (String) c.get("input");
            boolean isPrivate = "private".equals(c.get("kind"));
            if (c.containsKey("key")) {
                byte[] raw = isPrivate ? CipherLogKey.parsePrivateKey(input) : CipherLogKey.parse(input).publicKey();
                assertEquals(name, c.get("key"), Format.hex(raw));
            } else {
                String message = isPrivate ? privateError(input) : publicError(input);
                assertEquals(name, "cipherlog key: " + c.get("error"), message);
                assertFalse(name, message.toLowerCase(java.util.Locale.ROOT).contains(privHex.substring(0, 8)));
            }
        }
    }

    /** The library embeds only the test key's id (SPEC.md 1: apps must never ship the test key). */
    @Test
    public void theTestKeyIsNotEmbedded() {
        String pubHex = Format.hex(TestSupport.testPublicKey());
        java.util.List<java.io.File> todo = new java.util.ArrayList<>();
        todo.add(new java.io.File(TestSupport.REPO_ROOT, "android/cipherlog-core/src/main"));
        todo.add(new java.io.File(TestSupport.REPO_ROOT, "android/cipherlog/src/main"));
        int checked = 0;
        while (!todo.isEmpty()) {
            java.io.File f = todo.remove(todo.size() - 1);
            java.io.File[] children = f.listFiles();
            if (children != null) {
                java.util.Collections.addAll(todo, children);
            } else if (f.isFile()) {
                String text = new String(TestSupport.readBytes(f), Format.UTF_8).toLowerCase(java.util.Locale.ROOT);
                assertFalse(f.getPath(), text.contains(pubHex) || text.contains(pubHex.substring(0, 16)));
                checked++;
            }
        }
        assertTrue(checked > 10);
    }
}
