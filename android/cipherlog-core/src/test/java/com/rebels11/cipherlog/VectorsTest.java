package com.rebels11.cipherlog;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** vectors/records.json and vectors/test-key.json (SPEC.md 8). */
public class VectorsTest {
    private final Map<String, Object> json = TestSupport.recordsJson();
    private final Map<String, Object> header = Json.obj(json.get("header"));
    private final byte[] fileKey = Format.unhex((String) header.get("fileKey"));
    private final byte[] fileId = Format.unhex((String) header.get("fileId"));

    private static String str(Map<String, Object> m, String k) {
        return (String) m.get(k);
    }

    private static long num(Map<String, Object> m, String k) {
        return (Long) m.get(k);
    }

    @Test
    public void keyIdOfTheTestKey() {
        assertEquals(TestSupport.testKeyIdHex(), TestSupport.key().keyIdHex());
        assertEquals(json.get("keyId"), TestSupport.key().keyIdHex());
        assertArrayEquals(Format.publicFromPrivate(TestSupport.testPrivateKey()), TestSupport.testPublicKey());
        assertTrue(TestSupport.key().isTestKey());
    }

    @Test
    public void headerOpensWithTheTestPrivateKey() {
        byte[] bytes = Format.unhex(str(header, "hex"));
        assertEquals(118, bytes.length);
        assertArrayEquals(Format.ascii("CPL1"), Arrays.copyOfRange(bytes, 0, 4));
        byte[] keyId = Arrays.copyOfRange(bytes, 4, 12);
        assertEquals(TestSupport.testKeyIdHex(), Format.hex(keyId));
        assertEquals(str(header, "info"), Format.hex(Format.info(keyId)));
        Format.HeaderPlain plain = Format.openHeader(TestSupport.testPrivateKey(), keyId, Arrays.copyOfRange(bytes, 12, 118));
        assertNotNull(plain);
        assertArrayEquals(fileKey, plain.fileKey);
        assertArrayEquals(fileId, plain.fileId);
        assertEquals(num(header, "createdAt"), plain.createdAt);
        assertEquals(num(header, "platform"), plain.platform);
        assertEquals(num(header, "process"), plain.process);
    }

    @Test
    public void ourHeaderRoundTrips() throws Exception {
        CipherLogKey key = TestSupport.key();
        byte[] plain = Format.headerPlain(fileKey, fileId, 1_795_000_000_123L, 2, 7);
        byte[] bytes = Format.sealHeader(key.publicKey(), key.keyId(), plain);
        assertEquals(118, bytes.length);
        Format.HeaderPlain opened = Format.openHeader(TestSupport.testPrivateKey(), key.keyId(), Arrays.copyOfRange(bytes, 12, 118));
        assertNotNull(opened);
        assertArrayEquals(fileKey, opened.fileKey);
        assertEquals(1_795_000_000_123L, opened.createdAt);
        assertEquals(2, opened.platform);
        assertEquals(7, opened.process);
    }

    /** SPEC.md 2.1: a createdAt above 2^53 - 1 counts as a header that does not open. */
    @Test
    public void createdAtAboveTwoToThe53DoesNotOpen() throws Exception {
        CipherLogKey key = TestSupport.key();
        for (long createdAt : new long[] {(1L << 53) - 1, 1L << 53, -1L}) {
            byte[] bytes = Format.sealHeader(key.publicKey(), key.keyId(),
                    Format.headerPlain(fileKey, fileId, createdAt, 2, 7));
            Format.HeaderPlain opened =
                    Format.openHeader(TestSupport.testPrivateKey(), key.keyId(), Arrays.copyOfRange(bytes, 12, 118));
            assertEquals(String.valueOf(createdAt), createdAt == (1L << 53) - 1, opened != null);
        }
    }

    @Test
    public void recordsEncryptByteExact() throws Exception {
        Crypto.RecordCipher aead = Format.newAead(fileKey);
        for (Object o : Json.arr(json.get("records"))) {
            Map<String, Object> c = Json.obj(o);
            byte[] plain = Format.unhex(str(c, "plaintext"));
            byte[] record = Format.sealRecord(aead, fileId, num(c, "seq"), (int) num(c, "flags"), plain);
            assertEquals(str(c, "name"), str(c, "record"), Format.hex(record));
        }
    }

    @Test
    public void recordsDecrypt() throws Exception {
        Crypto.RecordCipher aead = Format.newAead(fileKey);
        for (Object o : Json.arr(json.get("records"))) {
            Map<String, Object> c = Json.obj(o);
            String name = str(c, "name");
            byte[] record = Format.unhex(str(c, "record"));
            Format.RecordResult result = Format.openRecord(aead, fileId, record, 0, num(c, "seq"));
            assertTrue(name + ": " + result.reason, result.isOk());
            assertEquals(name, str(c, "plaintext"), Format.hex(result.plain));
            assertEquals(name, num(c, "flags"), result.flags);
            assertEquals(name, record.length, result.size);
        }
    }

    @Test
    public void everyRejectionIsRejectedWithTheVectorsReason() throws Exception {
        // SPEC.md 5.3 pins the order (length bounds, truncated, seq, flags, AEAD), so every reader gives the same reason.
        Crypto.RecordCipher aead = Format.newAead(fileKey);
        List<Object> rejections = Json.arr(json.get("rejections"));
        assertTrue(rejections.size() >= 9);
        for (Object o : rejections) {
            Map<String, Object> c = Json.obj(o);
            String name = str(c, "name");
            Format.RecordResult result = Format.openRecord(aead, fileId, Format.unhex(str(c, "record")), 0, num(c, "seq"));
            assertFalse(name + " must be rejected", result.isOk());
            assertEquals(name, str(c, "reason"), result.reason);
        }
    }

    @Test
    public void reservedFlagBitsAreRefusedByTheWriter() throws Exception {
        Crypto.RecordCipher aead = Format.newAead(fileKey);
        try {
            Format.sealRecord(aead, fileId, 0, 2, new byte[0]);
            fail("flags 2 must be refused");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test
    public void aSeqPastU32IsRefusedByTheWriter() throws Exception {
        Crypto.RecordCipher aead = Format.newAead(fileKey);
        try {
            Format.sealRecord(aead, fileId, 0x1_0000_0000L, 0, new byte[0]);
            fail("seq 2^32 must be refused");
        } catch (GeneralSecurityException expected) {
            // ok
        }
    }

    @Test
    public void wholeFileVectorReads() {
        Map<String, Object> file = Json.obj(json.get("file"));
        CipherLogFile result = TestSupport.reader().readFile(Format.unhex(str(file, "hex")));
        assertTrue(result.opened());
        assertEquals(str(file, "text"), result.text());
        assertEquals(file.get("final"), result.closed());
        assertEquals(3, result.records());
        assertEquals(Collections.emptyList(), result.notes());
        assertEquals("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", result.fileIdHex());
        assertEquals(Integer.valueOf(1), result.platform());
        assertEquals(Integer.valueOf(2), result.process());
    }

    @Test
    public void unknownKeyIsSkippedWithANote() {
        Map<String, Object> file = Json.obj(json.get("file"));
        byte[] other = new byte[32];
        for (int i = 0; i < 32; i++) other[i] = (byte) (i + 1);
        CipherLogFile result = new CipherLogReader(Collections.singletonList(other)).readFile(Format.unhex(str(file, "hex")));
        assertFalse(result.opened());
        assertEquals("", result.text());
        assertEquals(1, result.notes().size());
        assertTrue(result.notes().toString(), result.notes().get(0).startsWith("unknown key " + TestSupport.testKeyIdHex()));
    }

    @Test
    public void everyRecordRejectionInsideAFileNamesItsReason() throws Exception {
        // The same rejections as whole files: header ‖ bad record gives "readable up to record 0 (<reason>)".
        byte[] fileHeader = Format.unhex(str(header, "hex"));
        for (Object o : Json.arr(json.get("rejections"))) {
            Map<String, Object> c = Json.obj(o);
            if (num(c, "seq") != 0) continue;
            byte[] bytes = Format.concat(fileHeader, Format.unhex(str(c, "record")));
            CipherLogFile result = TestSupport.reader().readFile(bytes);
            assertEquals(str(c, "name"), "readable up to record 0 (" + str(c, "reason") + ")", result.notes().get(0));
        }
    }
}
