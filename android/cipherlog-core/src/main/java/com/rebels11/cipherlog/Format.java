package com.rebels11.cipherlog;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

/** The byte layout of cipherlog-v1 (SPEC.md 1, 2.1, 2.2, 4). Big-endian throughout. */
final class Format {
    private Format() {
    }

    static final Charset ASCII = Charset.forName("US-ASCII");
    static final Charset UTF_8 = Charset.forName("UTF-8");

    static final byte[] MAGIC = ascii("CPL1");
    static final byte[] BUNDLE_MAGIC = ascii("CPB1");
    private static final byte[] KEY_LABEL = ascii("cipherlog-key-v1");
    private static final byte[] INFO_LABEL = ascii("cipherlog-v1");
    private static final byte[] RECORD_LABEL = ascii("cipherlog-rec-v1");

    static final int KEY_BYTES = 32;
    static final int KEY_ID_BYTES = 8;
    static final int FILE_KEY_BYTES = 32;
    static final int FILE_ID_BYTES = 16;
    static final int ENC_BYTES = 32;
    static final int HEADER_PLAIN_BYTES = 58;
    static final int SEALED_BYTES = HEADER_PLAIN_BYTES + 16;
    static final int HEADER_BYTES = 4 + KEY_ID_BYTES + ENC_BYTES + SEALED_BYTES; // 118
    static final int RECORD_HEADER_BYTES = 9;
    static final int TAG_BYTES = 16;
    static final int MIN_LEN = TAG_BYTES;
    static final int MAX_PLAIN = 64 * 1024;
    static final int MAX_LEN = MAX_PLAIN + TAG_BYTES; // 65 552
    static final int FLAG_FINAL = 1;
    static final long MAX_SEQ = 0xFFFFFFFFL;
    static final long MAX_INFLATED = 64L * 1024 * 1024;
    /** SPEC.md 5.4: all files of one read call together (a hostile bundle of many capped files). */
    static final long MAX_TOTAL_INFLATED = 256L * 1024 * 1024;

    static byte[] ascii(String text) {
        return text.getBytes(ASCII);
    }

    static byte[] concat(byte[]... parts) {
        int size = 0;
        for (byte[] part : parts) size += part.length;
        byte[] out = new byte[size];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    static byte[] keyId(byte[] publicKey) {
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is missing", e);
        }
        sha.update(KEY_LABEL);
        sha.update(publicKey);
        return Arrays.copyOf(sha.digest(), KEY_ID_BYTES);
    }

    static byte[] info(byte[] keyId) {
        return concat(INFO_LABEL, MAGIC, keyId);
    }

    static byte[] headerPlain(byte[] fileKey, byte[] fileId, long createdAt, int platform, int process) {
        if (fileKey.length != FILE_KEY_BYTES || fileId.length != FILE_ID_BYTES) {
            throw new IllegalArgumentException("fileKey is 32 bytes and fileId 16");
        }
        return concat(fileKey, fileId, u64(createdAt), new byte[] {(byte) platform, (byte) process});
    }

    /** The 118-byte header: magic ‖ keyId ‖ enc ‖ sealed. */
    static byte[] sealHeader(byte[] publicKey, byte[] keyId, byte[] plain) throws GeneralSecurityException {
        byte[] sealed = Crypto.hpkeSeal(publicKey, plain, info(keyId));
        if (sealed.length != ENC_BYTES + SEALED_BYTES) {
            throw new GeneralSecurityException("HPKE output is " + sealed.length + " bytes");
        }
        byte[] header = concat(MAGIC, keyId, sealed);
        if (header.length != HEADER_BYTES) throw new GeneralSecurityException("header is " + header.length + " bytes");
        return header;
    }

    /** The largest {@code createdAt} a reader accepts: 2^53 - 1 (SPEC.md 2.1). */
    static final long MAX_CREATED_AT = (1L << 53) - 1;

    /** Opens {@code enc ‖ sealed} of a header with a raw X25519 private key; null when it does not open. */
    static HeaderPlain openHeader(byte[] privateKey, byte[] keyId, byte[] encAndSealed) {
        try {
            byte[] plain = Crypto.hpkeOpen(privateKey, encAndSealed, info(keyId));
            if (plain.length != HEADER_PLAIN_BYTES) return null;
            HeaderPlain header = HeaderPlain.parse(plain);
            // createdAt above 2^53 - 1 (SPEC.md 2.1; negative here when above 2^63 - 1) does not open.
            return header.createdAt >= 0 && header.createdAt <= MAX_CREATED_AT ? header : null;
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    static byte[] publicFromPrivate(byte[] privateKey) {
        try {
            return Crypto.publicFromPrivate(privateKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("not an X25519 private key");
        }
    }

    /** The plaintext of a header (SPEC.md 2.1). */
    static final class HeaderPlain {
        final byte[] fileKey;
        final byte[] fileId;
        final long createdAt;
        final int platform;
        final int process;

        private HeaderPlain(byte[] fileKey, byte[] fileId, long createdAt, int platform, int process) {
            this.fileKey = fileKey;
            this.fileId = fileId;
            this.createdAt = createdAt;
            this.platform = platform;
            this.process = process;
        }

        static HeaderPlain parse(byte[] plain) {
            return new HeaderPlain(
                    Arrays.copyOfRange(plain, 0, 32),
                    Arrays.copyOfRange(plain, 32, 48),
                    readU64(plain, 48),
                    plain[56] & 0xff,
                    plain[57] & 0xff);
        }
    }

    static byte[] nonce(long seq) {
        return concat(new byte[8], u32(seq));
    }

    static byte[] recordAad(byte[] fileId, int len, long seq, int flags) {
        return concat(RECORD_LABEL, fileId, u32(len), u32(seq), new byte[] {(byte) flags});
    }

    /** One record: len ‖ seq ‖ flags ‖ ct. */
    static byte[] sealRecord(Crypto.RecordCipher aead, byte[] fileId, long seq, int flags, byte[] plain)
            throws GeneralSecurityException {
        if (plain.length > MAX_PLAIN) throw new IllegalArgumentException("record plaintext over 64 KiB");
        if ((flags & ~FLAG_FINAL) != 0) throw new IllegalArgumentException("reserved flag bits");
        if (seq < 0 || seq > MAX_SEQ) throw new GeneralSecurityException("seq past u32, nonce would repeat");
        int len = plain.length + TAG_BYTES;
        byte[] ct = aead.seal(nonce(seq), plain, recordAad(fileId, len, seq, flags));
        if (ct.length != len) throw new GeneralSecurityException("ciphertext is " + ct.length + " bytes, expected " + len);
        ByteArrayOutputStream out = new ByteArrayOutputStream(RECORD_HEADER_BYTES + len);
        out.write(u32(len), 0, 4);
        out.write(u32(seq), 0, 4);
        out.write(flags);
        out.write(ct, 0, ct.length);
        return out.toByteArray();
    }

    /** What reading one record gives: the plaintext and flags, or why it stops the file ({@link #reason} not null). */
    static final class RecordResult {
        final byte[] plain;
        final int flags;
        final int size;
        final String reason;

        private RecordResult(byte[] plain, int flags, int size, String reason) {
            this.plain = plain;
            this.flags = flags;
            this.size = size;
            this.reason = reason;
        }

        static RecordResult ok(byte[] plain, int flags, int size) {
            return new RecordResult(plain, flags, size, null);
        }

        static RecordResult bad(String reason) {
            return new RecordResult(null, 0, 0, reason);
        }

        boolean isOk() {
            return reason == null;
        }
    }

    /** Reads the record at {@code offset} (SPEC.md 5.3): length bounds, truncated, seq, flags, AEAD, in that order. */
    static RecordResult openRecord(Crypto.RecordCipher aead, byte[] fileId, byte[] bytes, int offset, long expectedSeq) {
        int remaining = bytes.length - offset;
        if (remaining < RECORD_HEADER_BYTES) return RecordResult.bad("truncated");
        long len = readU32(bytes, offset);
        if (len < MIN_LEN || len > MAX_LEN) return RecordResult.bad("bad length " + len);
        if (remaining < RECORD_HEADER_BYTES + len) return RecordResult.bad("truncated");
        long seq = readU32(bytes, offset + 4);
        if (seq != expectedSeq) return RecordResult.bad("seq " + seq + ", expected " + expectedSeq);
        int flags = bytes[offset + 8] & 0xff;
        if ((flags & ~FLAG_FINAL) != 0) {
            return RecordResult.bad(String.format(Locale.ROOT, "reserved flag bits 0x%02x", flags));
        }
        int start = offset + RECORD_HEADER_BYTES;
        byte[] ct = Arrays.copyOfRange(bytes, start, start + (int) len);
        byte[] plain;
        try {
            plain = aead.open(nonce(seq), ct, recordAad(fileId, (int) len, seq, flags));
        } catch (GeneralSecurityException e) {
            return RecordResult.bad("authentication failed");
        }
        return RecordResult.ok(plain, flags, RECORD_HEADER_BYTES + (int) len);
    }

    static Crypto.RecordCipher newAead(byte[] fileKey) throws GeneralSecurityException {
        return Crypto.recordCipher(fileKey);
    }

    static byte[] u32(long n) {
        return new byte[] {(byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n};
    }

    static byte[] u64(long n) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) out[i] = (byte) (n >>> (56 - 8 * i));
        return out;
    }

    static long readU32(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xffL) << 24) | ((bytes[offset + 1] & 0xffL) << 16)
                | ((bytes[offset + 2] & 0xffL) << 8) | (bytes[offset + 3] & 0xffL);
    }

    static long readU64(byte[] bytes, int offset) {
        long n = 0;
        for (int i = 0; i < 8; i++) n = (n << 8) | (bytes[offset + i] & 0xffL);
        return n;
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[2 * i] = HEX[(bytes[i] >> 4) & 0xf];
            out[2 * i + 1] = HEX[bytes[i] & 0xf];
        }
        return new String(out);
    }

    /** Upper- or lowercase hex to bytes. */
    static byte[] unhex(String text) {
        if (text.length() % 2 != 0) throw new IllegalArgumentException("odd hex length");
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = hexDigit(text.charAt(2 * i));
            int lo = hexDigit(text.charAt(2 * i + 1));
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("not hex");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** An ASCII hex digit's value, or -1 (Character.digit would also take other scripts' digits). */
    static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    static boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (bytes[i] != prefix[i]) return false;
        return true;
    }
}
