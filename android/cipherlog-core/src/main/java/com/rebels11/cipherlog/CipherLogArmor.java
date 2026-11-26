package com.rebels11.cipherlog;

import java.io.ByteArrayOutputStream;

/**
 * Armored bundles (SPEC.md 4.1): the bundle bytes as base64 text between BEGIN and END lines, so mail filters that
 * block encrypted attachments let them through. Base64 is done here: java.util.Base64 is not on Android 6.
 */
public final class CipherLogArmor {
    private CipherLogArmor() {
    }

    /** {@code -----BEGIN CIPHERLOG BUNDLE-----}. */
    public static final String BEGIN_LINE = "-----BEGIN CIPHERLOG BUNDLE-----";
    /** {@code -----END CIPHERLOG BUNDLE-----}. */
    public static final String END_LINE = "-----END CIPHERLOG BUNDLE-----";
    /** File extension of an armored bundle, without the leading dot. */
    public static final String FILE_EXTENSION = "cipherlogs.txt";
    /** MIME type of an armored bundle. */
    public static final String MIME_TYPE = "text/plain";

    private static final int LINE_LENGTH = 76;
    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    /** BEGIN line, base64 (standard alphabet, padded) in lines of 76 characters, END line; every line ends with \n. */
    public static String armor(byte[] bundle) {
        String b64 = base64(bundle);
        StringBuilder out = new StringBuilder(b64.length() + b64.length() / LINE_LENGTH + 80);
        out.append(BEGIN_LINE).append('\n');
        for (int i = 0; i < b64.length(); i += LINE_LENGTH) {
            out.append(b64, i, Math.min(b64.length(), i + LINE_LENGTH)).append('\n');
        }
        return out.append(END_LINE).append('\n').toString();
    }

    /**
     * Whether {@code data} holds a BEGIN line: a line that is exactly the marker once space, tab and {@code \r} around
     * it are removed. One pass over the bytes; nothing is allocated per line, so hostile input (megabytes of empty
     * lines) costs no memory.
     */
    public static boolean looksArmored(byte[] data) {
        return afterBegin(data) >= 0;
    }

    /**
     * The bundle bytes of an armored text (SPEC.md 4.1). Lines end at {@code \n}; space, tab and {@code \r} around a
     * line are ignored. The BEGIN line is the first line that is exactly the marker (text before it is a mail body and
     * may be any bytes). Every line after it up to the END line is empty or base64; the base64 of all lines together
     * must be padded correctly. Non-canonical padding bits are accepted. Lines are scanned in place, one at a time.
     *
     * @throws IllegalArgumentException with {@code armor: no … line}, {@code armor: line N after BEGIN is not base64}
     *     (N counts from 1 at the line after BEGIN) or {@code armor: base64 is cut or badly padded}
     */
    public static byte[] dearmor(byte[] data) {
        int pos = afterBegin(data);
        if (pos < 0) throw new IllegalArgumentException("armor: no " + BEGIN_LINE + " line");
        byte[] end = Format.ascii(END_LINE);
        StringBuilder b64 = new StringBuilder(Math.max(0, data.length - pos));
        for (int n = 1; pos <= data.length; n++) {
            int lineEnd = lineEnd(data, pos);
            int a = trimStart(data, pos, lineEnd);
            int b = trimEnd(data, a, lineEnd);
            if (equals(data, a, b, end)) {
                byte[] bytes = unbase64(b64);
                if (bytes == null) throw new IllegalArgumentException("armor: base64 is cut or badly padded");
                return bytes;
            }
            for (int i = a; i < b; i++) {
                if (value((char) (data[i] & 0xff)) < 0 && data[i] != '=') {
                    throw new IllegalArgumentException("armor: line " + n + " after BEGIN is not base64");
                }
                b64.append((char) data[i]);
            }
            pos = lineEnd + 1;
        }
        throw new IllegalArgumentException("armor: no " + END_LINE + " line");
    }

    /**
     * The offset just after the BEGIN line (its {@code \n}, or {@code data.length + 1} when it is the last line), or -1
     * when there is none. Lines are the pieces between {@code \n}s, the piece after the last one included.
     */
    private static int afterBegin(byte[] data) {
        byte[] begin = Format.ascii(BEGIN_LINE);
        for (int pos = 0; pos <= data.length; ) {
            int lineEnd = lineEnd(data, pos);
            int a = trimStart(data, pos, lineEnd);
            if (equals(data, a, trimEnd(data, a, lineEnd), begin)) return lineEnd + 1;
            pos = lineEnd + 1;
        }
        return -1;
    }

    /** The index of the next {@code \n} at or after {@code from}, or {@code data.length}. */
    private static int lineEnd(byte[] data, int from) {
        int i = from;
        while (i < data.length && data[i] != '\n') i++;
        return i;
    }

    private static int trimStart(byte[] data, int a, int b) {
        while (a < b && isBlank(data[a])) a++;
        return a;
    }

    private static int trimEnd(byte[] data, int a, int b) {
        while (b > a && isBlank(data[b - 1])) b--;
        return b;
    }

    private static boolean equals(byte[] data, int a, int b, byte[] text) {
        if (b - a != text.length) return false;
        for (int i = 0; i < text.length; i++) if (data[a + i] != text[i]) return false;
        return true;
    }

    private static boolean isBlank(byte c) {
        return c == ' ' || c == '\t' || c == '\r';
    }

    static String base64(byte[] in) {
        StringBuilder out = new StringBuilder((in.length + 2) / 3 * 4);
        int i = 0;
        while (i + 3 <= in.length) {
            int n = ((in[i] & 0xff) << 16) | ((in[i + 1] & 0xff) << 8) | (in[i + 2] & 0xff);
            out.append(ALPHABET[n >>> 18]).append(ALPHABET[(n >>> 12) & 63])
                    .append(ALPHABET[(n >>> 6) & 63]).append(ALPHABET[n & 63]);
            i += 3;
        }
        int rest = in.length - i;
        if (rest == 1) {
            int n = (in[i] & 0xff) << 16;
            out.append(ALPHABET[n >>> 18]).append(ALPHABET[(n >>> 12) & 63]).append("==");
        } else if (rest == 2) {
            int n = ((in[i] & 0xff) << 16) | ((in[i + 1] & 0xff) << 8);
            out.append(ALPHABET[n >>> 18]).append(ALPHABET[(n >>> 12) & 63]).append(ALPHABET[(n >>> 6) & 63]).append('=');
        }
        return out.toString();
    }

    /** Strict padded base64; null when it is not (length, padding in the middle, characters). */
    static byte[] unbase64(CharSequence s) {
        int length = s.length();
        if (length % 4 != 0) return null;
        int padding = 0;
        if (length > 0 && s.charAt(length - 1) == '=') padding++;
        if (length > 1 && s.charAt(length - 2) == '=') padding++;
        ByteArrayOutputStream out = new ByteArrayOutputStream(length / 4 * 3);
        for (int i = 0; i < length; i += 4) {
            boolean last = i + 4 == length;
            int[] v = new int[4];
            for (int j = 0; j < 4; j++) {
                char c = s.charAt(i + j);
                if (c == '=') {
                    if (!last || j < 4 - padding) return null;
                    v[j] = 0;
                } else {
                    v[j] = value(c);
                    if (v[j] < 0) return null;
                }
            }
            int n = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
            out.write(n >>> 16);
            if (!last || padding < 2) out.write((n >>> 8) & 0xff);
            if (!last || padding < 1) out.write(n & 0xff);
        }
        return out.toByteArray();
    }

    private static int value(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }
}
