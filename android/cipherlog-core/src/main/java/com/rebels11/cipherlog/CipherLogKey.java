package com.rebels11.cipherlog;

import java.util.Arrays;

/**
 * The developer's X25519 public key (32 raw bytes) that every log file is encrypted to (SPEC.md 1).
 *
 * <p>Only the holder of the matching private key can read the files. The library embeds no key: the app passes its
 * own, usually as a key string {@code cipherlog-pub-v1:<64 hex>} ({@link #parse(String)}, SPEC.md 1.1). Never ship the
 * test key from {@code vectors/test-key.json} in an app ({@link #isTestKey()}).
 */
public final class CipherLogKey {
    /** Prefix of a public key string (SPEC.md 1.1). */
    public static final String PUBLIC_PREFIX = "cipherlog-pub-v1:";
    /** Prefix of a private key string (SPEC.md 1.1); private keys belong in the developer's vault, never in an app. */
    public static final String PRIVATE_PREFIX = "cipherlog-priv-v1:";

    /**
     * The {@code keyId} of the published TEST key ({@code vectors/test-key.json}), which anyone can read logs written
     * to. The library embeds only this id, not the key; 64 bits of SHA-256 are plenty to tell the test key apart.
     */
    private static final String TEST_KEY_ID_HEX = "dacb47e7a1ba0cf1";

    private final byte[] raw;
    private final byte[] id;

    /** A key from its 32 raw bytes. */
    public CipherLogKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != Format.KEY_BYTES) {
            throw new IllegalArgumentException(
                    "an X25519 public key is 32 bytes, got " + (publicKey == null ? "null" : publicKey.length));
        }
        raw = publicKey.clone();
        id = Format.keyId(raw);
    }

    /**
     * A key from a public key string {@code cipherlog-pub-v1:<64 hex digits>} (upper- or lowercase hex, whitespace
     * around it allowed).
     *
     * @throws IllegalArgumentException naming the problem (empty, a private key given, wrong prefix, a character that
     *     is not hex, wrong length); text around the key other than whitespace is one of these
     */
    public static CipherLogKey parse(String keyString) {
        return new CipherLogKey(parseKeyString(keyString, PUBLIC_PREFIX));
    }

    /** A key from 64 hex digits without the prefix (whitespace around them allowed). */
    public static CipherLogKey fromHex(String hex) {
        return parse(PUBLIC_PREFIX + (hex == null ? "" : trimWhitespace(hex)));
    }

    /**
     * The 32 raw bytes of a private key string {@code cipherlog-priv-v1:<64 hex digits>}, for {@link CipherLogReader}.
     * The error never repeats the key or any part of it.
     *
     * @throws IllegalArgumentException naming the problem
     */
    public static byte[] parsePrivateKey(String keyString) {
        return parseKeyString(keyString, PRIVATE_PREFIX);
    }

    /** The private key string of 32 raw bytes: {@code cipherlog-priv-v1:} and 64 lowercase hex digits. */
    public static String privateKeyString(byte[] privateKey) {
        if (privateKey == null || privateKey.length != Format.KEY_BYTES) {
            throw new IllegalArgumentException("an X25519 private key is 32 bytes");
        }
        return PRIVATE_PREFIX + Format.hex(privateKey);
    }

    private static byte[] parseKeyString(String text, String prefix) {
        boolean isPrivate = prefix.equals(PRIVATE_PREFIX);
        String s = text == null ? "" : trimWhitespace(text);
        if (s.isEmpty()) throw new IllegalArgumentException("cipherlog key: the key string is empty");
        if (!s.startsWith(prefix)) {
            String other = isPrivate ? PUBLIC_PREFIX : PRIVATE_PREFIX;
            if (s.startsWith(other)) {
                // Never echoed: a private key pasted where the public one belongs must not reach a log.
                throw new IllegalArgumentException(isPrivate
                        ? "cipherlog key: this is a public key (cipherlog-pub-v1:…); opening logs needs the private"
                                + " key (cipherlog-priv-v1:…)"
                        : "cipherlog key: this is a PRIVATE key (cipherlog-priv-v1:…); an app ships only the public"
                                + " key (cipherlog-pub-v1:…)");
            }
            throw new IllegalArgumentException("cipherlog key: the key string must start with " + prefix);
        }
        String body = s.substring(prefix.length());
        int position = 0;
        for (int i = 0; i < body.length(); ) {
            int cp = body.codePointAt(i);
            position++;
            if (cp > 0x7F || Format.hexDigit((char) cp) < 0) {
                // Only a public key's character is echoed; it is not secret.
                throw new IllegalArgumentException("cipherlog key: character " + position
                        + " after the prefix is not a hex digit" + (isPrivate ? "" : " (" + escaped(cp) + ")"));
            }
            i += Character.charCount(cp);
        }
        if (position != 64) {
            throw new IllegalArgumentException(
                    "cipherlog key: expected 64 hex characters after the prefix, got " + position);
        }
        return Format.unhex(body);
    }

    /** A printable form of one character for an error message (control and invisible ones as {@code U+XXXX}). */
    private static String escaped(int cp) {
        if (cp >= 0x21 && cp < 0x7F) return "\"" + (char) cp + "\"";
        return String.format(java.util.Locale.ROOT, "U+%04X", cp);
    }

    /**
     * Strips space, tab, CR and LF at both ends (SPEC.md 1.1). Other whitespace (a no-break space, a byte order mark)
     * stays and is reported like any other wrong character.
     */
    private static String trimWhitespace(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && isSpace(s.charAt(start))) start++;
        while (end > start && isSpace(s.charAt(end - 1))) end--;
        return s.substring(start, end);
    }

    private static boolean isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    /** A copy of the 32-byte public key. */
    public byte[] publicKey() {
        return raw.clone();
    }

    /** First 8 bytes of SHA-256("cipherlog-key-v1" ‖ publicKey): tells a reader which private key to use. */
    public byte[] keyId() {
        return id.clone();
    }

    /** {@link #keyId()} as 16 lowercase hex digits. */
    public String keyIdHex() {
        return Format.hex(id);
    }

    /** The public key string {@code cipherlog-pub-v1:<64 lowercase hex>} (SPEC.md 1.1). */
    public String keyString() {
        return PUBLIC_PREFIX + Format.hex(raw);
    }

    /** True for the published test key, which must never ship in an app. */
    public boolean isTestKey() {
        return keyIdHex().equals(TEST_KEY_ID_HEX);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof CipherLogKey && Arrays.equals(raw, ((CipherLogKey) other).raw);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(raw);
    }

    @Override
    public String toString() {
        return "CipherLogKey(" + keyIdHex() + ")";
    }
}
