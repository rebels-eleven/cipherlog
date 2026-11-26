package com.rebels11.cipherlog;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Opens cipherlog files ({@code *.cipherlog}), bundles ({@code *.cipherlogs}) and armored bundles
 * ({@code *.cipherlogs.txt}) with X25519 private keys (32 raw bytes each, or key strings through
 * {@link CipherLogKey#parsePrivateKey(String)}). A file whose key id matches none of them is skipped with a note.
 *
 * <p>Output is capped at 64 MiB per file and at a total budget (256 MiB by default) for all files of one {@code read}
 * or {@code readBundle} call (SPEC.md 5.4): anyone with the public key can build a small bundle of many files that
 * each inflate to the per-file cap.
 */
public final class CipherLogReader {
    /** SPEC.md 5.4: a compressed stream that breaks keeps the text before the damage. */
    static final String DAMAGED_NOTE = "compressed stream damaged, text kept up to the damage";
    /** SPEC.md 5.4: a file without a {@code final} record. */
    static final String NOT_CLOSED_NOTE = "not closed (crash or still open), completeness unknown";

    private final Map<String, byte[]> keys = new HashMap<>();
    private final long maxTotalOutput;

    /** A reader with the default total output budget of 256 MiB per read call. */
    public CipherLogReader(List<byte[]> privateKeys) {
        this(privateKeys, Format.MAX_TOTAL_INFLATED);
    }

    /** A reader with its own total output budget per read call. */
    public CipherLogReader(List<byte[]> privateKeys, long maxTotalOutput) {
        if (maxTotalOutput < 0) throw new IllegalArgumentException("maxTotalOutput must not be negative");
        this.maxTotalOutput = maxTotalOutput;
        for (byte[] secret : privateKeys) {
            if (secret == null || secret.length != Format.KEY_BYTES) {
                throw new IllegalArgumentException("an X25519 private key is 32 bytes");
            }
            keys.put(Format.hex(Format.keyId(Format.publicFromPrivate(secret))), secret.clone());
        }
    }

    /** What is left of the total output budget of one read call. */
    static final class Budget {
        final long total;
        long left;

        Budget(long total) {
            this.total = total;
            this.left = total;
        }
    }

    /** Reads a file from disk: a bundle, an armored bundle or a single file. */
    public CipherLogReadResult read(File file) throws IOException {
        return read(Io.readAll(file), file.getName());
    }

    /**
     * Reads {@code bytes}: a bundle when they start with {@code CPB1}, a single file when they start with {@code CPL1},
     * armored text when they hold a BEGIN line (its payload read as a bundle or a single file, SPEC.md 4.1), otherwise a
     * single file named {@code name} (which then gets the note {@code not a cipherlog file}).
     */
    public CipherLogReadResult read(byte[] bytes, String name) {
        if (Format.startsWith(bytes, Format.BUNDLE_MAGIC)) return readBundle(bytes);
        if (!Format.startsWith(bytes, Format.MAGIC) && CipherLogArmor.looksArmored(bytes)) {
            byte[] bundle;
            try {
                bundle = CipherLogArmor.dearmor(bytes);
            } catch (IllegalArgumentException e) {
                return new CipherLogReadResult(Collections.<CipherLogFile>emptyList(),
                        Collections.singletonList(e.getMessage()));
            }
            // SPEC.md 4.1: the payload is a bundle or a single file, never armor a second time.
            if (Format.startsWith(bundle, Format.BUNDLE_MAGIC)) return readBundle(bundle);
            if (Format.startsWith(bundle, Format.MAGIC)) {
                return new CipherLogReadResult(
                        Collections.singletonList(readFile(bundle, name, new Budget(maxTotalOutput))),
                        Collections.<String>emptyList());
            }
            return new CipherLogReadResult(Collections.<CipherLogFile>emptyList(),
                    Collections.singletonList("not a cipherlog file or bundle"));
        }
        return new CipherLogReadResult(
                Collections.singletonList(readFile(bytes, name, new Budget(maxTotalOutput))),
                Collections.<String>emptyList());
    }

    /** {@link #read(byte[], String)} with the name {@code file}. */
    public CipherLogReadResult read(byte[] bytes) {
        return read(bytes, "file");
    }

    /** A bundle: {@code CPB1} ‖ entries of {@code len} (u32) ‖ file bytes. A bad length ends it with a note. */
    public CipherLogReadResult readBundle(byte[] bytes) {
        if (!Format.startsWith(bytes, Format.BUNDLE_MAGIC)) {
            return new CipherLogReadResult(Collections.<CipherLogFile>emptyList(),
                    Collections.singletonList("not a cipherlog bundle"));
        }
        List<String> notes = new ArrayList<>();
        List<CipherLogFile> files = new ArrayList<>();
        Budget budget = new Budget(maxTotalOutput);
        for (byte[] entry : Bundle.split(bytes, notes)) {
            files.add(readFile(entry, "entry " + (files.size() + 1), budget));
        }
        return new CipherLogReadResult(files, notes);
    }

    /** One {@code *.cipherlog} file. */
    public CipherLogFile readFile(byte[] bytes, String name) {
        return readFile(bytes, name, new Budget(maxTotalOutput));
    }

    /** One {@code *.cipherlog} file named {@code file}. */
    public CipherLogFile readFile(byte[] bytes) {
        return readFile(bytes, "file");
    }

    CipherLogFile readFile(byte[] bytes, String name, Budget budget) {
        List<String> notes = new ArrayList<>();
        if (bytes.length < Format.HEADER_BYTES) {
            boolean header = Format.startsWith(bytes, Format.MAGIC) || bytes.length < 4;
            return skipped(name, null, header ? "truncated header" : "not a cipherlog file");
        }
        if (!Format.startsWith(bytes, Format.MAGIC)) return skipped(name, null, "not a cipherlog file");
        byte[] keyId = Arrays.copyOfRange(bytes, 4, 4 + Format.KEY_ID_BYTES);
        String keyIdHex = Format.hex(keyId);
        byte[] secret = keys.get(keyIdHex);
        if (secret == null) return skipped(name, keyIdHex, "unknown key " + keyIdHex + ", file skipped");
        Format.HeaderPlain header =
                Format.openHeader(secret, keyId, Arrays.copyOfRange(bytes, 4 + Format.KEY_ID_BYTES, Format.HEADER_BYTES));
        if (header == null) return skipped(name, keyIdHex, "header does not open, file skipped");

        Crypto.RecordCipher aead;
        try {
            aead = Format.newAead(header.fileKey);
        } catch (GeneralSecurityException e) {
            return skipped(name, keyIdHex, "header does not open, file skipped");
        }
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        int offset = Format.HEADER_BYTES;
        long seq = 0;
        boolean closed = false;
        while (offset < bytes.length) {
            if (closed) {
                notes.add("readable up to record " + seq + " (data after final)");
                break;
            }
            Format.RecordResult result = Format.openRecord(aead, header.fileId, bytes, offset, seq);
            if (!result.isOk()) {
                notes.add("readable up to record " + seq + " (" + result.reason + ")");
                break;
            }
            stream.write(result.plain, 0, result.plain.length);
            offset += result.size;
            seq++;
            if ((result.flags & Format.FLAG_FINAL) != 0) closed = true;
        }
        String text = inflate(stream.toByteArray(), notes, budget);
        if (!closed) notes.add(NOT_CLOSED_NOTE);
        return new CipherLogFile(name, keyIdHex, Format.hex(header.fileId), header.createdAt, header.platform,
                header.process, true, closed, (int) seq, text, notes);
    }

    private static CipherLogFile skipped(String name, String keyIdHex, String note) {
        return new CipherLogFile(name, keyIdHex, null, null, null, null, false, false, 0, "",
                Collections.singletonList(note));
    }

    private static final class Inflated {
        final byte[] out;
        final boolean capped;
        final boolean damaged;

        Inflated(byte[] out, boolean capped, boolean damaged) {
            this.out = out;
            this.capped = capped;
            this.damaged = damaged;
        }
    }

    private String inflate(byte[] compressed, List<String> notes, Budget budget) {
        if (compressed.length == 0) return "";
        String totalNote = "total output capped at " + sizeText(budget.total);
        if (budget.left <= 0) {
            notes.add(totalNote);
            return "";
        }
        long cap = Math.min(Format.MAX_INFLATED, budget.left);
        Inflated result = inflateRaw(compressed, compressed.length, cap);
        if (result.damaged) {
            // java.util.zip drops the output of the call that hits the damage, so the text before it is found as the
            // output of the longest input prefix that inflates without an error (a prefix of a stream is never
            // damaged when the stream is not, so the search is a bisection).
            int lo = 0;
            int hi = compressed.length;
            Inflated best = new Inflated(new byte[0], false, false);
            while (hi - lo > 1) {
                int mid = lo + (hi - lo) / 2;
                Inflated trial = inflateRaw(compressed, mid, cap);
                if (trial.damaged) {
                    hi = mid;
                } else {
                    lo = mid;
                    best = trial;
                }
            }
            result = new Inflated(best.out, best.capped, true);
        }
        if (result.capped) notes.add(cap < Format.MAX_INFLATED ? totalNote : "output capped at 64 MiB");
        if (result.damaged && !result.capped) notes.add(DAMAGED_NOTE);
        budget.left -= result.out.length;
        return new String(result.out, Format.UTF_8);
    }

    /** Inflates the first {@code length} bytes as one raw stream (an unfinished one is fine), at most {@code cap}. */
    private static Inflated inflateRaw(byte[] input, int length, long cap) {
        Inflater inflater = new Inflater(true);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[64 * 1024];
        try {
            inflater.setInput(input, 0, length);
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                // 0 bytes: the input ends (an unfinished stream is fine, SPEC.md 2.3) or a dictionary is asked for.
                if (n == 0) break;
                if ((long) out.size() + n > cap) {
                    out.write(buffer, 0, (int) (cap - out.size()));
                    return new Inflated(out.toByteArray(), true, false);
                }
                out.write(buffer, 0, n);
            }
        } catch (DataFormatException e) {
            return new Inflated(out.toByteArray(), false, true);
        } finally {
            inflater.end();
        }
        return new Inflated(out.toByteArray(), false, false);
    }

    static String sizeText(long bytes) {
        return bytes % (1024 * 1024) == 0 ? (bytes / (1024 * 1024)) + " MiB" : bytes + " bytes";
    }
}
