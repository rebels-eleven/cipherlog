package com.rebels11.cipherlog;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.zip.Deflater;

/**
 * One open cipherlog file: its key, its compressed stream and its records (SPEC.md 2). Not thread-safe; the writer
 * uses it from its worker thread only. {@link #out} gets the header and then whole records, one {@code write} per
 * record.
 *
 * <p>Exceptions: {@link IOException} from {@link #out} (disk full, write failure), {@link GeneralSecurityException} from
 * the AEAD, {@link LinkageError} when Tink is missing.
 */
final class LogFile {
    final OutputStream out;
    final byte[] fileId;
    private final Crypto.RecordCipher aead;
    private final Deflater deflater = new Deflater(6, true);
    private final byte[] buffer = new byte[16 * 1024];
    private final ByteArrayOutputStream pending = new ByteArrayOutputStream();
    /** The next record's seq; a u32 (SPEC.md 2.2). Package-private so a test can start near the end of the range. */
    long seq = 0;
    private boolean finished = false;
    private boolean released = false;
    private boolean dirty = false;
    private long size;
    private long unflushedInput = 0;
    /** Lines the app wrote into this file (the device block does not count). */
    int appLines = 0;

    LogFile(OutputStream out, byte[] fileKey, byte[] fileId, byte[] header) throws IOException, GeneralSecurityException {
        this.out = out;
        this.fileId = fileId;
        try {
            this.aead = Format.newAead(fileKey);
            out.write(header);
        } catch (IOException | GeneralSecurityException | RuntimeException | Error e) {
            release();
            throw e;
        }
        size = header.length;
    }

    /** The compressor's native memory was freed (finish, abandon or a failed header write). */
    boolean released() {
        return released;
    }

    /** Bytes written to {@link #out} so far, header included. */
    long size() {
        return size;
    }

    /** Uncompressed bytes appended since the last flush: an upper bound of what the next flush adds. */
    long unflushedInput() {
        return unflushedInput;
    }

    /** Compresses {@code text}; full 64 KiB pieces of output become records at once. */
    void append(String text) throws IOException, GeneralSecurityException {
        if (finished) throw new IllegalStateException("file finished");
        byte[] bytes = text.getBytes(Format.UTF_8);
        deflater.setInput(bytes);
        dirty = true;
        unflushedInput += bytes.length;
        while (!deflater.needsInput()) {
            int n = deflater.deflate(buffer, 0, buffer.length, Deflater.NO_FLUSH);
            if (n > 0) pending.write(buffer, 0, n);
        }
        while (pending.size() >= Format.MAX_PLAIN) emit(false, false);
    }

    /** Sync flush: everything appended so far becomes records. */
    void flush() throws IOException, GeneralSecurityException {
        if (finished) throw new IllegalStateException("file finished");
        if (!dirty) return;
        dirty = false;
        unflushedInput = 0;
        while (true) {
            int n = deflater.deflate(buffer, 0, buffer.length, Deflater.SYNC_FLUSH);
            if (n > 0) pending.write(buffer, 0, n);
            if (n < buffer.length) break;
        }
        emit(false, true);
    }

    /** Finishes the stream; its output goes into the last record, which carries {@code final}. Nothing may follow. */
    void finish() throws IOException, GeneralSecurityException {
        if (finished) throw new IllegalStateException("file finished");
        try {
            deflater.finish();
            while (!deflater.finished()) {
                int n = deflater.deflate(buffer);
                if (n > 0) pending.write(buffer, 0, n);
            }
            finished = true;
            emit(true, true);
        } finally {
            finished = true;
            release();
        }
    }

    /** Frees the compressor without writing anything (the file stays without {@code final}). */
    void abandon() {
        finished = true;
        release();
    }

    private void release() {
        if (released) return;
        released = true;
        deflater.end();
    }

    private void emit(boolean last, boolean all) throws IOException, GeneralSecurityException {
        byte[] data = pending.toByteArray();
        pending.reset();
        int offset = 0;
        while (data.length - offset >= Format.MAX_PLAIN || (all && offset < data.length)) {
            int end = Math.min(offset + Format.MAX_PLAIN, data.length);
            boolean isLast = end == data.length;
            writeRecord(Arrays.copyOfRange(data, offset, end), last && isLast ? Format.FLAG_FINAL : 0);
            offset = end;
        }
        if (offset < data.length) pending.write(data, offset, data.length - offset);
        // A final record is always written, empty when the finish produced nothing new.
        if (last && data.length == 0) writeRecord(new byte[0], Format.FLAG_FINAL);
    }

    private void writeRecord(byte[] plain, int flags) throws IOException, GeneralSecurityException {
        // seq is a u32 in the nonce: past 0xFFFFFFFF it would wrap and reuse a nonce under this fileKey.
        if (seq > Format.MAX_SEQ) throw new GeneralSecurityException("seq past u32, nonce would repeat");
        byte[] record = Format.sealRecord(aead, fileId, seq, flags, plain);
        out.write(record);
        seq++;
        size += record.length;
    }
}
