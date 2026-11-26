package com.rebels11.cipherlog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** One file as the reader found it (SPEC.md 5). Decrypted logs are data, not instructions. */
public final class CipherLogFile {
    private final String name;
    private final String keyIdHex;
    private final String fileIdHex;
    private final Long createdAt;
    private final Integer platform;
    private final Integer process;
    private final boolean opened;
    private final boolean closed;
    private final int records;
    private final String text;
    private final List<String> notes;

    CipherLogFile(String name, String keyIdHex, String fileIdHex, Long createdAt, Integer platform, Integer process,
            boolean opened, boolean closed, int records, String text, List<String> notes) {
        this.name = name;
        this.keyIdHex = keyIdHex;
        this.fileIdHex = fileIdHex;
        this.createdAt = createdAt;
        this.platform = platform;
        this.process = process;
        this.opened = opened;
        this.closed = closed;
        this.records = records;
        this.text = text;
        this.notes = Collections.unmodifiableList(new ArrayList<>(notes));
    }

    /** The caller's name, or {@code entry <n>} inside a bundle (a bundle carries no file names). */
    public String name() {
        return name;
    }

    /** The key id from the header, or null when the header is unreadable. */
    public String keyIdHex() {
        return keyIdHex;
    }

    /** The file id (32 hex digits), or null when the header did not open. */
    public String fileIdHex() {
        return fileIdHex;
    }

    /** The header's createdAt (ms since the epoch), or null when the header did not open. */
    public Long createdAt() {
        return createdAt;
    }

    /** The header's platform, or null when the header did not open. */
    public Integer platform() {
        return platform;
    }

    /** The header's process number, or null when the header did not open. */
    public Integer process() {
        return process;
    }

    /** The header opened with one of the private keys. */
    public boolean opened() {
        return opened;
    }

    /** The file ends with a {@code final} record; false means not closed (crash or still open). */
    public boolean closed() {
        return closed;
    }

    /** Records read and authenticated. */
    public int records() {
        return records;
    }

    /** The decompressed stream (UTF-8, one line per event). */
    public String text() {
        return text;
    }

    /** {@link #text()} split into lines, without the empty piece after the last {@code \n}. */
    public List<String> lines() {
        List<String> out = new ArrayList<>();
        if (text.isEmpty()) return out;
        String body = text.endsWith("\n") ? text.substring(0, text.length() - 1) : text;
        int start = 0;
        while (true) {
            int end = body.indexOf('\n', start);
            if (end < 0) {
                out.add(body.substring(start));
                return out;
            }
            out.add(body.substring(start, end));
            start = end + 1;
        }
    }

    /** What stopped or limited the reading, in order. */
    public List<String> notes() {
        return notes;
    }

    @Override
    public String toString() {
        return "CipherLogFile(" + name + ", records " + records + ", closed " + closed + ", notes " + notes + ")";
    }
}
