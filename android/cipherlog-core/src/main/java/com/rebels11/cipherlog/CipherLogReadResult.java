package com.rebels11.cipherlog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Everything read from a file or a bundle: one result per file, plus notes about the bundle itself. */
public final class CipherLogReadResult {
    private final List<CipherLogFile> files;
    private final List<String> notes;

    CipherLogReadResult(List<CipherLogFile> files, List<String> notes) {
        this.files = Collections.unmodifiableList(new ArrayList<>(files));
        this.notes = Collections.unmodifiableList(new ArrayList<>(notes));
    }

    /** The files, in bundle order. */
    public List<CipherLogFile> files() {
        return files;
    }

    /** Notes about the container: a bad entry length, not a bundle, armor errors. */
    public List<String> notes() {
        return notes;
    }
}
