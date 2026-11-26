package com.rebels11.cipherlog;

/** Event levels (SPEC.md 2.4), lowest first. {@link #W} and above are written at once. */
public enum CipherLogLevel {
    /** Debug. */
    D('D'),
    /** Info. */
    I('I'),
    /** Notice. */
    N('N'),
    /** Warning. */
    W('W'),
    /** Error. */
    E('E'),
    /** Fault. */
    F('F');

    private final char letter;

    CipherLogLevel(char letter) {
        this.letter = letter;
    }

    /** The letter written in every line. */
    public char letter() {
        return letter;
    }
}
