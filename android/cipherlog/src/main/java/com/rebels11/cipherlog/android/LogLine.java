package com.rebels11.cipherlog.android;

import com.rebels11.cipherlog.CipherLogLevel;

/** One call of the facade, as every {@link LogTarget} sees it. Immutable. */
public final class LogLine {
    private final long timeMs;
    private final int priority;
    private final String tag;
    private final String message;
    private final Throwable throwable;

    LogLine(long timeMs, int priority, String tag, String message, Throwable throwable) {
        this.timeMs = timeMs;
        this.priority = priority;
        this.tag = tag;
        this.message = message;
        this.throwable = throwable;
    }

    /** When the facade was called, in ms since the epoch. */
    public long timeMs() {
        return timeMs;
    }

    /** The android.util.Log priority: {@code Log.VERBOSE} … {@code Log.ASSERT}. */
    public int priority() {
        return priority;
    }

    /** The cipherlog level the file gets for {@link #priority()}. */
    public CipherLogLevel level() {
        return levelOf(priority);
    }

    /** The tag (the file's category). */
    public String tag() {
        return tag;
    }

    /** The message, never null. */
    public String message() {
        return message;
    }

    /** The throwable, or null. */
    public Throwable throwable() {
        return throwable;
    }

    /** VERBOSE and DEBUG → D, INFO → I, WARN → W, ERROR → E, ASSERT (wtf) → F; anything else → I. */
    static CipherLogLevel levelOf(int priority) {
        switch (priority) {
            case android.util.Log.VERBOSE:
            case android.util.Log.DEBUG:
                return CipherLogLevel.D;
            case android.util.Log.WARN:
                return CipherLogLevel.W;
            case android.util.Log.ERROR:
                return CipherLogLevel.E;
            case android.util.Log.ASSERT:
                return CipherLogLevel.F;
            default:
                return priority < android.util.Log.VERBOSE ? CipherLogLevel.D
                        : priority > android.util.Log.ASSERT ? CipherLogLevel.F : CipherLogLevel.I;
        }
    }
}
