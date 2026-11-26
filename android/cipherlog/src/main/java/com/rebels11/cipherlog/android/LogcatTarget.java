package com.rebels11.cipherlog.android;

import android.util.Log;

/** Passes every line to android.util.Log unchanged, stack traces included (Logcat stays on the device). */
final class LogcatTarget {
    private LogcatTarget() {
    }

    static int log(LogLine line) {
        String tag = line.tag();
        String msg = line.message();
        Throwable tr = line.throwable();
        switch (line.priority()) {
            case Log.VERBOSE:
                return tr == null ? Log.v(tag, msg) : Log.v(tag, msg, tr);
            case Log.DEBUG:
                return tr == null ? Log.d(tag, msg) : Log.d(tag, msg, tr);
            case Log.INFO:
                return tr == null ? Log.i(tag, msg) : Log.i(tag, msg, tr);
            case Log.WARN:
                return tr == null ? Log.w(tag, msg) : Log.w(tag, msg, tr);
            case Log.ERROR:
                return tr == null ? Log.e(tag, msg) : Log.e(tag, msg, tr);
            case Log.ASSERT:
                return tr == null ? Log.wtf(tag, msg) : Log.wtf(tag, msg, tr);
            default:
                // A priority outside VERBOSE..ASSERT: the nearest valid one (never wtf, which may end the process).
                if (line.priority() < Log.VERBOSE) return tr == null ? Log.v(tag, msg) : Log.v(tag, msg, tr);
                return tr == null ? Log.e(tag, msg) : Log.e(tag, msg, tr);
        }
    }
}
