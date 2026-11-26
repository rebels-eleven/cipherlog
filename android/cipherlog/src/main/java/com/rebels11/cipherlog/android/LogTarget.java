package com.rebels11.cipherlog.android;

/**
 * Where the facade sends each line besides the encrypted file and Logcat: a crash reporter's breadcrumbs, a debug
 * screen. Called on the caller's thread; must be fast and must not throw (a throw is caught and ignored).
 */
public interface LogTarget {
    /** One line. */
    void log(LogLine line);
}
