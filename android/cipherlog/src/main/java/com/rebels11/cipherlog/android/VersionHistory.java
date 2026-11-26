package com.rebels11.cipherlog.android;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Every app version first seen on this device with the UTC day it was first seen, newest first, at most {@link #LIMIT}
 * entries. Kept in the app's own private storage (SharedPreferences file {@code cipherlog}, key
 * {@code cipherlog.versionHistory}); behind {@link Store} so the merge can be tested without a device.
 */
final class VersionHistory {
    private VersionHistory() {
    }

    static final int LIMIT = 20;
    static final String KEY = "cipherlog.versionHistory";
    private static final Object LOCK = new Object();

    /** Where the encoded history lives. */
    interface Store {
        String get(String key);

        void put(String key, String value);
    }

    /** One version: name, code and the day (yyyy-MM-dd, UTC) it was first seen. */
    static final class Entry {
        final String name;
        final long code;
        final String since;

        Entry(String name, long code, String since) {
            this.name = clean(name);
            this.code = code;
            this.since = since;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Entry)) return false;
            Entry e = (Entry) o;
            return e.code == code && e.name.equals(name) && e.since.equals(since);
        }

        @Override
        public int hashCode() {
            return name.hashCode() * 31 + Long.hashCode(code);
        }

        @Override
        public String toString() {
            return name + " (" + code + ") since " + since;
        }
    }

    /** Adds the running version when it is new (on top), keeps at most {@link #LIMIT}, saves, returns the list. */
    static List<Entry> record(Store store, String name, long code, long nowMillis) {
        synchronized (LOCK) {
            List<Entry> entries = decode(store.get(KEY));
            String cleaned = clean(name);
            for (Entry e : entries) {
                if (e.code == code && e.name.equals(cleaned)) return entries;
            }
            entries.add(0, new Entry(cleaned, code, utcDay(nowMillis)));
            while (entries.size() > LIMIT) entries.remove(entries.size() - 1);
            store.put(KEY, encode(entries));
            return entries;
        }
    }

    /** What is stored, without recording anything. */
    static List<Entry> read(Store store) {
        synchronized (LOCK) {
            return decode(store.get(KEY));
        }
    }

    /** {@code 1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-12}, or {@code none}. */
    static String format(List<Entry> entries) {
        if (entries.isEmpty()) return "none";
        StringBuilder sb = new StringBuilder();
        for (Entry e : entries) {
            if (sb.length() > 0) sb.append(" · ");
            sb.append(e);
        }
        return sb.toString();
    }

    /** One entry per line: {@code <code>\t<day>\t<name>}. */
    static String encode(List<Entry> entries) {
        StringBuilder sb = new StringBuilder();
        for (Entry e : entries) sb.append(e.code).append('\t').append(e.since).append('\t').append(e.name).append('\n');
        return sb.toString();
    }

    /** Lines that do not parse are dropped; never throws. */
    static List<Entry> decode(String stored) {
        List<Entry> out = new ArrayList<>();
        if (stored == null || stored.isEmpty()) return out;
        for (String line : stored.split("\n")) {
            String[] parts = line.split("\t", 3);
            if (parts.length != 3) continue;
            try {
                out.add(new Entry(parts[2], Long.parseLong(parts[0]), parts[1]));
            } catch (NumberFormatException ignored) {
                // Dropped.
            }
            if (out.size() == LIMIT) break;
        }
        return out;
    }

    /** No tabs or line breaks inside a stored name; a missing name is {@code -}. */
    static String clean(String name) {
        if (name == null || name.trim().isEmpty()) return "-";
        return name.trim().replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    /** {@code 2026-11-26} in UTC. */
    static String utcDay(long millis) {
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date(millis));
    }
}
