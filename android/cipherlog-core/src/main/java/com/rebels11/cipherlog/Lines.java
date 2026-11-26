package com.rebels11.cipherlog;

/** The text format of a line (SPEC.md 2.4). */
final class Lines {
    private Lines() {
    }

    private static final int NAME_MAX = 32;
    private static final char REPLACEMENT = '�';
    private static final long DAY_MS = 86_400_000L;

    /** {@code 2026-11-26T10:00:00.123Z I app spotify: connect\n}. */
    static String format(long timeMs, CipherLogLevel level, String processName, String category, String message) {
        String cat = category == null || category.isEmpty() ? "-" : name(category);
        return time(timeMs) + ' ' + level.letter() + ' ' + processName + ' ' + cat + ": " + text(message) + '\n';
    }

    /** UTC, ISO 8601 with milliseconds and {@code Z}. java.time is not on Android 6, so the calendar is done here. */
    static String time(long timeMs) {
        long[] c = civil(timeMs);
        StringBuilder out = new StringBuilder(24);
        pad(out, c[0], 4).append('-');
        pad(out, c[1], 2).append('-');
        pad(out, c[2], 2).append('T');
        pad(out, c[3], 2).append(':');
        pad(out, c[4], 2).append(':');
        pad(out, c[5], 2).append('.');
        pad(out, c[6], 3).append('Z');
        return out.toString();
    }

    /** {@code yyyyMMdd-HHmm} in UTC, for export file names. */
    static String compactMinute(long timeMs) {
        long[] c = civil(timeMs);
        StringBuilder out = new StringBuilder(13);
        pad(out, c[0], 4);
        pad(out, c[1], 2);
        pad(out, c[2], 2).append('-');
        pad(out, c[3], 2);
        pad(out, c[4], 2);
        return out.toString();
    }

    /** year, month, day, hour, minute, second, millisecond of a UTC instant (proleptic Gregorian calendar). */
    private static long[] civil(long timeMs) {
        long days = timeMs / DAY_MS;
        long msOfDay = timeMs % DAY_MS;
        if (msOfDay < 0) {
            msOfDay += DAY_MS;
            days--;
        }
        // H. Hinnant, civil_from_days.
        long z = days + 719_468;
        long era = (z >= 0 ? z : z - 146_096) / 146_097;
        long doe = z - era * 146_097;
        long yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        long year = yoe + era * 400;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long day = doy - (153 * mp + 2) / 5 + 1;
        long month = mp < 10 ? mp + 3 : mp - 9;
        if (month <= 2) year++;
        return new long[] {
            year, month, day, msOfDay / 3_600_000, (msOfDay / 60_000) % 60, (msOfDay / 1000) % 60, msOfDay % 1000
        };
    }

    private static StringBuilder pad(StringBuilder out, long value, int width) {
        String digits = Long.toString(value);
        for (int i = digits.length(); i < width; i++) out.append('0');
        return out.append(digits);
    }

    /** Process name and category: the first 32 code points, each outside {@code [A-Za-z0-9._-]} becomes {@code _}. */
    static String name(String raw) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        int count = 0;
        while (i < raw.length() && count < NAME_MAX) {
            int cp = raw.codePointAt(i);
            boolean ok = (cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z') || (cp >= '0' && cp <= '9')
                    || cp == '.' || cp == '_' || cp == '-';
            out.append(ok ? (char) cp : '_');
            count++;
            i += Character.charCount(cp);
        }
        return out.toString();
    }

    /**
     * A field that never breaks the line: {@code \r\n}, {@code \r}, {@code \n} become the two characters {@code \n};
     * other C0 controls except tab, DEL and C1 controls become U+FFFD. Unpaired surrogates become U+FFFD too (they have
     * no UTF-8 form).
     */
    static String text(String raw) {
        boolean clean = true;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if ((c < 0x20 && c != 0x09) || (c >= 0x7F && c <= 0x9F) || Character.isSurrogate(c)) {
                clean = false;
                break;
            }
        }
        if (clean) return raw;
        StringBuilder out = new StringBuilder(raw.length() + 8);
        int i = 0;
        while (i < raw.length()) {
            char c = raw.charAt(i);
            if (c == '\r') {
                out.append("\\n");
                if (i + 1 < raw.length() && raw.charAt(i + 1) == '\n') i++;
            } else if (c == '\n') {
                out.append("\\n");
            } else if (c == 0x09) {
                out.append(c);
            } else if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) {
                out.append(REPLACEMENT);
            } else if (Character.isHighSurrogate(c) && i + 1 < raw.length()
                    && Character.isLowSurrogate(raw.charAt(i + 1))) {
                out.append(c).append(raw.charAt(i + 1));
                i++;
            } else if (Character.isSurrogate(c)) {
                out.append(REPLACEMENT);
            } else {
                out.append(c);
            }
            i++;
        }
        return out.toString();
    }

    /** The simple type name of an error or value: {@code IOException}, never a stack trace. */
    static String typeName(Object value) {
        Class<?> cls = value.getClass();
        String simple = cls.getSimpleName();
        if (!simple.isEmpty()) return simple;
        String name = cls.getName();
        return name.substring(name.lastIndexOf('.') + 1);
    }
}
