package com.rebels11.cipherlog.android;

import android.annotation.TargetApi;
import android.os.Build;
import android.system.Os;
import android.system.OsConstants;
import java.io.File;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Locale;

/**
 * Sizes of folders, walked with one shared hard cap (entries and time) so a huge folder cannot stall the writer. Only
 * byte counts leave here, never names. Sizes are logical file lengths (as on iOS), not allocated blocks. Symbolic
 * links are counted as entries but not followed or sized.
 *
 * <p>On API 26+ directories are read lazily ({@link Files#newDirectoryStream}) and the read stops at the cap. On API
 * 23–25 only {@link File#listFiles()} exists, which reads a whole directory at once: there the cap is checked before
 * each directory read, so one read of one flat directory is the most that can run past it.
 */
final class FolderSizes {
    private FolderSizes() {
    }

    static final int MAX_ENTRIES = 50_000;
    static final long MAX_NANOS = 200_000_000L;

    /** A clock in nanoseconds (java.util.function needs API 24). */
    interface Clock {
        long nanoTime();
    }

    /** Whether a path is a symbolic link. */
    interface LinkCheck {
        boolean isLink(File file);
    }

    /** Hands the children of a directory to a visitor, one at a time, until the visitor returns false. */
    interface Lister {
        void list(File dir, Visitor visitor);
    }

    /** Takes one child; false stops the listing of that directory. */
    interface Visitor {
        boolean visit(File child);
    }

    /** Lazy on API 26+, {@code listFiles()} below. Unreadable directories list nothing. */
    static final Lister DEFAULT_LISTER = (dir, visitor) -> {
        if (Build.VERSION.SDK_INT >= 26) {
            listLazily(dir, visitor);
        } else {
            listAll(dir, visitor);
        }
    };

    static void listAll(File dir, Visitor visitor) {
        File[] children = dir.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (!visitor.visit(child)) return;
        }
    }

    @TargetApi(26)
    static void listLazily(File dir, Visitor visitor) {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir.toPath())) {
            for (Path child : stream) {
                if (!visitor.visit(child.toFile())) return;
            }
        } catch (Throwable ignored) {
            // Unreadable or vanished: nothing more to count here.
        }
    }

    /** What one walk may still spend; shared by all folders of one collector run. */
    static final class Budget {
        int entriesLeft;
        final long deadline;
        final Clock clock;
        boolean exhausted;

        Budget(int maxEntries, long maxNanos, Clock clock) {
            this.entriesLeft = maxEntries;
            this.clock = clock;
            this.deadline = clock.nanoTime() + maxNanos;
        }

        /** Spends one entry; false (and exhausted from then on) when the cap is reached. */
        boolean spend() {
            if (isOver()) return false;
            entriesLeft--;
            return true;
        }

        /** Whether the cap is reached, without spending; exhausted from then on. */
        boolean isOver() {
            if (exhausted) return true;
            if (entriesLeft <= 0 || clock.nanoTime() - deadline > 0) exhausted = true;
            return exhausted;
        }
    }

    /** The bytes counted and whether the walk saw everything. */
    static final class Size {
        final long bytes;
        final boolean complete;

        Size(long bytes, boolean complete) {
            this.bytes = bytes;
            this.complete = complete;
        }

        /** {@code 340 KB}, or {@code ≥ 340 KB} when the walk stopped early. */
        String text() {
            return (complete ? "" : "≥ ") + rounded(bytes);
        }
    }

    static final LinkCheck LSTAT = file -> {
        try {
            return OsConstants.S_ISLNK(Os.lstat(file.getPath()).st_mode);
        } catch (Throwable e) {
            return false;
        }
    };

    /** The size of everything under {@code root} (0 when it does not exist), within {@code budget}. */
    static Size walk(File root, Budget budget, LinkCheck links) {
        return walk(root, budget, links, DEFAULT_LISTER);
    }

    static Size walk(File root, final Budget budget, final LinkCheck links, Lister lister) {
        if (root == null || !root.exists()) return new Size(0, true);
        final long[] bytes = {0};
        final boolean[] stopped = {false};
        final ArrayDeque<File> pending = new ArrayDeque<>();
        pending.push(root);
        Visitor visitor = child -> {
            if (!budget.spend()) {
                stopped[0] = true;
                return false;
            }
            if (links.isLink(child)) return true;
            if (child.isDirectory()) {
                pending.push(child);
            } else {
                bytes[0] += Math.max(0, child.length());
            }
            return true;
        };
        while (!pending.isEmpty()) {
            // Checked before every directory read, so a read that would only be thrown away is never started.
            if (budget.isOver()) return new Size(bytes[0], false);
            lister.list(pending.pop(), visitor);
            if (stopped[0]) return new Size(bytes[0], false);
        }
        return new Size(bytes[0], true);
    }

    /** Decimal units: whole KB under 1 MB, then MB and GB with one decimal. */
    static String rounded(long bytes) {
        long b = Math.max(0, bytes);
        long kb = Math.round(b / 1_000.0);
        if (kb < 1_000) return kb + " KB";
        double mb = b / 1_000_000.0;
        if (Math.round(mb * 10) < 10_000) return String.format(Locale.ROOT, "%.1f MB", mb);
        return String.format(Locale.ROOT, "%.1f GB", b / 1_000_000_000.0);
    }
}
