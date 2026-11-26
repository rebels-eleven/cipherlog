package com.rebels11.cipherlog;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** Small java.io helpers (java.nio.file is not on Android 6). */
final class Io {
    private Io() {
    }

    static byte[] readAll(File file) throws IOException {
        try (InputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.max(32, Math.min(file.length(), 1 << 24)));
            byte[] buffer = new byte[64 * 1024];
            int n;
            while ((n = in.read(buffer)) > 0) out.write(buffer, 0, n);
            return out.toByteArray();
        }
    }

    /** Writes a new file; fails if it exists. */
    static void writeNew(File file, byte[] bytes) throws IOException {
        if (!file.createNewFile()) throw new IOException("file exists");
        try (OutputStream out = new FileOutputStream(file)) {
            out.write(bytes);
        }
    }

    /** Deletes a file or a folder with everything in it; symbolic links are deleted, not followed. */
    static void deleteRecursively(File file) {
        File[] children = isLink(file) ? null : file.listFiles();
        if (children != null) for (File child : children) deleteRecursively(child);
        //noinspection ResultOfMethodCallIgnored
        file.delete();
    }

    private static boolean isLink(File file) {
        try {
            File parent = file.getParentFile();
            File canonicalDir = parent == null ? file : new File(parent.getCanonicalFile(), file.getName());
            return !canonicalDir.getCanonicalFile().equals(canonicalDir.getAbsoluteFile());
        } catch (IOException e) {
            return true;
        }
    }
}
