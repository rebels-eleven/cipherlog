package com.rebels11.cipherlog;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The file operations the writer uses for log files. {@link #DEFAULT} is the real file system; tests pass their own
 * (usually a subclass of {@link Default}) to make opening or writing fail. Called from the writer's worker thread only.
 */
public interface CipherLogFileSystem {
    /** Creates {@code file} and opens it for writing. Must fail if the file already exists (a file is never appended). */
    OutputStream createNew(File file) throws IOException;

    /** The files directly inside {@code directory}; empty when it does not exist. */
    List<File> list(File directory);

    /** Deletes {@code file}; false when it could not. */
    boolean delete(File file);

    /** The file's modification time in ms since the epoch. */
    long lastModified(File file);

    /** The file's size in bytes. */
    long length(File file);

    /** The whole file. */
    byte[] readBytes(File file) throws IOException;

    /** Whether {@code file} still exists (another process may have wiped the directory). */
    boolean exists(File file);

    /** java.io on the real file system. No locks, no fsync. */
    CipherLogFileSystem DEFAULT = new Default();

    /** java.io on the real file system; open for subclasses that inject failures. */
    class Default implements CipherLogFileSystem {
        @Override
        public OutputStream createNew(File file) throws IOException {
            File dir = file.getParentFile();
            if (dir != null && !dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory()) {
                throw new IOException("cannot create directory");
            }
            // createNewFile is atomic "create new, fail if it exists" (java.nio.file is not on Android 6).
            if (!file.createNewFile()) throw new IOException("file exists");
            return new FileOutputStream(file);
        }

        @Override
        public List<File> list(File directory) {
            File[] files = directory.listFiles();
            return files == null ? new ArrayList<File>() : new ArrayList<>(Arrays.asList(files));
        }

        @Override
        public boolean delete(File file) {
            return file.delete();
        }

        @Override
        public long lastModified(File file) {
            return file.lastModified();
        }

        @Override
        public long length(File file) {
            return file.length();
        }

        @Override
        public byte[] readBytes(File file) throws IOException {
            return Io.readAll(file);
        }

        @Override
        public boolean exists(File file) {
            return file.exists();
        }
    }
}
