package com.rebels11.cipherlog.android;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Serves the export bundles of {@link CipherLog#shareIntent} to the mail app, read only, through per-Uri grants.
 *
 * <p>It is the library's own provider class with its own authority {@code <applicationId>.cipherlog}, so it never
 * clashes in the manifest merge with an app's {@code androidx.core.content.FileProvider} (two providers of the same
 * class, or two {@code FILE_PROVIDER_PATHS}, are the classic merge failure). It is not a FileProvider subclass:
 * androidx.core would bring kotlin-stdlib, coroutines and a dozen androidx artifacts into every app (cipherlog-core keeps
 * them out of Tink's dependencies too, see its build file), and a FileProvider
 * paths file can only describe folders, while this provider accepts nothing but the exact shape of an export:
 * {@code content://<authority>/exports/<32 hex>/cipherlog-<yyyyMMdd-HHmm>.cipherlogs[.txt]} under
 * {@code <cache>/cipherlog-exports}. No other path, no {@code ..}, no symbolic link out of that folder.
 */
public final class CipherLogFileProvider extends ContentProvider {
    /** The folder inside the app's cache directory that holds shareable exports. */
    static final String EXPORT_FOLDER = "cipherlog-exports";
    /** The first path segment of every Uri. */
    static final String EXPORTS_SEGMENT = "exports";
    static final String AUTHORITY_SUFFIX = ".cipherlog";

    private static final Pattern FOLDER = Pattern.compile("^[0-9a-f]{32}$");
    private static final Pattern NAME = Pattern.compile("^cipherlog-\\d{8}-\\d{4}\\.cipherlogs(\\.txt)?$");
    private static final String[] COLUMNS = {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE};

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public void attachInfo(Context context, ProviderInfo info) {
        super.attachInfo(context, info);
        // The same checks FileProvider makes: a provider that others could open without a grant must not start.
        if (info.exported) throw new SecurityException("CipherLogFileProvider must not be exported");
        if (!info.grantUriPermissions) throw new SecurityException("CipherLogFileProvider must grant Uri permissions");
    }

    /** The export root of {@code context}: {@code <cache>/cipherlog-exports}. */
    static File exportRoot(Context context) {
        return new File(context.getCacheDir(), EXPORT_FOLDER);
    }

    static String authority(Context context) {
        return context.getPackageName() + AUTHORITY_SUFFIX;
    }

    /** The content Uri of an export file, or null when the file is not an export under the root. */
    static Uri uriFor(Context context, File file) {
        File folder = file.getParentFile();
        if (folder == null || !isExportPath(EXPORTS_SEGMENT, folder.getName(), file.getName())) return null;
        File root = exportRoot(context);
        if (!sameFile(root, folder.getParentFile())) return null;
        return new Uri.Builder().scheme("content").authority(authority(context))
                .appendPath(EXPORTS_SEGMENT).appendPath(folder.getName()).appendPath(file.getName()).build();
    }

    /** True for exactly {@code exports/<32 lowercase hex>/cipherlog-<yyyyMMdd-HHmm>.cipherlogs[.txt]}. */
    static boolean isExportPath(String first, String folder, String name) {
        return EXPORTS_SEGMENT.equals(first) && folder != null && name != null && FOLDER.matcher(folder).matches()
                && NAME.matcher(name).matches();
    }

    /** {@code text/plain} for an armored bundle, {@code application/octet-stream} for a binary one. */
    static String mimeTypeOf(String name) {
        return name.endsWith(".txt") ? "text/plain" : "application/octet-stream";
    }

    private static boolean sameFile(File a, File b) {
        if (a == null || b == null) return false;
        try {
            return a.getCanonicalFile().equals(b.getCanonicalFile());
        } catch (java.io.IOException e) {
            return false;
        }
    }

    /** The file behind {@code uri}, or null when the Uri is not an export of this provider. */
    private File fileFor(Uri uri) {
        Context context = getContext();
        if (context == null || uri == null || !authority(context).equals(uri.getAuthority())) return null;
        List<String> segments = uri.getPathSegments();
        if (segments == null || segments.size() != 3) return null;
        if (!isExportPath(segments.get(0), segments.get(1), segments.get(2))) return null;
        File root = exportRoot(context);
        File file = new File(new File(root, segments.get(1)), segments.get(2));
        try {
            // No symbolic link may lead out of the export folder.
            File canonical = file.getCanonicalFile();
            File canonicalRoot = root.getCanonicalFile();
            File parent = canonical.getParentFile();
            if (parent == null || !canonicalRoot.equals(parent.getParentFile())) return null;
            return canonical;
        } catch (java.io.IOException e) {
            return null;
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        File file = fileFor(uri);
        if (file == null || !file.isFile()) return null;
        String[] columns = projection == null ? COLUMNS : projection;
        String[] cols = new String[columns.length];
        Object[] values = new Object[columns.length];
        int n = 0;
        for (String column : columns) {
            if (OpenableColumns.DISPLAY_NAME.equals(column)) {
                cols[n] = OpenableColumns.DISPLAY_NAME;
                values[n++] = file.getName();
            } else if (OpenableColumns.SIZE.equals(column)) {
                cols[n] = OpenableColumns.SIZE;
                values[n++] = file.length();
            }
        }
        String[] outCols = new String[n];
        Object[] outValues = new Object[n];
        System.arraycopy(cols, 0, outCols, 0, n);
        System.arraycopy(values, 0, outValues, 0, n);
        MatrixCursor cursor = new MatrixCursor(outCols, 1);
        cursor.addRow(outValues);
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        File file = fileFor(uri);
        return file == null ? null : mimeTypeOf(file.getName());
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (mode == null || !mode.equals("r")) throw new SecurityException("read only");
        File file = fileFor(uri);
        if (file == null || !file.isFile()) throw new FileNotFoundException("no such export");
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("read only");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("read only");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("read only");
    }
}
