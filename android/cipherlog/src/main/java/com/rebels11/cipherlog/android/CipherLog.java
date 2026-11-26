package com.rebels11.cipherlog.android;

import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Parcelable;
import android.util.Log;
import com.rebels11.cipherlog.CipherLogCollector;
import com.rebels11.cipherlog.CipherLogConfig;
import com.rebels11.cipherlog.CipherLogKey;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The Android integration of cipherlog (SPEC.md 7.1): a static facade that mirrors {@link android.util.Log}.
 *
 * <pre>{@code
 * // Application.onCreate, once per process:
 * CipherLog.start(this, "cipherlog-pub-v1:<your public key>");
 * // Call sites: Log.d(TAG, "…") becomes
 * CipherLog.d(TAG, "connected");
 * CipherLog.e(TAG, "upload failed", error);
 * // Support screen:
 * Intent mail = CipherLog.shareIntent(context, "support@example.com", "App logs");
 * if (mail != null) context.startActivity(mail); // else offer a plain share
 * }</pre>
 *
 * <p>Every line goes to Logcat (unless turned off) and to the encrypted file, which only the holder of the private key
 * can read. The file gets {@code <type>: <message>} of a throwable, never its stack trace; Logcat gets what
 * android.util.Log would. Before {@link #start} (or when it failed) the facade only forwards to Logcat. Nothing here
 * throws.
 *
 * <p>The writer itself is {@link com.rebels11.cipherlog.CipherLog} of cipherlog-core ({@link #writer()}).
 */
public final class CipherLog {
    private CipherLog() {
    }

    static final String TAG = "cipherlog";

    private static volatile com.rebels11.cipherlog.CipherLog writer;
    private static volatile boolean logcat = true;
    private static final List<LogTarget> targets = new CopyOnWriteArrayList<>();
    private static final Object lock = new Object();

    /** What {@link #start(Context, String, Options)} lets an app change. Every value has a default. */
    public static final class Options {
        File directory;
        Integer process;
        String processName;
        List<CipherLogCollector> collectors;
        final List<CipherLogCollector> extraCollectors = new ArrayList<>();
        CipherLogConfig.Scrub scrub;
        CipherLogConfig.Diagnostics diagnostics;
        File exportRoot;
        boolean logcat = true;
        final List<LogTarget> targets = new ArrayList<>();

        /** Log directory; default {@code noBackupFilesDir/cipherlog} (not in backups). */
        public Options directory(File directory) {
            this.directory = directory;
            return this;
        }

        /** Header process number 0..255; default 1 for the main process, 2 for any other. */
        public Options process(int process) {
            this.process = process;
            return this;
        }

        /** Process name in lines and file names; default {@code app}, or the part after {@code :} of other processes. */
        public Options processName(String processName) {
            this.processName = processName;
            return this;
        }

        /** Replaces the built-in collectors ({@link DeviceCollectors#defaults}). */
        public Options collectors(List<? extends CipherLogCollector> collectors) {
            this.collectors = collectors == null ? new ArrayList<CipherLogCollector>() : new ArrayList<>(collectors);
            return this;
        }

        /** Adds a collector after the built-in ones. */
        public Options addCollector(CipherLogCollector collector) {
            if (collector != null) extraCollectors.add(collector);
            return this;
        }

        /** Masks every message, throwable message and collector line before it is written. Default: none. */
        public Options scrub(CipherLogConfig.Scrub scrub) {
            this.scrub = scrub;
            return this;
        }

        /**
         * Receives {@code cipherlog off: …}, the test-key warning and start failures, on a background thread. They
         * always go to Logcat (tag {@code cipherlog}) as well.
         */
        public Options diagnostics(CipherLogConfig.Diagnostics diagnostics) {
            this.diagnostics = diagnostics;
            return this;
        }

        /** Default root of {@link #export(boolean)}; default {@code <cache>/cipherlog-exports}. */
        public Options exportRoot(File exportRoot) {
            this.exportRoot = exportRoot;
            return this;
        }

        /** Also write every line to Logcat. Default true; see {@link #setLogcatEnabled(boolean)}. */
        public Options logcat(boolean enabled) {
            this.logcat = enabled;
            return this;
        }

        /** Adds a target that sees every line (crash reporter breadcrumbs, a debug screen). */
        public Options addTarget(LogTarget target) {
            if (target != null) targets.add(target);
            return this;
        }
    }

    // ---- start ----------------------------------------------------------------------------------------------------

    /** {@link #start(Context, String, Options)} with the defaults. */
    public static com.rebels11.cipherlog.CipherLog start(Context context, String publicKeyString) {
        return start(context, publicKeyString, new Options());
    }

    /**
     * Starts the writer of this process once, in {@code Application.onCreate} (each process of the app calls it); later
     * calls return the same writer and ignore their arguments. {@code publicKeyString} is {@code cipherlog-pub-v1:…}
     * (SPEC.md 1.1).
     *
     * <p>Returns null, without throwing, when it cannot start (a wrong key string); the reason goes to Logcat and
     * {@code options.diagnostics}. Starting with the published test key in an app that is not debuggable logs a
     * warning at every start.
     */
    public static com.rebels11.cipherlog.CipherLog start(Context context, String publicKeyString, Options options) {
        Options opts = options == null ? new Options() : options;
        com.rebels11.cipherlog.CipherLog existing = writer;
        if (existing != null) return existing;
        try {
            CipherLogKey key;
            try {
                key = CipherLogKey.parse(publicKeyString);
            } catch (IllegalArgumentException e) {
                // The key errors never echo a private key.
                reportStartFailure("cipherlog not started: " + e.getMessage(), opts.diagnostics);
                return null;
            }
            Context app = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            File directory = opts.directory != null ? opts.directory : new File(noBackupDir(app), "cipherlog");
            ProcessNames.Detected detected = ProcessNames.of(ProcessNames.current(app), app.getPackageName());
            List<CipherLogCollector> collectors = new ArrayList<>(
                    opts.collectors != null ? opts.collectors : DeviceCollectors.defaults(app, directory));
            collectors.addAll(opts.extraCollectors);
            final CipherLogConfig.Diagnostics appDiagnostics = opts.diagnostics;
            CipherLogConfig.Builder builder = CipherLogConfig.builder(directory, key)
                    .platform(CipherLogConfig.PLATFORM_ANDROID)
                    .process(opts.process != null ? opts.process : detected.process)
                    .processName(opts.processName != null ? opts.processName : detected.name)
                    .collectors(collectors)
                    .scrub(opts.scrub)
                    .exportRoot(opts.exportRoot != null ? opts.exportRoot : CipherLogFileProvider.exportRoot(app))
                    .warnIfTestKey(!isDebuggable(app))
                    .diagnostics(line -> {
                        // The test-key warning reached Logcat already, on the caller's thread at start.
                        if (!com.rebels11.cipherlog.CipherLog.TEST_KEY_WARNING.equals(line)) Log.w(TAG, line);
                        if (appDiagnostics != null) appDiagnostics.report(line);
                    });
            return start(app, builder.build(), opts);
        } catch (Throwable e) {
            reportStartFailure("cipherlog not started: " + e.getClass().getSimpleName(), opts.diagnostics);
            return null;
        }
    }

    /**
     * Starts the writer of this process with a full core config (any directory, limits, clock), once; later calls
     * return the first writer. The test key in an app that is not debuggable still gets its Logcat warning; set
     * {@code warnIfTestKey} on the config for the diagnostics line too.
     *
     * <p>Like the key-string overload it never throws (SPEC.md 7.1): a null argument, or a writer that cannot start (no
     * thread can be created), returns null and reports {@code cipherlog not started: <error type>} to Logcat and
     * {@code options.diagnostics}; the facade then only forwards to Logcat.
     */
    public static com.rebels11.cipherlog.CipherLog start(Context context, CipherLogConfig config, Options options) {
        Options opts = options == null ? new Options() : options;
        try {
            synchronized (lock) {
                if (writer != null) return writer;
                Context app = context.getApplicationContext() != null ? context.getApplicationContext() : context;
                if (config.key().isTestKey() && !isDebuggable(app)) {
                    Log.w(TAG, com.rebels11.cipherlog.CipherLog.TEST_KEY_WARNING);
                }
                com.rebels11.cipherlog.CipherLog started = new com.rebels11.cipherlog.CipherLog(config);
                logcat = opts.logcat;
                targets.clear();
                targets.addAll(opts.targets);
                writer = started;
                return started;
            }
        } catch (Throwable e) {
            reportStartFailure("cipherlog not started: " + e.getClass().getSimpleName(), opts.diagnostics);
            return null;
        }
    }

    /** The writer of this process, or null before {@link #start}. */
    public static com.rebels11.cipherlog.CipherLog writer() {
        return writer;
    }

    /** True after a successful {@link #start}. */
    public static boolean isStarted() {
        return writer != null;
    }

    /** Turns the Logcat passthrough on or off at run time (the file is not affected). */
    public static void setLogcatEnabled(boolean enabled) {
        logcat = enabled;
    }

    /** Whether lines also go to Logcat. */
    public static boolean isLogcatEnabled() {
        return logcat;
    }

    /** Tests: forgets the writer of this process (closing it) so another start can run. */
    static void reset() {
        synchronized (lock) {
            com.rebels11.cipherlog.CipherLog old = writer;
            writer = null;
            logcat = true;
            targets.clear();
            if (old != null) old.close();
        }
    }

    @SuppressWarnings("deprecation")
    private static File noBackupDir(Context context) {
        File dir = context.getNoBackupFilesDir();
        return dir != null ? dir : context.getFilesDir();
    }

    private static boolean isDebuggable(Context context) {
        try {
            return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Throwable e) {
            return false;
        }
    }

    private static void reportStartFailure(final String message, final CipherLogConfig.Diagnostics diagnostics) {
        try {
            Log.e(TAG, message);
        } catch (Throwable ignored) {
            // Logcat unavailable.
        }
        if (diagnostics == null) return;
        try {
            // Off the caller's thread, like every other diagnostics call (SPEC.md 7).
            Thread thread = new Thread(() -> {
                try {
                    diagnostics.report(message);
                } catch (Throwable ignored) {
                    // A failing callback changes nothing.
                }
            }, "cipherlog-start");
            thread.setDaemon(true);
            thread.start();
        } catch (Throwable ignored) {
            // No thread: the Logcat line stands.
        }
    }

    // ---- android.util.Log mirror ----------------------------------------------------------------------------------

    /** Like {@link Log#v(String, String)}; returns what Logcat returned, 0 when Logcat is off. */
    public static int v(String tag, String msg) {
        return println(Log.VERBOSE, tag, msg, null);
    }

    /** Like {@link Log#v(String, String, Throwable)}. */
    public static int v(String tag, String msg, Throwable tr) {
        return println(Log.VERBOSE, tag, msg, tr);
    }

    /** Like {@link Log#d(String, String)}. */
    public static int d(String tag, String msg) {
        return println(Log.DEBUG, tag, msg, null);
    }

    /** Like {@link Log#d(String, String, Throwable)}. */
    public static int d(String tag, String msg, Throwable tr) {
        return println(Log.DEBUG, tag, msg, tr);
    }

    /** Like {@link Log#i(String, String)}. */
    public static int i(String tag, String msg) {
        return println(Log.INFO, tag, msg, null);
    }

    /** Like {@link Log#i(String, String, Throwable)}. */
    public static int i(String tag, String msg, Throwable tr) {
        return println(Log.INFO, tag, msg, tr);
    }

    /** Like {@link Log#w(String, String)}; written to the file at once. */
    public static int w(String tag, String msg) {
        return println(Log.WARN, tag, msg, null);
    }

    /** Like {@link Log#w(String, String, Throwable)}. */
    public static int w(String tag, String msg, Throwable tr) {
        return println(Log.WARN, tag, msg, tr);
    }

    /** Like {@link Log#w(String, Throwable)}. */
    public static int w(String tag, Throwable tr) {
        return println(Log.WARN, tag, "", tr);
    }

    /** Like {@link Log#e(String, String)}; written to the file at once. */
    public static int e(String tag, String msg) {
        return println(Log.ERROR, tag, msg, null);
    }

    /** Like {@link Log#e(String, String, Throwable)}. */
    public static int e(String tag, String msg, Throwable tr) {
        return println(Log.ERROR, tag, msg, tr);
    }

    /** Like {@link Log#wtf(String, String)}: level F in the file. */
    public static int wtf(String tag, String msg) {
        return println(Log.ASSERT, tag, msg, null);
    }

    /** Like {@link Log#wtf(String, String, Throwable)}. */
    public static int wtf(String tag, String msg, Throwable tr) {
        return println(Log.ASSERT, tag, msg, tr);
    }

    /** Like {@link Log#isLoggable(String, int)}: Logcat's own filter, not cipherlog's (which writes every line). */
    public static boolean isLoggable(String tag, int priority) {
        try {
            return Log.isLoggable(tag, priority);
        } catch (Throwable e) {
            return false;
        }
    }

    /** Like {@link Log#getStackTraceString(Throwable)} (for Logcat; the file never gets stack traces). */
    public static String getStackTraceString(Throwable tr) {
        return Log.getStackTraceString(tr);
    }

    /**
     * Like {@link Log#println(int, String, String)} with an optional throwable: one line to Logcat (when on), the file
     * and every target. Never throws.
     */
    public static int println(int priority, String tag, String msg, Throwable tr) {
        int result = 0;
        try {
            LogLine line = new LogLine(System.currentTimeMillis(), priority, tag == null ? "" : tag,
                    msg == null ? "null" : msg, tr);
            if (logcat) {
                try {
                    result = LogcatTarget.log(line);
                } catch (Throwable ignored) {
                    // Logcat unavailable.
                }
            }
            com.rebels11.cipherlog.CipherLog w = writer;
            if (w != null) w.log(line.level(), line.tag(), line.message(), tr);
            for (LogTarget target : targets) {
                try {
                    target.log(line);
                } catch (Throwable ignored) {
                    // A target never breaks logging.
                }
            }
        } catch (Throwable ignored) {
            // Logging never throws, not even an Error.
        }
        return result;
    }

    // ---- writer passthroughs --------------------------------------------------------------------------------------

    /** {@link com.rebels11.cipherlog.CipherLog#flush(long)}; false before start. Safe from a crash handler. */
    public static boolean flush(long timeoutMs) {
        com.rebels11.cipherlog.CipherLog w = writer;
        return w != null && w.flush(timeoutMs);
    }

    /** Crash and failure reports: the current file (and the previous one when it is small) as bundle bytes, or null. */
    public static byte[] recentBundle(long timeoutMs) {
        com.rebels11.cipherlog.CipherLog w = writer;
        return w == null ? null : w.recentBundle(timeoutMs);
    }

    /** The newest file of the previous run of this process as bundle bytes, or null. */
    public static byte[] previousRunBundle(long timeoutMs) {
        com.rebels11.cipherlog.CipherLog w = writer;
        return w == null ? null : w.previousRunBundle(timeoutMs);
    }

    /** Sign-out or account deletion: deletes every cipherlog file and export, then opens a new file. */
    public static boolean wipe() {
        com.rebels11.cipherlog.CipherLog w = writer;
        return w != null && w.wipe();
    }

    /**
     * The support bundle in the export root ({@code .cipherlogs.txt} when {@code armored}, the default for mail). Call
     * it off the main thread: it waits for the writer (10 s at most).
     *
     * @throws IOException when it cannot be written, or before start
     */
    public static File export(boolean armored) throws IOException {
        com.rebels11.cipherlog.CipherLog w = writer;
        if (w == null) throw new IOException("cipherlog not started");
        File root = w.config().exportRoot();
        if (root == null) root = new File(w.config().directory(), "exports");
        return w.exportBundle(root, armored, 10_000);
    }

    /**
     * A ready mail intent with the armored bundle attached ({@code *.cipherlogs.txt}, text/plain, which mail filters
     * let through), or null when nothing can send mail, before start, or when the export fails; the caller can then
     * fall back to a plain share. Never throws. Call it off the main thread (it writes the bundle, 10 s at most), then
     * {@code startActivity} the result; it carries {@code FLAG_ACTIVITY_NEW_TASK}, so any context works.
     *
     * <p>What it does against the known pitfalls: the file is served by the library's own provider
     * ({@code <applicationId>.cipherlog}, no clash with an app's FileProvider); the read grant is on the send intent and
     * on the chooser, both as a flag and through ClipData (Android 4.1+ and 10+ grant from ClipData); the chooser's
     * selector is {@code ACTION_SENDTO mailto:} so only mail apps are listed; {@code EXTRA_EMAIL} is a String array
     * (a plain String is ignored by most mail apps); the library manifest declares the {@code mailto} query for
     * Android 11+ package visibility.
     *
     * @return an {@code ACTION_CHOOSER} intent around the {@code ACTION_SEND}, or null
     */
    public static Intent shareIntent(Context context, String email, String subject) {
        try {
            com.rebels11.cipherlog.CipherLog w = writer;
            if (w == null || context == null) return null;
            Context app = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            Intent mailto = new Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:"));
            if (!canResolve(app.getPackageManager(), mailto)) return null;
            File file = w.exportBundle(CipherLogFileProvider.exportRoot(app), true, 10_000);
            Uri uri = CipherLogFileProvider.uriFor(app, file);
            if (uri == null) return null;
            return mailIntent(app, uri, file.getName(), email, subject);
        } catch (Throwable e) {
            try {
                Log.w(TAG, "cipherlog shareIntent: " + e.getClass().getSimpleName());
            } catch (Throwable ignored) {
                // Logcat unavailable.
            }
            return null;
        }
    }

    /**
     * The support mail. Each mail app (an app that handles {@code mailto:}) gets its own {@code ACTION_SEND} with the
     * attachment, addressed to its package; one app opens directly, several open in a chooser. A selector on a
     * chooser is not used: Samsung's chooser (One UI, Android 16) ignores it and shows "No apps can perform this
     * action". Null when no mail app takes the attachment.
     */
    static Intent mailIntent(Context context, Uri uri, String fileName, String email, String subject) {
        PackageManager pm = context.getPackageManager();
        if (pm == null) return null;
        List<ResolveInfo> mailApps = pm.queryIntentActivities(
                new Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:")), PackageManager.MATCH_DEFAULT_ONLY);
        LinkedHashSet<String> packages = new LinkedHashSet<>();
        if (mailApps != null) {
            for (ResolveInfo info : mailApps) {
                if (info != null && info.activityInfo != null && info.activityInfo.packageName != null) {
                    packages.add(info.activityInfo.packageName);
                }
            }
        }
        List<Intent> targeted = new ArrayList<>();
        for (String pkg : packages) {
            Intent send = sendIntent(context, uri, fileName, email, subject);
            send.setPackage(pkg);
            if (canResolve(pm, send)) targeted.add(send);
        }
        if (targeted.isEmpty()) return null;
        if (targeted.size() == 1) {
            Intent only = targeted.get(0);
            only.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            return only;
        }
        Intent first = targeted.remove(0);
        Intent chooser = Intent.createChooser(first, subject != null ? subject : fileName);
        chooser.putExtra(Intent.EXTRA_INITIAL_INTENTS, targeted.toArray(new Parcelable[0]));
        chooser.setClipData(first.getClipData());
        chooser.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
        return chooser;
    }

    static Intent sendIntent(Context context, Uri uri, String fileName, String email, String subject) {
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType(CipherLogFileProvider.mimeTypeOf(fileName));
        send.putExtra(Intent.EXTRA_STREAM, uri);
        if (email != null && !email.isEmpty()) send.putExtra(Intent.EXTRA_EMAIL, new String[] {email});
        if (subject != null) send.putExtra(Intent.EXTRA_SUBJECT, subject);
        // The grant travels with ClipData, also through a chooser.
        send.setClipData(ClipData.newUri(context.getContentResolver(), fileName, uri));
        send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        return send;
    }

    private static boolean canResolve(PackageManager pm, Intent intent) {
        if (pm == null) return false;
        List<?> handlers = pm.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
        return handlers != null && !handlers.isEmpty();
    }

    /** The collectors {@link #start} uses by default, for apps that build their own list around them. */
    public static List<CipherLogCollector> defaultCollectors(Context context, File directory) {
        try {
            return DeviceCollectors.defaults(context, directory);
        } catch (Throwable e) {
            return Collections.emptyList();
        }
    }
}
